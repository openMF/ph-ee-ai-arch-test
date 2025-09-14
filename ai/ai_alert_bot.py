from datetime import datetime, timezone
from collections import defaultdict
from detectors import extract_total_ms, summarize_payload_issues
from slack_client import post as slack_post
import os, time, logging, requests, statistics, math
from pathlib import Path
import json
import joblib
import numpy as np

IFOREST_MODEL_DIR  = os.getenv("IFOREST_MODEL_DIR", "ai/models")
IFOREST_SOURCE_IDX = os.getenv("IFOREST_SOURCE_INDEX", "ph-ee_features_1m_all")
IFOREST_WINDOW_MIN = int(os.getenv("IFOREST_WINDOW_MIN", "15"))
IFOREST_MODEL_ENV = os.getenv("IFOREST_MODEL")
IFOREST_META_ENV  = os.getenv("IFOREST_META")

logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"))
log = logging.getLogger("ai-bot")

ES_URL  = os.getenv("ES_URL",  "http://localhost:9200")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASS")

PROM_URL = os.getenv("PROM_URL")  # optional

LOOP_SEC = int(os.getenv("LOOP_SEC", "60"))
COOLDOWN_MIN = int(os.getenv("COOLDOWN_MIN", "10"))

# thresholds
BACKPRESSURE_MIN = int(os.getenv("BACKPRESSURE_MIN", "1"))
BACKPRESSURE_LOOKBACK_MIN = int(os.getenv("BACKPRESSURE_LOOKBACK_MIN", "5"))
CLIENTSTATUS_MIN = int(os.getenv("CLIENTSTATUS_MIN", "5"))
OPS_P95_MS       = int(os.getenv("OPS_P95_MS", "1500"))
PAYLOAD_ALERTS_MIN = int(os.getenv("PAYLOAD_ALERTS_MIN", "1"))

CHANNEL_ERR_PER_MIN  = int(os.getenv("CHANNEL_ERR_PER_MIN", "20"))  # 4xx/5xx / minute (approx)
TENANT_NOISY_MIN     = int(os.getenv("TENANT_NOISY_MIN", "3"))      # suspicious payloads per tenant in 5m
OPS_GC_MIN           = int(os.getenv("OPS_GC_MIN", "1"))            # GC/OOM hits in 5m
KEYCLOAK_4XX_MIN     = int(os.getenv("KEYCLOAK_4XX_MIN", "5"))      # 401/403 in 5m
INGESTION_STALL_MINS = int(os.getenv("INGESTION_STALL_MINS", "2"))

def es_search(index, query):
    url = f"{ES_URL}/{index}/_search"
    auth = (ES_USER, ES_PASS) if ES_USER else None
    r = requests.post(url, json=query, auth=auth, timeout=20)
    r.raise_for_status()
    return r.json()

def es_count(index, query):
    url  = f"{ES_URL}/{index}/_count"
    auth = (ES_USER, ES_PASS) if ES_USER else None
    r = requests.post(url, json=query, auth=auth, timeout=20)
    r.raise_for_status()
    return r.json()["count"]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def cooldown_ok(state, key):
    last = state.get(key)
    if not last: return True
    return (time.time() - last) >= COOLDOWN_MIN*60

def mark(state, key): state[key] = time.time()

def watch_backpressure(state):
    """
    Detect Zeebe Gateway/Broker backpressure by searching for the well-known
    'writer is full' / 'Failed to write client request' phrases in either Body
    or Attributes.raw_line, restricted to the zeebe-gateway container.
    """
    q = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{BACKPRESSURE_LOOKBACK_MIN}m"}}},
                    # limit to gateway (you can add 'zeebe' if you also want broker logs)
                    {"terms": {"Attributes.k8s.container.name": ["zeebe-gateway"]}},
                    {
                        "bool": {
                            "minimum_should_match": 1,
                            "should": [
                                # phrase match across Body and Attributes.raw_line
                                {"multi_match": {
                                    "type": "phrase",
                                    "query": "writer is full",
                                    "fields": ["Body", "Attributes.raw_line"]
                                }},
                                {"multi_match": {
                                    "type": "phrase",
                                    "query": "INTERNAL_ERROR",
                                    "fields": ["Body", "Attributes.zeebe_error_code"]
                                }}
                            ]
                        }
                    }
                ]
            }
        },
        "aggs": {
            "by_comp": {"terms": {"field": "Attributes.k8s.container.name", "size": 10}}
        }
    }

    res = es_search("logs*", q)
    total = res["hits"]["total"]["value"]
    log.info("backpressure hits(%sm)=%s", BACKPRESSURE_LOOKBACK_MIN, total)

    if total >= BACKPRESSURE_MIN and cooldown_ok(state, "backpressure"):
        buckets = res.get("aggregations", {}).get("by_comp", {}).get("buckets", [])
        comps = ", ".join(f"{b['key']}:{b['doc_count']}" for b in buckets) or "zeebe-gateway"
        text = (
            "Zeebe Gateway/Broker reported *backpressure* recently.\n"
            "Most common error: `writer is full / Failed to write client request`.\n\n"
            "*Runbook*\n"
            "• Gateway errors: `kubectl -n paymenthub logs deploy/phee-zeebe-gateway --since=10m "
            "| egrep -i \"writer is full|Failed to write client request\"`\n"
            "• Broker/partition view: `kubectl -n paymenthub logs statefulset/phee-zeebe --since=10m | grep -i backpressure`\n"
            "• Consider scaling gateway/broker or throttling load."
        )
        slack_post(
            "Backpressure detected",
            text,
            severity="crit",
            facts=[("Hits", str(total)), ("Scope", comps)],
            mention=True,
        )
        mark(state, "backpressure")


def watch_clientstatus(state):
    q = {
      "size": 0, "track_total_hits": True,
      "query": {"bool": {"filter": [
          {"range": {"@timestamp": {"gte": "now-5m"}}},
          {"simple_query_string": {
              "query": "\"ClientStatusException\" | \"ClientStatusException occurred\"",
              "fields": ["Body"], "default_operator": "or"
          }}
      ]}},
      "aggs": {"by_comp": {"terms": {"field": "Attributes.k8s.container.name", "size": 10}}}
    }
    res = es_search("logs*", q)
    total = res["hits"]["total"]["value"]
    log.info("ClientStatusException hits(5m)=%s", total)   # <-- debug line
    min_hits = int(os.getenv("CLIENTSTATUS_MIN", CLIENTSTATUS_MIN))  # default lowered via env during testing
    if total >= min_hits and cooldown_ok(state, "clientstatus"):
        comps = ", ".join([f"{b['key']}:{b['doc_count']}" for b in res["aggregations"]["by_comp"]["buckets"]])
        text = ("Spike of `ClientStatusException` (last 5m).\n"
                "*Likely causes*: gateway ↔ broker retries/timeouts, leader changes, resource pressure.\n"
                "*Next*:\n"
                "• Check gateway/broker restarts & CPU/mem.\n"
                "• Inspect network and pod events.")
        slack_post("ClientStatusException spike", text, severity="warn",
                   facts=[("Hits (5m)", str(total)), ("By component", comps)])
        mark(state, "clientstatus")

def watch_ops_p95(state):
    q = {
      "_source": ["Body"],
      "size": 1000,
      "query": {"bool": {"filter": [
          {"range": {"@timestamp": {"gte": "now-10m"}}},
          {"term": {"Attributes.k8s.container.name": "ph-ee-operations-app"}},
          {"term": {"Attributes.logger": "org.apache.fineract.core.service.TenantAwareHeaderFilter.doFilter"}}
      ]}}
    }
    res = es_search("logs*", q)
    totals = []
    for hit in res["hits"]["hits"]:
        ms = extract_total_ms(hit["_source"].get("Body",""))
        if ms is not None:
            totals.append(ms)
    log.info("ops-app samples(10m)=%s", len(totals))       # <-- debug line
    if len(totals) >= 50:
        totals.sort()
        p95 = totals[max(0, math.floor(0.95*len(totals))-1)]
        p99 = totals[max(0, math.floor(0.99*len(totals))-1)]
        if p95 >= OPS_P95_MS and cooldown_ok(state, "ops_p95"):
            text = ("Ops-App p95 is above SLO in the last 10m.\n"
                    "*Runbook*\n"
                    "• Check DB (`operationsmysql`) latency and slow queries\n"
                    "• Inspect GC/CPU for Ops-App pod\n"
                    "• Warm caches (identity/account-mapper) if cold after deploy.")
            slack_post("Ops-App p95 SLO breach", text, severity="warn",
                       facts=[("Samples", str(len(totals))), ("p95 (ms)", p95), ("p99 (ms)", p99)])
            mark(state, "ops_p95")


def watch_channel_payloads(state):
    q = {
      "_source":["Body","Attributes.clientRefId","Attributes.k8s.container.name"],
      "size":200,
      "query":{"bool":{"filter":[
          {"range":{"@timestamp":{"gte":"now-2m"}}},
          {"term":{"Attributes.k8s.container.name":"ph-ee-connector-channel"}}
      ]}}
    }
    res = es_search("logs*", q)
    suspicious = []
    for hit in res["hits"]["hits"]:
        b = hit["_source"].get("Body","")
        issues = summarize_payload_issues(b)
        if issues:
            suspicious.append((issues, b[:700]))  # truncate preview

    if len(suspicious) >= PAYLOAD_ALERTS_MIN and cooldown_ok(state, "payloads"):
        top = "; ".join(sorted({i for issues, _ in suspicious for i in issues}))
        preview = suspicious[0][1]
        text = ("Suspicious *channel* payload patterns detected (last 2m).\n"
                "*Examples:* " + top + "\n\n"
                "First sample (truncated):\n```" + preview + "```")
        slack_post("Channel payload anomalies", text, severity="crit",
                   facts=[("Occurrences (2m)", str(len(suspicious)))], mention=True)
        mark(state, "payloads")

def watch_zeebe_resource_exhausted(state):
    # Channel logs show the client facing error when partitions are exhausted
    q = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-2m"}}},
            {"term": {"Attributes.k8s.container.name": "ph-ee-connector-channel"}},
            {"bool": {"minimum_should_match": 1, "should": [
                {"match_phrase": {"Body": "Caused by: java.util.concurrent.ExecutionException: io.grpc.StatusRuntimeException: RESOURCE_EXHAUSTED"}},
                {"match_phrase": {"Attributes.raw_line": "Caused by: java.util.concurrent.ExecutionException: io.grpc.StatusRuntimeException: RESOURCE_EXHAUSTED"}},
                {"match_phrase": {"Body": "Caused by: io.grpc.StatusRuntimeException: RESOURCE_EXHAUSTED: Expected to execute the command on one of the partitions, but all failed; there are no more partitions available to retry. Please try again. If the error persists contact your zeebe operator"}}
            ]}}
        ]}}
    }
    res = es_search("logs*", q)
    total = res["hits"]["total"]["value"]
    log.info("zeebe RESOURCE_EXHAUSTED hits(2m)=%s", total)
    if total >= 1 and cooldown_ok(state, "resource_exhausted"):
        text = (
            "*Zeebe command execution exhausted retries* (last 5m).\n"
            "The gateway could not execute on *any* partition and gave up.\n\n"
            "*Next steps*\n"
            "• Check gateway/broker health & restarts\n"
            "• Validate partition leaders and CPU/memory pressure\n"
            "• Reduce client concurrency / backoff"
        )
        slack_post("Zeebe capacity/partitions exhausted",
                   text, severity="crit",
                   facts=[("Hits (2m)", str(total)), ("Component", "ph-ee-connector-channel")],
                   mention=True)
        mark(state, "resource_exhausted")

def watch_channel_http_errors(state):
    """
    Approximate 4xx/5xx rate for ph‑ee‑connector‑channel.
    We use two signals:
      1) explicit error level logs
      2) HTTP codes in raw text (401/403/404/5xx), when present
    """
    should = [
        {"term" : {"Attributes.level": "ERROR"}},
        {"match_phrase": {"Body": "HTTP 500"}},
        {"match_phrase": {"Body": "HTTP/1.1 5"}},
        {"match_phrase": {"Body": "status=50"}},
        {"match_phrase": {"Body": " 401 "}},
        {"match_phrase": {"Body": " 403 "}},
        {"match_phrase": {"Attributes.raw_line": "HTTP 500"}},
        {"match_phrase": {"Attributes.raw_line": " 401 "}},
        {"match_phrase": {"Attributes.raw_line": " 403 "}}
    ]
    q = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-1m"}}},
            {"term":  {"Attributes.k8s.container.name": "ph-ee-connector-channel"}},
            {"bool":  {"minimum_should_match": 1, "should": should}}
        ]}}
    }
    total = es_search("logs*", q)["hits"]["total"]["value"]
    log.info("channel http-ish errors(1m)=%s", total)

    if total >= CHANNEL_ERR_PER_MIN and cooldown_ok(state, "channel_http"):
        text = (
            "High *HTTP error‑like* rate for `ph‑ee‑connector‑channel` (last 1m).\n"
            "Signals include error‑level lines and visible 401/403/5xx markers in logs."
        )
        slack_post("Channel 4xx/5xx spike (approx.)", text, severity="warn",
                   facts=[("Hits (1m)", total)])
        mark(state, "channel_http")

def watch_payloads_by_tenant(state):
    """
    Group suspicious payloads by tenant so you can see noisy tenants.
    """
    q = {
        "_source": ["Body", "Attributes.tenant_id"],
        "size": 600,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-5m"}}},
            {"term":  {"Attributes.k8s.container.name": "ph-ee-connector-channel"}}
        ]}}
    }
    res = es_search("logs*", q)
    per_tenant = defaultdict(int)
    for hit in res["hits"]["hits"]:
        body = hit["_source"].get("Body", "")
        issues = summarize_payload_issues(body)
        if issues:
            tenant = hit["_source"].get("Attributes.tenant_id", "(unknown)")
            per_tenant[tenant] += 1

    if not per_tenant:
        return

    # find noisy tenants
    noisy = [(t, c) for t, c in per_tenant.items() if c >= TENANT_NOISY_MIN]
    noisy.sort(key=lambda x: x[1], reverse=True)
    if noisy and cooldown_ok(state, "tenant_noise"):
        top = ", ".join([f"{t}:{c}" for t, c in noisy[:10]])
        text = (
            "Suspicious payloads by *tenant* (last 5m).\n"
            "Use this to spot noisy tenants during tests or attacks."
        )
        slack_post("Tenant isolation — noisy payloads", text, severity="info",
                   facts=[("≥ occurrences per tenant", TENANT_NOISY_MIN), ("Noisy tenants", top)])
        mark(state, "tenant_noise")

def watch_ops_gc_pressure(state):
    """
    Look for GC overhead/OOM in Ops‑App (last 5m).
    """
    patterns = [
        "java.lang.OutOfMemoryError",
        "GC overhead limit exceeded",
        "Full GC",
        "OutOfMemoryError"
    ]
    should = [{"match_phrase": {"Body": p}} for p in patterns] + \
             [{"match_phrase": {"Attributes.raw_line": p}} for p in patterns]

    q = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-5m"}}},
            {"term":  {"Attributes.k8s.container.name": "ph-ee-operations-app"}},
            {"bool":  {"minimum_should_match": 1, "should": should}}
        ]}}
    }
    total = es_search("logs*", q)["hits"]["total"]["value"]
    log.info("ops-app GC/OOM hits(5m)=%s", total)

    if total >= OPS_GC_MIN and cooldown_ok(state, "ops_gc"):
        text = (
            "Possible *GC pressure / OOM* in Ops‑App (last 5m).\n"
            "*Next*:\n"
            "• Check pod memory/GC logs\n"
            "• Review heap/Xms/Xmx and DB connection pool size."
        )
        slack_post("Ops‑App GC/OOM signals", text, severity="warn",
                   facts=[("Hits (5m)", total)])
        mark(state, "ops_gc")

def watch_keycloak_failures(state):
    """
    Token/authorization failures. We look at keycloak and channel logs for 401/403 spikes.
    """
    should = [
        {"match_phrase": {"Body": " 401 "}},
        {"match_phrase": {"Body": " 403 "}},
        {"match_phrase": {"Body": "Unauthorized"}},
        {"match_phrase": {"Attributes.raw_line": " 401 "}},
        {"match_phrase": {"Attributes.raw_line": " 403 "}},
        {"match_phrase": {"Attributes.raw_line": "Unauthorized"}}
    ]
    q = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-5m"}}},
            {"bool": {"minimum_should_match": 1, "should": [
                {"term": {"Attributes.k8s.container.name": "phee-keycloak"}},
                {"term": {"Attributes.k8s.container.name": "ph-ee-connector-channel"}},
                {"term": {"Attributes.k8s.container.name": "phee-identity"}}
            ]}},
            {"bool": {"minimum_should_match": 1, "should": should}}
        ]}}
    }
    total = es_search("logs*", q)["hits"]["total"]["value"]
    log.info("keycloak 401/403 hits(5m)=%s", total)

    if total >= KEYCLOAK_4XX_MIN and cooldown_ok(state, "kc_4xx"):
        text = (
            "Spike of *401/403* around Keycloak/identity (last 5m).\n"
            "Check client credentials, token TTL/clock skew, and Keycloak pod health."
        )
        slack_post("Auth/token failures (401/403)", text, severity="warn",
                   facts=[("Hits (5m)", total)])
        mark(state, "kc_4xx")

def watch_ingestion_stall(state):
    """
    Alert if log ingestion stalls (no new docs in logs* in N minutes).
    """
    # 1) recent window: last N minutes
    q_recent = {"query": {"range": {"@timestamp": {"gte": f"now-{INGESTION_STALL_MINS}m"}}}}
    recent = es_count("logs*", q_recent)

    # 2) larger window to prove cluster is alive
    q_prev = {"query": {"range": {"@timestamp": {"gte": "now-30m", "lte": f"now-{INGESTION_STALL_MINS}m"}}}}
    prev   = es_count("logs*", q_prev)

    log.info("ingestion recent=%s prev(30m->%sm)=%s", recent, INGESTION_STALL_MINS, prev)

    if recent == 0 and prev > 0 and cooldown_ok(state, "ingest_stall"):
        text = (
            f"No new log documents for *{INGESTION_STALL_MINS}m* in `logs*`.\n"
            "This often means Filebeat/OTel/Filelog pipeline crashed or stuck."
        )
        slack_post("Indexing/ingestion stall", text, severity="crit",
                   facts=[("Recent (docs)", recent), ("Earlier docs (30m window)", prev)], mention=True)
        mark(state, "ingest_stall")


def _iforest_paths():
    """
    Return absolute Paths to the model (.joblib) and meta (.json).
    Resolved relative to this source file (ai/) unless env overrides are set.
    """
    ai_dir = Path(__file__).resolve().parent  # .../ai
    model_p = Path(IFOREST_MODEL_ENV) if IFOREST_MODEL_ENV else (ai_dir / "models" / "iforest.joblib")
    meta_p  = Path(IFOREST_META_ENV)  if IFOREST_META_ENV  else (ai_dir / "models" / "iforest_meta.json")
    return model_p, meta_p

def _iforest_load():
    """
    Load the IsolationForest and optional scaler + meta.
    Supports:
      * dict: {"model": IsolationForest, "scaler": StandardScaler, ...}
      * tuple: (model, scaler)
      * raw IsolationForest object
    """
    model_p, meta_p = _iforest_paths()
    if not model_p.exists():
        log.warning("IsolationForest model not available at %s ; skipping ML anomaly.", model_p)
        return None

    try:
        obj = joblib.load(str(model_p))
    except Exception as e:
        log.error("Failed loading IsolationForest from %s: %s", model_p, e)
        return None

    model, scaler = None, None
    if isinstance(obj, dict):
        model  = obj.get("model", obj.get("iforest", None))
        scaler = obj.get("scaler")
        if model is None:
            # in case user saved the estimator directly under another key
            for v in obj.values():
                if hasattr(v, "decision_function"):
                    model = v
                    break
    elif isinstance(obj, (list, tuple)) and len(obj) >= 1:
        model  = obj[0]
        scaler = obj[1] if len(obj) >= 2 else None
    else:
        model = obj  # bare estimator

    if model is None or not hasattr(model, "decision_function"):
        log.error("Loaded object from %s does not look like an IsolationForest; got %r", model_p, type(obj))
        return None

    try:
        meta = json.loads(meta_p.read_text()) if meta_p.exists() else {}
    except Exception as e:
        log.warning("Could not read meta from %s: %s (continuing without meta)", meta_p, e)
        meta = {}

    log.info("Loaded IsolationForest from %s ; meta=%s", model_p, meta or "{}")
    return model, scaler, meta

def _scale_if_needed(X, scaler):
    return scaler.transform(X) if scaler is not None else X

def _iforest_fetch_features():
    # Pull last N minutes of minute-aggregated features
    q = {
      "size": 200, "sort": [{"ts_minute":"asc"}],
      "_source": ["ts_minute","rps","err_backpressure","err_clientstatus","err_error_level"],
      "query": {"range": {"ts_minute": {"gte": f"now-{IFOREST_WINDOW_MIN}m"}}}
    }
    res = es_search(IFOREST_SOURCE_IDX, q)
    hits = res.get("hits", {}).get("hits", [])
    X = []
    ts = []
    for h in hits:
        src = h["_source"]
        rps = float(src.get("rps",0))
        b   = float(src.get("err_backpressure",0))
        cs  = float(src.get("err_clientstatus",0))
        ee  = float(src.get("err_error_level",0))
        rate = (b+cs+ee)/max(rps, 1.0)
        X.append([rps, b, cs, ee, rate])
        ts.append(src.get("ts_minute"))
    return np.array(X, dtype=float), ts

def watch_iforest_anomaly(state):
    """Score the latest minute with ML; alert with layman-friendly context."""
    loaded = getattr(watch_iforest_anomaly, "_loaded", None)
    if loaded is None:
        loaded = _iforest_load()           # loads model + scaler + meta from ai/models
        watch_iforest_anomaly._loaded = loaded
    if loaded is None:
        return  # model not ready

    model, scaler, meta = loaded
    X, ts = _iforest_fetch_features()      # most-recent window of minute features
    if X.shape[0] == 0:
        return

    Xs      = scaler.transform(X)
    scores  = model.decision_function(Xs).astype(float)
    latest_ts     = ts[-1]
    latest_score  = float(scores[-1])
    threshold     = float(meta.get("threshold", -0.1))
    features_used = ", ".join(meta.get("feature_order", [])) or "rps, err_*"

    # Simple trend (last up to 5 scores)
    hist        = scores[-5:] if scores.shape[0] >= 5 else scores
    mean_last5  = float(hist.mean())
    delta_last  = latest_score - mean_last5
    margin      = threshold - latest_score      # +ve => worse (further below the threshold)

    # Risk bucket + Slack severity
    if latest_score < threshold:
        if margin >= 0.05:
            risk, sev = "Severe", "crit"
        elif margin >= 0.02:
            risk, sev = "High", "crit"
        else:
            risk, sev = "Elevated", "warn"
    else:
        risk, sev = "Normal (no alert)", "info"

    # Human‑readable message
    # Keep it short; Slack will show the facts panel just below.
    what = (
        "*What happened?* Our anomaly model spotted a minute that **doesn't look normal** "
        "compared to your recent traffic. It looks at a few live signals together (request rate "
        "and error counters) and assigns a score—*lower is more unusual*. When it drops below the "
        "*learned* threshold, we alert."
    )
    why = (
        "*Why it matters:* Unusual combinations of traffic + errors often **precede user‑visible issues** "
        "(throttling, backpressure or misconfiguration). Investigate to confirm or rule out."
    )
    next_steps = (
        "*Next steps*\n"
        "• Check gateway/broker for backpressure or resource exhaustion.\n"
        "• Review recent channel errors and any deploys/config changes.\n"
        "• If impact is suspected, scale up or temporarily shed load."
    )

    # Only page when truly anomalous and cooldown allows it
    if latest_score < threshold and cooldown_ok(state, "iforest"):
        slack_post(
            "ML anomaly – minute features",
            f"{what}\n\n{why}\n\n{next_steps}",
            severity=sev,
            facts=[
                ("Latest minute", f"{latest_ts}"),
                ("Risk",         f"{risk}  (margin {margin:+.4f})"),
                ("Score",        f"{latest_score:.4f}"),
                ("Alert threshold", f"{threshold:.4f}"),
                ("Recent avg (last 5)", f"{mean_last5:.4f}  (Δ {delta_last:+.4f})"),
                ("Signals used", features_used),
                ("Window",      f"last {IFOREST_WINDOW_MIN}m"),
            ],
            mention=True,  # respects SLACK_MENTION if set
        )
        mark(state, "iforest")




# -------------------------
# Main loop
# -------------------------
def main():
    log.info("AI alert bot starting. ES=%s LOOP_SEC=%s", ES_URL, LOOP_SEC)
    state = {}
    while True:
        try:
            watch_backpressure(state)
            watch_clientstatus(state)
            watch_ops_p95(state)
            watch_channel_payloads(state)
            watch_channel_http_errors(state)
            watch_payloads_by_tenant(state)
            watch_ops_gc_pressure(state)
            watch_keycloak_failures(state)
            watch_ingestion_stall(state)
            watch_iforest_anomaly(state)
            watch_zeebe_resource_exhausted(state)

        except Exception as e:
            log.exception("Watcher error: %s", e)
        time.sleep(LOOP_SEC)

if __name__ == "__main__":
    main()
