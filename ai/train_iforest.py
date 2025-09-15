#!/usr/bin/env python3
import os, json, math, time, argparse, logging, requests
from datetime import datetime, timezone, timedelta
import numpy as np
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
import joblib

log = logging.getLogger("train-iforest")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

def es_search_all(es_url, index, start_iso, batch=2000):
    """Pull docs for >= start_iso. We keep it simple: one page if small; else paginate with search_after."""
    query = {
        "size": batch,
        "sort": [{"ts_minute":"asc"}],
        "query": {"range": {"ts_minute": {"gte": start_iso}}},
        "_source": ["ts_minute", "rps", "err_backpressure", "err_clientstatus", "err_error_level"],
    }
    url = f"{es_url}/{index}/_search"
    auth = None  # add (user, pass) if you need
    results = []
    sa = None

    while True:
        q = dict(query)
        if sa:
            q["search_after"] = sa
        r = requests.post(url, json=q, auth=auth, timeout=30)
        r.raise_for_status()
        data = r.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break
        results.extend(hits)
        sa = hits[-1]["sort"]
        if len(hits) < batch:
            break
    return results

def build_features(hits):
    """
    Feature vector order (persisted in meta):
      0: rps
      1: err_backpressure
      2: err_clientstatus
      3: err_error_level
      4: err_rate_total = (err_backpressure+err_clientstatus+err_error_level)/(max(rps,1))
    """
    X = []
    for h in hits:
        src = h["_source"]
        rps = float(src.get("rps", 0.0))
        b   = float(src.get("err_backpressure", 0.0))
        cs  = float(src.get("err_clientstatus", 0.0))
        ee  = float(src.get("err_error_level", 0.0))
        err_rate_total = (b+cs+ee)/max(rps, 1.0)
        X.append([rps, b, cs, ee, err_rate_total])
    return np.array(X, dtype=float)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--es-url", default=os.getenv("ES_URL","http://localhost:9200"))
    ap.add_argument("--index",  default=os.getenv("IFOREST_SOURCE_INDEX","ph-ee_features_1m_all"))
    ap.add_argument("--hours",  type=int, default=int(os.getenv("IFOREST_TRAIN_HOURS","48")))
    ap.add_argument("--outdir", default=os.getenv("IFOREST_MODEL_DIR","ai/models"))
    ap.add_argument("--contamination", type=float, default=float(os.getenv("IFOREST_CONTAM","0.03")),
                    help="expected anomaly fraction")
    args = ap.parse_args()

    start = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).isoformat()
    log.info("Training from index=%s since %s", args.index, start)
    hits = es_search_all(args.es_url, args.index, start)
    if not hits:
        raise RuntimeError("No training data found; ensure transform ph-ee_features_1m_all has docs in the time range.")

    X = build_features(hits)
    log.info("Rows=%d  Feature-dim=%d", X.shape[0], X.shape[1])

    scaler = RobustScaler().fit(X)
    Xs = scaler.transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    ).fit(Xs)

    # Choose threshold using decision_function on training set (lower == more anomalous)
    scores = model.decision_function(Xs)
    thresh = float(np.quantile(scores, 0.02))  # 2% lower-tail by default

    os.makedirs(args.outdir, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler}, os.path.join(args.outdir, "iforest.joblib"))
    meta = {
        "feature_order": ["rps","err_backpressure","err_clientstatus","err_error_level","err_rate_total"],
        "threshold": thresh,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "index": args.index,
        "hours": args.hours,
        "contamination": args.contamination,
    }
    with open(os.path.join(args.outdir, "iforest_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    log.info("Saved model to %s / iforest.joblib and iforest_meta.json; threshold=%.4f", args.outdir, thresh)

if __name__ == "__main__":
    main()
