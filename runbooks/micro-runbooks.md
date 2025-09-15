# PH‑EE AI Bot — Micro‑runbooks (on‑call)

> Copy‑paste ready checks for common PH‑EE failures. Use the **env + object map** below to match your cluster naming.

---

## Env & object map (adjust if your names differ)
```bash
# Namespace
export NS=paymenthub

# Zeebe
export GATEWAY_DEPLOY=phee-zeebe-gateway           # Deployment name
export BROKER_STS=phee-zeebe                        # StatefulSet name

# Apps (container names as they appear in logs)
export CHANNEL_CONTAINER=ph-ee-connector-channel
export OPS_APP_CONTAINER=phee-operations-app        # or: ph-ee-operations-app
```
> If your cluster uses different names, change the variables above and re‑run the commands.

---

## Global norms
- **Triage order**: Symptom → Scope → Shared cause? → Fix fast → Verify → Follow‑ups.
- **Dashboards**: Keep a Kibana saved search per component + a Grafana board pinned for latency/error SLOs.
- **Exit criteria**: Every runbook section defines when you are “done”. Don’t close early.

---

## 1) Zeebe gateway backpressure ("writer is full")
**Trigger**: Logs show `writer is full`, `ResourceExhausted`, or `Failed to write client request` in last 10–15m.

**Quick checks**
```bash
# Gateway logs (last 10m)
kubectl -n $NS logs deploy/$GATEWAY_DEPLOY --since=10m \
  | egrep -i "writer is full|ResourceExhausted|Failed to write client request" || true

# Broker leadership / elections (last 10m)
kubectl -n $NS logs statefulset/$BROKER_STS -c zeebe --since=10m \
  | egrep -i "election|timeout|append|raft" || true

# Pod/node resources
kubectl -n $NS top pods | egrep -i "zeebe|gateway" || true
kubectl get nodes | tail -n +2 | awk '{print $1}' | \
  xargs -I{} kubectl describe node {} | egrep -i "(Disk|Memory)Pressure" || true
```

**Optional topology (if `zbctl` available)**
```bash
kubectl -n $NS port-forward deploy/$GATEWAY_DEPLOY 26500:26500 >/dev/null 2>&1 &
zbctl --insecure --address 127.0.0.1:26500 topology || true
```

**Likely causes**
- Sudden load spike (clients/JMeter), gateway under‑provisioned.
- Broker IO saturation (PVC too slow / nearly full), snapshot/compaction lag.
- Leader flapping during node pressure or noisy neighbor.

**Actions (now)**
- **Throttle load** (reduce RPS/threads; pause spiky clients).
- **Scale gateway** to 2 replicas; raise CPU/mem requests.
- **Validate broker storage**: free space ≥20%, fast SSD class; restart if stuck after relief.

**Follow‑ups**
- Tune snapshot/compaction periods; ensure steady headroom during peaks.
- Revisit HPA targets for gateway based on p95 traffic.

**Exit criteria**
- No new backpressure lines for **15m** and client 5xx due to Zeebe near‑zero.

---

## 2) ClientStatusException / Gateway internal error
**Trigger**: Channel/Ops hit `ClientStatusException` or gateway 5xx spikes.

**Connectivity & events**
```bash
# Service/ports
kubectl -n $NS get svc | egrep -i "zeebe"

# From gateway pod: check broker internal port (26502)
kubectl -n $NS exec deploy/$GATEWAY_DEPLOY -- sh -lc 'nc -zv $BROKER_STS 26502 || true'

# Gateway events & restarts
kubectl -n $NS describe deploy $GATEWAY_DEPLOY | sed -n '/Events/,$p'
```

**Likely causes**
- Wrong service name/port, TLS mismatch, or broker restart loop.

**Actions (now)**
- Fix SVC endpoints; ensure broker is stable before bouncing gateway.
- Increase client retry/backoff; confirm timeouts align with p95 latencies.

**Exit criteria**
- `zbctl … topology` stable; no new `ClientStatusException` in **15m**.

---

## 3) Ops‑App p95 latency (SLO breach)
**SLO example**: p95 < **800 ms** for Ops APIs over 15m.

**Where to look**
- **Kibana**: filter `Attributes.k8s.container.name: "$OPS_APP_CONTAINER"` and `TenantAwareHeaderFilter.doFilter`.
- **DB**: `operationsmysql` CPU/mem, connections, slow queries (if enabled).
- **JVM**: GC pauses/heap headroom.
- **Downstream**: identity, account‑mapper, channel connectors.

**ES percentile (JSON DSL)**
```json
{
  "size": 0,
  "aggs": { "latency_p95": { "percentiles": { "field": "Latency", "percents": [95] } } },
  "query": { "bool": { "filter": [
    { "term": { "Attributes.k8s.container.name": "phee-operations-app" } },
    { "range": { "@timestamp": { "gte": "now-15m" } } }
  ] } }
}
```

**Actions (now)**
- Scale Ops‑App (HPA), right‑size DB pool; warm caches; roll back if a recent deploy correlates.
- If GC bound: raise `-Xmx` cautiously or tune GC.

**Exit criteria**
- p95 <= SLO for **15m** sustained.

---

## 4) Channel suspicious inbound payloads
**Goal**: catch invalid enums, negative/oversized amounts, XSS/SQLi in free text.

**KQL — invalid enums/amounts**
```
Attributes.k8s.container.name:"ph-ee-connector-channel" AND (
  Body:"partyIdType\":\"INVALID" OR
  Body:"\"amount\":\"-" OR
  Body:"currency\":\"???"
)
```

**KQL — possible injection/XSS**  
*(KQL regex is case‑sensitive; emulate CI with char classes)*
```
Attributes.k8s.container.name:"ph-ee-connector-channel" AND (
  Body:/<\s*[Ss][Cc][Rr][Ii][Pp][Tt]/ OR
  Body:/UNION\s+SELECT/ OR
  Body:/OR\s+1=1/
)
```

**Actions (now)**
- Reject at Channel (4xx) with clear reason; cap `note` length; enforce JSON schema with enum allowlists.
- Add ingress WAF (ModSecurity/OWASP CRS) for generic XSS/SQLi.

**Exit criteria**
- No new suspicious payloads for **1 business hour**; 4xx stays at baseline.

---

## 5) Channel error‑rate surge
**Split**: 4xx (input/tenant) vs 5xx (downstream/infra).

**KQL — 5xx** *(adjust field to your schema)*
```
Attributes.k8s.container.name:"ph-ee-connector-channel" AND status:[500 TO 599]
```

**KQL — 4xx**
```
Attributes.k8s.container.name:"ph-ee-connector-channel" AND status:[400 TO 499]
```

**Correlate**
- Compare with Zeebe backpressure window; pivot by `tenant_id`, `fspId`, endpoint, build version.

**Actions (now)**
- Roll back latest Channel/connector build if correlated.
- Rate‑limit abusive tenants; verify Mojaloop/AMS health.

**Exit criteria**
- 5xx < **1%** over **30m**; 4xx at historical baseline.

---

## 6) Zeebe `RESOURCE_EXHAUSTED`
**Trigger**: Gateway/Channel logs include `RESOURCE_EXHAUSTED` or `no more partitions available to retry`.

**Check**
```bash
kubectl -n $NS logs deploy/$GATEWAY_DEPLOY --since=10m \
  | egrep -i "RESOURCE_EXHAUSTED|no more partitions|Expected to execute the command"
```

**Actions (now)**
- Reduce producers’ concurrency; pause batch jobs.
- Scale gateway; ensure brokers healthy (see #1) and not compaction‑stalled.

**Exit criteria**
- No new `RESOURCE_EXHAUSTED` for **15m** and throughput back to baseline.

---

## Micro‑runbook template (reuse for new alerts)
```
### <Symptom / Alert name>
**Trigger:** <alert text / threshold>
**Dashboards:** <Grafana panel or Kibana saved search>
**Logs/metrics to check:** <copy‑paste cmds / KQL / DSL>
**Likely causes:** <ranked list>
**Actions (now):** <throttle / scale / restart / config>
**Follow‑ups:** <tuning or PRs>
**Exit criteria:** <measurable, time‑bounded>
```

---

## Quick actions cheat‑sheet
```bash
# Restart a deployment (zero‑downtime expectations depend on replicas)
kubectl -n $NS rollout restart deploy/<name>
kubectl -n $NS rollout status deploy/<name>

# Scale up/down\ nkubectl -n $NS scale deploy/<name> --replicas=2

# Port‑forward Elasticsearch or Gateway for local tooling
kubectl -n $NS port-forward svc/elasticsearch-master 9200:9200
kubectl -n $NS port-forward deploy/$GATEWAY_DEPLOY 26500:26500
```
