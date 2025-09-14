# AI‑Driven Architectural Test for MIFOS Payment Hub EE — Project Report


This README documents the design and execution of an AI‑driven architectural test program for the MIFOS Payment Hub EE (PH‑EE). 
The work delivered an end‑to‑end, testable resilience and security harness that (a) ingests and enriches runtime logs, (b) derives 
signals for reliability and security, (c) raises human‑readable alerts to Slack, and (d) correlates behavior under load with 
platform resources (Zeebe, Ops‑App, MySQL, and ingress).

## Environment & Baseline

• Platform: PH‑EE on Kubernetes (Azure VM), single node (node name: ph‑ee). 
• Access: port‑forwarding for Kibana, Grafana and service endpoints (no public exposure). 
• Observability: OpenTelemetry Collector (DaemonSet, filelog receiver) → Elasticsearch + Kibana; Grafana with Prometheus and Elasticsearch data sources. 
• Logging scope: PH‑EE connectors, Zeebe broker/gateway, Ops‑App, and (optionally) ingress‑nginx controller. 
• Constraints: Kibana Basic features for alerts (server log connector only), older UI (no “Data Views”); single‑node Elasticsearch; limited CPU/memory on VM.

## Implementation Highlights

1) **Collector & Parsing**
   – filelog receiver watching `/var/log/pods` and `/var/log/containers`, start_at=end (steady‑state), K8s attributes enrichment. 
   – Regex parsers to normalize Java/Zeebe line formats; mapped severities; extracted correlation keys:
      transactionId, zeebe_instance_key, zeebe_job_key, tenant_id, process suffix. 
   – Ops‑App access pattern extractor (`TenantAwareHeaderFilter.doFilter`) to derive per‑request latency (ms). 
   – Zeebe gateway backpressure extraction (partition id) from raw gateway errors (“writer is full”).

2) **Elasticsearch & Kibana**
   – Index template for `ph‑ee‑ai‑alerts*` and smoke‑tested indexing. 
   – Saved Discover/Lens views to validate parsers and queries. 
   – Working log‑threshold rules (e.g., gateway backpressure and client status spikes).

3) **AI Alert Bot (Python)**
   – Periodic ES queries (log windows) convert to signals and post Slack block cards.
   – Detectors: backpressure (gateway), ClientStatusException bursts (gateway/brokers), Ops‑App p95 SLO breach, and channel payload anomalies 
     (negative amount, too‑many decimals, invalid partyIdType, SQLi/XSS patterns, BigInteger overflow). 
   – Slack integration via webhook or bot token; cooldowns to avoid noisy duplicates.

4) **Load & Security Exercises**
   – JMeter: warm‑up, spike, and stress profiles against `/channel/transfer` (HTTPS). 
   – Observed behaviors: 200s under nominal load; 412s (no process definition) near peaks; 500s on malformed payloads; Zeebe “writer is full” during spikes. 
   – Security fuzzing: negatives and oversized numeric amounts, enum poisoning (`partyIdType`), special characters and scripts, SQLi hints, BigInteger overflow traces.

5) **Metrics & Panels**
   – Grafana panels for CPU of Zeebe/gateway and error rate of channel over time (Prometheus + ES).

## Key Results & Findings

• **Backpressure**: Confirmed Zeebe gateway “writer is full” episodes under spike load; actionable runbook drafted (scale/throttle; check partitions). 
• **ClientStatusException**: Correlated to gateway↔broker contention during spikes; useful as an early warning. 
• **Ops‑App latency**: p95 can drift during warmup; raw access‑log extraction enables SLO checks without code changes. 
• **Security inputs**: Negative/oversized amounts and BigInteger overflow detected reliably; some malformed payloads are rejected upstream and may not appear as structured channel logs.
• **Infra contention**: Zeebe CPU peaked ~1.1 cores; many sleeping MySQL connections observed during tests (possible pool tuning task).



