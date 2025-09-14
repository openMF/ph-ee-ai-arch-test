#!/usr/bin/env bash
set -euo pipefail
ES_URL=${ES_URL:-http://127.0.0.1:9200}

now=$(date -u +%FT%TZ)

echo "[seed] backpressure line"
curl -fsS -XPOST "$ES_URL/logs-test/_doc" -H 'Content-Type: application/json' -d @- <<JSON
{"@timestamp":"$now","Attributes":{"k8s":{"container":{"name":"zeebe-gateway"}}},"Body":"io.camunda.zeebe.gateway.cmd.BrokerErrorException: Received error from broker (INTERNAL_ERROR): Failed to write client request to partition '1', because the writer is full."}
JSON
echo

echo "[seed] ops-app slow"
curl -fsS -XPOST "$ES_URL/logs-test/_doc" -H 'Content-Type: application/json' -d @- <<JSON
{"@timestamp":"$now","Attributes":{"k8s":{"container":{"name":"ph-ee-operations-app"}}},"Body":"... TenantAwareHeaderFilter.doFilter - Start: 1756682125437 -- total: 950 -- method: GET -- url: http://ops ..."}
JSON
echo

echo "[seed] channel suspicious inbound payload"
PAYLOAD='{"clientRefId":"txn-9999","payer":{"partyIdInfo":{"partyIdType":"?INVALID","partyIdentifier":"37480190222","fspId":"jupiter"}},"payee":{"partyIdInfo":{"partyIdType":"EMAIL","partyIdentifier":"hacker@example.com","fspId":"jupiter"}},"amount":{"amount":"-10.000","currency":"cad"},"transactionType":{"scenario":"TRANSFER","initiator":"PAYER","initiatorType":"CONSUMER"},"note":"<script>alert(1)</script>"}'
BODY="31-08-2025 23:03:25.437 [http] INFO inbound-transaction-request.log - ## CHANNEL -> PAYER inbound transfer request: $PAYLOAD"
python3 - "$ES_URL" "$now" "$BODY" <<'PY'
import json,sys,requests
es,now,body = sys.argv[1:4]
doc = {"@timestamp":now, "Attributes":{"k8s":{"container":{"name":"ph-ee-connector-channel"}}}, "Body":body}
r = requests.post(f"{es}/logs-test/_doc", json=doc, timeout=10); r.raise_for_status()
print(r.text)
PY
echo
echo "[done] seeded 3 docs into logs-test"
