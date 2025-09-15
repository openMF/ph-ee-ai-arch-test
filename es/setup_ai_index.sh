#!/usr/bin/env bash
set -euo pipefail
ES_URL=${ES_URL:-http://127.0.0.1:9200}

echo "[1] Put index template (data stream)"
curl -fsS -X PUT "$ES_URL/_index_template/ph-ee-ai-alerts" -H 'Content-Type: application/json'   -d @es/index_template_ai_alerts.json || true
echo

echo "[2] Create data stream (idempotent)"
curl -fsS -X PUT "$ES_URL/_data_stream/ph-ee-ai-alerts" -H 'Content-Type: application/json' -d '{}' || true
echo

echo "[OK] ph-ee-ai-alerts data stream ready"
