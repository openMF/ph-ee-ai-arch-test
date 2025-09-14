SHELL := /bin/bash

help:
	@echo "Targets:"
	@echo "  init-es        -> create AI alerts data stream template"
	@echo "  seed           -> insert sample log docs into logs-test"
	@echo "  run            -> run bot locally (requires venv/requirements)"
	@echo "  docker-build   -> build container image"
	@echo "  k8s-apply      -> apply k8s manifests in paymenthub ns"

init-es:
	ES_URL=$${ES_URL:-http://127.0.0.1:9200} ES_URL=$$ES_URL bash es/setup_ai_index.sh

seed:
	ES_URL=$${ES_URL:-http://127.0.0.1:9200} ES_URL=$$ES_URL bash es/seed_samples.sh

run:
	python ai/ai_alert_bot.py

docker-build:
	docker build -t ph-ee-ai-alert-bot:latest -f - . <<'DOCKER'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ai ai
CMD ["python","ai/ai_alert_bot.py"]
DOCKER

k8s-apply:
	kubectl -n paymenthub apply -f k8s/secret-slack-webhook.example.yaml
	kubectl -n paymenthub apply -f k8s/deployment.yaml
