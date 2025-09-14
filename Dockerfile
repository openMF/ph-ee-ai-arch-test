FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ai ai
ENV PYTHONUNBUFFERED=1
CMD ["python","-u","ai/ai_alert_bot.py"]
