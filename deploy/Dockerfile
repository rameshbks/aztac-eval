FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY aztac ./aztac
COPY policy ./policy
COPY experiments ./experiments
ENV PYTHONUNBUFFERED=1
# Overridden per service in docker-compose.yml
CMD ["uvicorn", "aztac.http_apps:gateway_app", "--host", "0.0.0.0", "--port", "8200"]
