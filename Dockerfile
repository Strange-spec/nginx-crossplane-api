FROM python:3.11-slim

LABEL maintainer="NGINX Crossplane Config Checker API"
LABEL description="Dockerized NGINX / NGINX Plus configuration checker API powered by Crossplane + Deep Semantic Analyzer + Auto-Mocked nginx -t"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=8080

WORKDIR /app

# Install nginx binary, openssl (for auto-mocked SSL certificates), and curl (for HEALTHCHECK)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx openssl curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /app/mock_assets && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /app/mock_assets/mock.key \
      -out /app/mock_assets/mock.crt \
      -subj "/CN=localhost"

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn -r /app/requirements.txt

COPY app /app/app
COPY tests /app/tests

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
