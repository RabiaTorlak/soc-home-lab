# SOC Lab - Python SOAR konteyner imajı
# Not: Birincil dağıtım systemd (soar.service). Bu imaj, SOAR'ı konteyner
# olarak çalıştırmak isteyenler içindir. iptables ve alerts.json erişimi için
# host ağı + NET_ADMIN gerekir (bkz. ../docker-compose.yml).
FROM python:3.12-slim

LABEL org.opencontainers.image.title="soc-lab-soar" \
      org.opencontainers.image.description="Wazuh SIEM için Python SOAR" \
      org.opencontainers.image.source="https://github.com/RabiaTorlak/soc-home-lab"

WORKDIR /app

# iptables istemcisi (yerel engelleme aksiyonu için)
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

ENTRYPOINT ["python", "soar_responder.py", "--config", "/app/config.yaml"]
