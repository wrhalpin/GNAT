# GNAT monitor service
# Exposes a /health endpoint and connector status summary for external monitoring.
FROM python:3.15-rc-alpine3.22

LABEL maintainer="GNAT" \
      description="GNAT health monitor service"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -e ".[serve,persist]"

ENV GNAT_CONFIG=/etc/gnat/config.ini

VOLUME ["/var/gnat/workspace"]

EXPOSE 8090

CMD ["python", "-m", "gnat.agents.health_monitor", "--serve", "--host", "0.0.0.0", "--port", "8090"]
