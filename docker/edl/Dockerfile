# GNAT EDL (Enforcement Decision List) HTTP server
# Serves dynamic block-lists over HTTP for consumption by firewalls / proxies.
FROM python:3.11-slim

LABEL maintainer="GNAT" \
      description="GNAT EDL server service"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -e ".[serve,persist]"

ENV GNAT_CONFIG=/etc/gnat/config.ini

VOLUME ["/var/gnat/workspace"]

EXPOSE 8080

CMD ["python", "-m", "gnat.export.edl_server", "--host", "0.0.0.0", "--port", "8080"]
