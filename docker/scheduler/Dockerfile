# GNAT scheduler service
# Runs the FeedScheduler daemon — ingests from all configured sources on cron schedule.
FROM python:3.11-slim

LABEL maintainer="GNAT" \
      description="GNAT feed scheduler service"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -e ".[schedule,ingest,persist]"

# Config is bind-mounted at runtime via GNAT_CONFIG env var
ENV GNAT_CONFIG=/etc/gnat/config.ini

# Workspace persistence volume
VOLUME ["/var/gnat/workspace"]

CMD ["python", "-m", "gnat.schedule.daemon"]
