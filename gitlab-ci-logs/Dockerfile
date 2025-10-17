FROM gitguardian/ggshield:latest

WORKDIR /app

# Add curl for API calls and jq for JSON parsing
RUN \
    apt-get update \
    && apt-get install -y --no-install-recommends curl jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data
VOLUME [ "/data" ]
CMD ["ggshield"]