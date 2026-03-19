FROM python:3.11-slim

LABEL org.opencontainers.image.title="SwarmHawk AI"
LABEL org.opencontainers.image.description="Autonomous offensive security assessment"
LABEL org.opencontainers.image.url="https://swarmhawk.ai"

WORKDIR /app

# Install system dependencies for optional tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python package
COPY pyproject.toml README.md ./
COPY swarmhawk/ ./swarmhawk/
RUN pip install --no-cache-dir -e .

# Reports output volume
VOLUME ["/app/reports", "/app/scopes"]

ENTRYPOINT ["swarmhawk"]
CMD ["--help"]
