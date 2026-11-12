# Tokosint: BBoT fork + web UI + MCP server, in one reproducible image.
# Build:  docker build -t tokosint .
# Run:    docker compose up         (see docker-compose.yml)
#
# The image pins the whole environment (OpenSSL, build tools, BBoT module binaries), which is what makes the
# toolkit start the same way on Linux as on macOS. The venv is built inside the image from bbot/uv.lock.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# System packages BBoT and its modules expect:
#   build-essential, libssl-dev, pkg-config - build blasthttp (BBoT's HTTP engine) from source
#   git, curl, ca-certificates, unzip, p7zip-full - fetching and unpacking module tools
#   nmap - used by some active modules; sudo - ansible 'become' when a module installs an apt dependency
# Keep the apt lists: BBoT's --install-all-deps (below) lets some modules apt-install their own system packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev pkg-config \
        git curl ca-certificates unzip p7zip-full nmap sudo

WORKDIR /app

# Install Python dependencies first (cached unless the lock changes). Needs the bbot package source to build the
# bbot wheel, so copy the bbot tree before syncing.
COPY bbot/ /app/bbot/
RUN cd /app/bbot && uv sync --frozen --no-dev --group mcp

# The rest of the toolkit (web backend, MCP server, bin/ wrappers, config templates, chord-graph assets, ...).
COPY . /app/

ENV BBOT_CONFIG_DIR=/app/config \
    TOKOSINT_BBOT_BASE=/app/.bbot \
    TOKOSINT_WEB_HOST=0.0.0.0 \
    TOKOSINT_MCP_HOST=0.0.0.0 \
    TOKOSINT_MAX_SCANS=2 \
    PATH=/app/bbot/.venv/bin:$PATH

# Pre-install module tool binaries (gowitness for screenshots, httpx, etc.) into the shared BBoT home so scans,
# which run with --no-deps, find them. Non-fatal: a module whose apt/go dependency fails to build here is simply
# unavailable; the core passive set and gowitness install cleanly.
RUN bbot -c home=/app/.bbot --install-all-deps -y \
        || echo "WARNING: some module dependencies failed to install; those modules will be unavailable"
RUN rm -rf /var/lib/apt/lists/*

# scans/ and data/ are bind-mounted volumes at runtime (see docker-compose.yml); create the mount points.
RUN mkdir -p /app/scans /app/data

EXPOSE 8777 8778
ENTRYPOINT ["/app/bin/docker-entrypoint.sh"]
CMD ["web"]
