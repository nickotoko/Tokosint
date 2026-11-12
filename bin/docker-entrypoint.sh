#!/usr/bin/env bash
# Entry point for the Tokosint container. The first argument selects the service:
#   web [port]        web backend (default, port 8777)
#   mcp [port]        MCP server over streamable-HTTP (default port 8778)
#   osint <args...>   run a scan (bin/osint passthrough)
#   bash | sh         a shell
# Anything else is executed as-is.
set -euo pipefail
cd /app

cmd="${1:-web}"
shift || true

case "$cmd" in
  web)
    exec bin/web "${1:-8777}"
    ;;
  mcp)
    exec bin/mcp http "${1:-8778}"
    ;;
  osint)
    exec bin/osint "$@"
    ;;
  bash|sh)
    exec "$cmd"
    ;;
  *)
    exec "$cmd" "$@"
    ;;
esac
