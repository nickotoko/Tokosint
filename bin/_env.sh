# Shared environment for the bin/ scripts (sourced, not executed). Expects ROOT to be set.
#   require_install       stop with a hint when bbot/.venv is missing or the install did not finish
#   CA bundle             if config/ca-bundle.pem exists (made by bin/setup on networks that intercept TLS, e.g. a
#                         corporate proxy), Python, OpenSSL (blasthttp) and curl trust it instead of their own roots

export BBOT_CONFIG_DIR="$ROOT/config"

CA_BUNDLE="$ROOT/config/ca-bundle.pem"
if [ -s "$CA_BUNDLE" ]; then
  export SSL_CERT_FILE="$CA_BUNDLE" REQUESTS_CA_BUNDLE="$CA_BUNDLE" CURL_CA_BUNDLE="$CA_BUNDLE"
fi

require_install() {
  # bbot/.venv/bin/bbot exists only after a complete install (a failed install leaves a bare .venv)
  [ -x "$ROOT/bbot/.venv/bin/bbot" ] || {
    echo "Tokosint is not installed (or the install did not finish): run  $ROOT/bin/setup" >&2
    exit 1
  }
}
