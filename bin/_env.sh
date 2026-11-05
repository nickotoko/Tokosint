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

check_secrets() {
  # config/secrets.yml must keep every module under "modules:". A module block at the top level (written that way by an
  # older Keys tab when the file was BBoT's comment-only template) is moved back under "modules:"; a YAML syntax error
  # stops with the line number. Only locations are printed, never key values.
  [ -f "$ROOT/config/secrets.yml" ] || return 0
  "$ROOT/bbot/.venv/bin/python" -I - "$ROOT/config/secrets.yml" "$ROOT/bbot/bbot/modules" <<'PY' || exit 1
import os, sys, yaml
path, modules_dir = sys.argv[1], sys.argv[2]
text = open(path).read()
try:
    data = yaml.safe_load(text) or {}
except yaml.YAMLError as e:
    mark = getattr(e, "problem_mark", None)
    where = f" (line {mark.line + 1})" if mark else ""
    sys.exit(f"config/secrets.yml is not valid YAML{where}: fix the indentation, or delete the file and set keys on the Keys tab")
if not isinstance(data, dict):
    sys.exit("config/secrets.yml must be a mapping with a top-level 'modules:' key")
known = {f[:-3] for f in os.listdir(modules_dir) if f.endswith(".py")}
misplaced = [k for k in data if k != "modules" and k in known and isinstance(data[k], dict)]
if misplaced:
    modules = data.get("modules") or {}
    for k in misplaced:
        modules.setdefault(k, {}).update(data.pop(k))
    data["modules"] = modules
    header = "".join(l for l in text.splitlines(keepends=True) if l.startswith("#"))
    if header and not header.endswith("\n"):
        header += "\n"
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    print(f"repaired config/secrets.yml: moved {', '.join(misplaced)} under 'modules:'", file=sys.stderr)
PY
}

foreign_home_dirs() {
  # directories under ~/.cache and ~/.bbot (two levels deep, ~30 ms) that are not owned by the current user, usually
  # left by an earlier `sudo` run; BBoT, tldextract, cloudcheck and uv write there and fail or hang on them
  local me; me="$(id -un)"
  { find "$HOME/.cache" -maxdepth 2 ! -user "$me" -print 2>/dev/null
    find "$HOME/.bbot" -maxdepth 2 ! -user "$me" -print 2>/dev/null; } \
    | sed -E "s|^($HOME/\.cache/[^/]+).*|\1|; s|^($HOME/\.bbot).*|\1|" | sort -u
}

check_home_ownership() {
  # warn (do not stop): stale root-owned leftovers are sometimes harmless, but a root-owned cache makes scans hang
  local dirs; dirs="$(foreign_home_dirs)"
  [ -z "$dirs" ] && return 0
  {
    echo "! Not owned by $(id -un) (usually left by an earlier sudo run) — scans may fail or hang:"
    echo "$dirs" | sed "s|^|    |"
    printf '  fix:  sudo chown -R "%s"' "$(id -un)"
    echo "$dirs" | while IFS= read -r d; do printf ' "%s"' "$d"; done
    echo
  } >&2
}
