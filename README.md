# Tokosint

**Tokosint** is a passive OSINT toolkit with strict validation of findings and the relations between them.
It is built on a fork of [BBoT](https://github.com/blacklanternsecurity/bbot) 3.0.2 by Black Lantern Security:
the recursive engine, modules and event types come from BBoT; on top of them Tokosint adds a validation layer,
a curated and reworked set of passive sources, and a local web interface.

> Use it only against targets you are authorised to investigate. The toolkit is built for passive collection:
> requests go to third-party sources; the target's own infrastructure is touched only by DNS resolution and by
> the `http` module's requests to the target's web resources.

## Concept

1. **Every asset type is a separate kind of finding** with its own fields (DNS name, IP, URL, port, email,
   repository, finding…).
2. **A source takes typed findings as input and produces typed findings.**
3. **Discovery is recursive:** every new finding is run through every source that accepts it, never twice through
   the same source.
4. **Validation is the core.** Every finding records where it was discovered and which finding it is related to.
5. **Three statuses.** *Valid* — current now; *historical* — was current in the past (still searched, for context);
   *false* — not stored and not used for recursion.
6. **Validation metadata:** observation date, number of sources confirming the relation, freshness of the source's data.

## What is different from BBoT

### Validation model (`bbot/bbot/modules/internal/validity.py`)
A built-in intercept module tags every observation after DNS resolution:

- **Source freshness** — a mandatory `meta["freshness"]` field on every module that produces events:
  `current` (live DNS/HTTP, unexpired certificates, current host state), `historical` (archives, passive DNS,
  indexes, CT history), `inherit` (derived from the parent: a parsed page, file or URL).
- **Recursion rule:** status = min(source freshness, parent status). A valid parent may have children of any
  status; a historical parent, by default, no valid ones.
- **Checks** (they may demote a finding or confirm it):
  - **DNS:** a name that does not resolve → historical; a dangling CNAME → historical; wildcard resolution proves
    nothing; a target subdomain that resolves → *confirmed now* (valid even if it was found in an archive).
  - **HTTP:** a target resource that answers → confirmed; 404/410 → historical.
  - **Relation:** an out-of-scope DNS name is valid only with a proven relation (a target DNS record, or promotion
    by the `related_domains` module). A link on a page, a shared IP or a shared certificate is not proof: such names
    are false and hidden from the output (the relation analyser still sees them and may promote the domain).
  - **Junk:** names without a public suffix (`hand@3x.png`), `example.*`, placeholder emails, profiles whose owner
    could not be verified (found only because the name matched).
- **Third party:** providers from the target's DNS records (mail, DNS, cloud) are a valid relation tagged `third-party`.
- False findings are written to `scans/<scan>/validity_false.jsonl` with the reason.
- The final status of a finding is recomputed over the graph of all discovery paths (`web/validity.py`): if a finding
  first arrived from an archive and later from a current source, it and its descendants become valid without
  querying the sources again.

### Sources
The BBoT module set was cut down to passive modules, each one reviewed (free tier, hardcoded limits, false
relations); the rest live in `bbot/modules_archive/` and come back with `bin/module restore <name>`.
New modules: `commoncrawl`, `criminalip`, `crtname`, `hudsonrock`, `netlas`, `robtex`, `shodanct`, `subdomainapi`,
`thc`, `related_domains` (promotes related domains into scope on DNS evidence: NS/MX/SPF/DMARC).
Fixed or reworked, among others: `virustotal` (pagination), `shodan_idb` (API key mode), `censys_ip`
(Platform API v3), `trickest`, `hunterio`, `pgp`, `social`, `dockerhub` (profile ownership check), `trufflehog`
(secret verification is off by default — it would mean using leaked credentials).

### Web interface (`web/`, no dependencies, no build step)
- **Analysis** — start scans, list scans, findings with their status (valid / historical / false with the reason),
  DNS check and third-party tag; filters, sorting, a details card with the discovery context;
  a per-source report (what each source found and how much, which sources did not start and why).
- **Sources** — module metadata: input/output, API key, quotas, data freshness, health check result.
- **Keys** — add, change and delete API keys (values are never sent back to the UI, only a mask).

## Installation

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). On macOS `blasthttp` is built from source against
Homebrew OpenSSL, and some module dependencies need GNU tar (`brew install gnu-tar`).

```bash
git clone https://github.com/nickotoko/Tokosint.git && cd Tokosint
cd bbot && uv sync --python 3.12 --group dev && cd ..
# macOS:
# cd bbot && OPENSSL_DIR=/opt/homebrew/opt/openssl@3 PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig \
#   uv sync --python 3.12 --group dev && cd ..
cp config/secrets.example.yml config/secrets.yml && chmod 600 config/secrets.yml   # API keys are optional
```

The configuration is isolated in `config/` (the `BBOT_CONFIG_DIR` variable, set by the `bin/` scripts); the global
`~/.config/bbot` is not used.

## Usage

```bash
# web interface: http://127.0.0.1:8777/  (listens on localhost only)
bin/web

# command-line scan (results go to scans/<name>/)
bin/osint -t target.example -f passive -y --no-deps -c scope.report_distance=1 -n <name>

# selected sources only
bin/osint -t target.example -m crt certspotter hackertarget -om json -n <name> -y

# manage the module set
bin/module list | restore <name> | archive <name>

# deep source health check (real requests to neutral targets)
bin/healthcheck

# tests
cd bbot && .venv/bin/pytest bbot/test/test_step_2/module_tests/test_module_validity.py -q
bbot/.venv/bin/pytest web/test_validity.py -q
```

## Limitations

- **Not strictly passive:** DNS resolution goes through the system resolvers and reaches the target's authoritative
  name servers; the `http` module requests the target's web resources (without it there is no way to tell whether
  a resource is alive). BBoT's active modules (port scanners, brute force, fuzzing) are archived and were not reviewed.
- **A status is a snapshot taken during the scan:** resolution and HTTP answers depend on the resolver, caches,
  geolocation and anti-bot protection.
- **The checks are heuristics:** shared hosting is detected by the number of names on an IP and the network owner;
  the placeholder email list is a heuristic; a Docker Hub profile owner is verified only by a link to a target domain
  in the profile. IP validation (AS, anti-DDoS proxies, CDN) and port checks through third-party services are planned.
- **Out-of-scope names without a proven relation are hidden:** a related domain reaches the results only if
  `related_domains` promotes it (NS/MX/SPF/DMARC). WHOIS and certificate relations are not used yet.
- **Source quotas:** many free tiers are small (e.g. hunter.io — 50 requests a month, VirusTotal — 500 a day);
  the web server runs a deep health check once a day, which spends them too. Some sources do not work without a key.
- **One scan at a time** when started from the UI; the running scan's status is kept in the server's memory.
- Some upstream BBoT tests refer to archived modules and fail.
- Tested on macOS; Linux should work the same (BBoT targets it), Windows is untested.

## Layout

```
bbot/            BBoT 3.0.2 fork (modules, core, tests); bbot/modules_archive/ — modules outside the active set
bin/             osint (scan), web (UI), module (module set and keys), healthcheck
config/          bbot.yml — project config; secrets.yml — API keys (not in git), secrets.example.yml — template
web/             server.py, scans.py, validity.py, apikeys.py, health.py, index.html
scans/           scan results (not in git)
```

## License

AGPL-3.0, same as BBoT (`LICENSE`). Tokosint is a modified version of BBoT 3.0.2 © Black Lantern Security;
changes: the validation layer, the module set and module fixes, the web interface and launcher scripts.
