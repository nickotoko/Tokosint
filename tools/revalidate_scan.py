"""Re-validate an old scan with the current rules (strict FOFA matches, host relation, wildcard placeholder): moves false events from output.json to
validity_false.jsonl (originals kept as *.before-revalidation.*). per_ip.json - FOFA `ip="X"` answers for the IPs that fofa
queried host details for: {ip: {"error", "results": [[host, port, cert.subject.cn, domain], ...]}}.
usage: bbot/.venv/bin/python tools/revalidate_scan.py scans/<scan> per_ip.json [--apply]"""
import collections, json, re, shutil, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))
import scans  # noqa: E402

scan_dir, per_ip_file = Path(sys.argv[1]), sys.argv[2]
apply = "--apply" in sys.argv
out_file = scan_dir / "output.json"
events = [json.loads(l) for l in out_file.open()]
per_ip = json.load(open(per_ip_file))
IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
HOST_FINDING_TYPES = ("OPEN_TCP_PORT", "URL", "TECHNOLOGY")
DNS_MODULES = {"A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR", "SRV", "CAA"}

def host_of(e):
    h = e.get("host")
    if h: return str(h)
    d = e.get("data")
    if isinstance(d, str): return re.sub(r":\d+$", "", d.split("://")[-1].split("/")[0])
    return ""

def tagged(e, t): return t in (e.get("tags") or [])

# the target's domains: names in scope that are not false
inscope = {str(e["data"]).lower() for e in events if e.get("type") == "DNS_NAME" and e.get("scope_distance") == 0}
import tldextract
domains = {tldextract.extract(h).top_domain_under_public_suffix for h in inscope} - {""}
def under(h, ds=domains):
    h = str(h or "").lower().rstrip(".")
    if h.startswith("*."): h = h[2:]
    return bool(h) and any(h == d or h.endswith("." + d) for d in ds)

resolved_ips = set()
for e in events:
    if e.get("type") == "IP_ADDRESS" and e.get("module") in ("A", "AAAA") and "validity-false" not in (e.get("tags") or []):
        chain = e.get("parent_chain") or []
        pe = next((x for x in events if x.get("uuid") == chain[-2]), None) if len(chain) > 1 else None
        if pe is not None and under(host_of(pe)):
            resolved_ips.add(str(e["data"]))

def ip_tied(ip):
    if ip in resolved_ips:
        return True  # an in-scope name resolves to it
    """FOFA associates the IP with a target name or certificate (host, domain or cert CN under a target domain)."""
    r = per_ip.get(ip)
    if r is None or r.get("error"): return None  # unknown
    for row in r["results"]:
        host, _port, cn, dom = (list(row) + ["", "", "", ""])[:4]
        name = re.sub(r":\d+$", "", str(host).split("://")[-1].split("/")[0])
        if under(name) or under(cn) or under(dom): return True
    return False

ip_tags = collections.defaultdict(set)
for e in events:
    if e.get("type") == "IP_ADDRESS": ip_tags[str(e["data"])].update(e.get("tags") or [])
def foreign_ip(ip):
    t = ip_tags.get(ip, set())
    if "ip-proxy" in t or "third-party" in t or any(x.startswith("cdn-") for x in t): return "a CDN / proxy / third-party front"
    return None

by_uuid = {e.get("uuid"): e for e in events if e.get("uuid")}
junk = {}  # uuid -> reason
for e in events:
    u, t, m, ctx = e.get("uuid"), e.get("type"), e.get("module"), e.get("discovery_context", "")
    if not u or t == "SCAN" or tagged(e, "seed"): continue
    h = host_of(e)
    if h.startswith("_wildcard."):
        junk[u] = f"wildcard placeholder, not a host: every name under {h[len('_wildcard.'):]} resolves"; continue
    if m == "fofa" and "host details for" in ctx:
        ip = re.search(r"host details for (\S+) ", ctx).group(1)
        why = foreign_ip(ip)
        if why: junk[u] = f"fofa host details of {ip}: {why}, not a target asset"; continue
        tied = ip_tied(ip)
        if tied is False: junk[u] = f"fofa host details of {ip}: FOFA has no target name or certificate on this IP"; continue
    if m == "fofa" and "searched FOFA" in ctx and t == "OPEN_TCP_PORT" and IP_RE.match(h):
        q = re.search(r'domain="([^"]+)"', ctx).group(1)
        tied = ip_tied(h)
        if tied is False: junk[u] = f'fofa result {h} for "{q}": certificate is not for the target (substring match)'; continue
    if t in HOST_FINDING_TYPES and (e.get("scope_distance") or 0) > 0 and h and not IP_RE.match(h) and m not in DNS_MODULES and not under(h):
        chain = e.get("parent_chain") or []
        parent = by_uuid.get(chain[-2]) if len(chain) > 1 else None
        if parent is None or host_of(parent) != h:
            junk[u] = f"{t} on an out-of-scope host without proven relation ({m})"; continue

# descendants of false findings are false (unless confirmed now)
changed = True
while changed:
    changed = False
    for e in events:
        u = e.get("uuid")
        if not u or u in junk or tagged(e, "freshness-verified"): continue
        chain = e.get("parent_chain") or []
        p = chain[-2] if len(chain) > 1 else None
        if p in junk:
            pe = by_uuid.get(p)
            junk[u] = f"parent is false ({pe['type'] if pe else '?'}: {host_of(pe) if pe else p})"; changed = True

# report on the finding level: a finding goes false only if all its events are false
before = scans.aggregate_scan(out_file, with_false=False)
keep = [e for e in events if e.get("uuid") not in junk]
ev_by_key = collections.defaultdict(list)
for e in events:
    d = scans.asset_data(e)
    if d is not None and e.get("type") != "SCAN": ev_by_key[(e["type"], d)].append(e)
gone = {k: v for k, v in ev_by_key.items() if all(x.get("uuid") in junk for x in v)}
partial = {k for k, v in ev_by_key.items() if k not in gone and any(x.get("uuid") in junk for x in v)}
st = {(f["type"], f["data"]): f["status"] for f in before}
print("in-scope domains:", sorted(domains))
print("events false:", len(junk), "of", len(events))
print("findings -> false:", len(gone), collections.Counter((k[0], st.get(k)) for k in gone).most_common())
print("findings keep (another path):", len(partial))
print("reasons:", collections.Counter(re.sub(r"\d+\.\d+\.\d+\.\d+|\"[^\"]+\"|\([^)]*\)|: .*", "*", r) for r in junk.values()).most_common(12))
unknown = sorted({re.search(r"host details for (\S+) ", e.get("discovery_context", "")).group(1) for e in events
                  if e.get("module") == "fofa" and "host details for" in e.get("discovery_context", "") and ip_tied(re.search(r"host details for (\S+) ", e["discovery_context"]).group(1)) is None})
print("IPs not checked yet:", len(unknown), "resolved from in-scope names:", len(resolved_ips))
print("names going false:", [k for k in gone if k[0] == "DNS_NAME"])

if apply:
    bak = scan_dir / "output.before-revalidation.json"
    if not bak.exists(): shutil.copy2(out_file, bak)
    shutil.copy2(scan_dir / "validity_false.jsonl", scan_dir / "validity_false.before-revalidation.jsonl")
    with (scan_dir / "validity_false.jsonl").open("a") as fh:
        for e in events:
            u = e.get("uuid")
            if u in junk:
                chain = e.get("parent_chain") or []
                fh.write(json.dumps({"type": e["type"], "data": scans.asset_data(e), "module": e.get("module"),
                                     "parent": e.get("parent"), "reason": junk[u] + " [re-validated]",
                                     "hidden": False}, ensure_ascii=False) + "\n")
    out_file.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in keep))
    print("applied: output.json", len(events), "->", len(keep))
