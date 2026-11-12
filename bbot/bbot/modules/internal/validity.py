import json
import time

from bbot.modules.base import BaseInterceptModule
from bbot.core.config.models import BaseModuleConfig, Field

# Finding (IoC) statuses in ascending order: false < historical < valid.
FALSE, HISTORICAL, VALID = 0, 1, 2
STATUS_NAMES = {FALSE: "false", HISTORICAL: "historical", VALID: "valid"}
STATUS_BY_NAME = {v: k for k, v in STATUS_NAMES.items()}
# Own freshness "confirmed by a check now": status valid regardless of the parent.
VERIFIED = 3
OWN_NAMES = {None: "inherit", FALSE: "false", HISTORICAL: "historical", VALID: "current", VERIFIED: "verified"}

# Source data freshness - `meta["freshness"]` of every module that produces events:
#   current    - the source reflects the present state (live DNS, unexpired certs, a current host scan)
#   historical - archive / passive DNS / index: the data may be outdated
#   inherit    - derived from the parent (parsed response, file, URL), no freshness of its own
FRESHNESS = {"current": VALID, "historical": HISTORICAL, "inherit": None}
# Core dummy modules: DNS records of live resolution and target seeds are current.
FRESHNESS_BY_DUMMY_TYPE = {"DNS": "current", "SEED": "current"}

# Stage 2 check verdicts (strongest first): false, "outdated" (capped at historical),
# "confirmed now" (valid even if the parent is historical).
VERDICT_FALSE, VERDICT_HISTORICAL, VERDICT_VERIFIED = "false", "historical", "verified"
# False as a relation to the target, but a candidate for relation analysers: hidden (internal), not dropped.
VERDICT_UNRELATED = "unrelated"

DNS_NAME_TYPES = ("DNS_NAME", "DNS_NAME_UNRESOLVED")
# Findings on a host (host:port, URL, product on a port): an out-of-scope host name needs the same proven relation
# as the name itself, unless the finding hangs off that name (then the name was checked).
HOST_FINDING_TYPES = ("OPEN_TCP_PORT", "URL", "TECHNOLOGY")
# BBoT's placeholder for collapsed wildcard names: "every name under the domain resolves", not a host
WILDCARD_PLACEHOLDER = "_wildcard."
# Live HTTP answer (status-NNN tag on a URL): the resource answers now, except "no such resource".
HTTP_GONE = (404, 410)
PROMOTE_POLICIES = ("in_scope", "none")

# Domains reserved for examples (RFC 2606); the test/local/invalid/localhost/example zones
# are caught by the missing public suffix.
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
# Local parts of placeholder emails from forms and docs (user@..., email@...); checked only on foreign domains.
PLACEHOLDER_LOCALS = {
    "user", "username", "usermail", "name", "email", "mail", "my", "you", "your", "test", "sender", "client",
    "login", "example", "somebody", "someone",
}  # fmt: skip
# Source module tag: ownership of the found profile/account by the target could not be verified -> false.
OWNER_UNVERIFIED_TAG = "owner-unverified"
# A third-party resource the target uses (a provider from its DNS records): the relation is valid, but not a target asset.
THIRD_PARTY_TAG = "third-party"
# ipowner: the address is the front of someone else's service -> third-party (see bbot/modules/internal/ipowner.py)
IP_PROXY_TAG = "ip-proxy"


class validity(BaseInterceptModule):
    """
    Tags every finding with a status: valid / historical / false.

    Stage 1 - recursion rule: status = min(source freshness, parent status).
    A valid parent may have valid, historical and false children; a historical parent by default
    only historical (or false) ones. False findings do not enter the scan (no recursion, not saved);
    they are logged to the scan's `validity_false.jsonl`.

    Stage 2 - checks (`self.checks`): synchronous functions `check(event) -> (verdict, reason) | None`,
    applied when an event is tagged, so descendants always see an already checked parent.
      false       - the finding is false;
      historical  - status is capped at historical (e.g. the name does not resolve);
      verified    - confirmed now: valid even if the discovery path is historical
                    (the only way to lift the "by default" part of the recursion rule).
    Checks read what is already on the event (DNS records from dnsresolve, cloud tags); they never contact the target.

    DNS check (`dns_check`) for DNS_NAME, based on dnsresolve's result:
      no records (NXDOMAIN/empty)       -> historical, tag dns-check-nxdomain
      resolution error (SERVFAIL/timeout) -> unchanged, dns-check-error
      CNAME without an address (dangling) -> historical, dns-check-dangling
      wildcard                          -> unchanged (wildcard resolution proves nothing), dns-check-wildcard
      resolves                          -> dns-check-ok; with `promote_resolved: in_scope` a name in scope by name
                                           (a target subdomain) -> verified

    HTTP check (`http_check`) for URLs with a status-NNN tag (a live http answer): 404/410 -> historical
    (the resource is gone, the path may have come from an archive); 5xx/400 -> no verdict; otherwise
    (2xx/3xx/401/403/405...) the resource answers -> verified if the host is in scope and `promote_resolved: in_scope`.
    HTTP_RESPONSE and the findings extracted from it inherit the URL's status.

    Relation check (`relation_check`): an out-of-scope DNS name is valid only with a proven relation -
      a DNS record of a valid parent (NS/MX/CNAME... - the target uses the resource) or a module with
      `meta["proves_relation"]` (related_domains -> verified). A link on a page, a shared IP, a shared certificate
      prove nothing -> verdict unrelated: status false, but the event is hidden (internal) instead of dropped -
      it never reaches the output, yet relation analysers (related_domains resolves candidates itself) see it
      and may promote the domain. Descendants of a hidden name are ordinary false findings (dropped), no recursion.
      The same applies to a port / URL / technology on an out-of-scope host name that a search module reports
      directly (not through the name): `foo.other.example:443` from a search for target.example is false.

    Tag `third-party`: an out-of-scope name from a target DNS record (MX/NS/CNAME... to a provider), an IP address
    tagged `ip-proxy` by ipowner (reached through a CNAME to a provider, an anti-DDoS/CDN network) and their
    out-of-scope descendants - the relation is valid ("the target uses it"), but it is third-party
    infrastructure, not a target asset.

    Junk check (`junk_check`) - false (except names from DNS records): names/emails without a public suffix
    (`hand@3x.png`, `*.test`, `*.local`), reserved domains (example.com), placeholder emails on foreign domains
    (user@..., email@...), events tagged `owner-unverified` by the source module (a profile found by a name match
    whose ownership could not be verified); BBoT's wildcard placeholder `_wildcard.<domain>` and anything on it
    (a wildcard means every name resolves - it is not a host of the target).

    False findings are dropped (`drop_false`), unrelated ones are hidden; both are logged to `validity_false.jsonl`.

    Event tags:
      validity-<status>    - the observation's status within the scan
      freshness-<level>    - the observation's own freshness relative to its parent in the output
                             (current / historical / inherit / verified / false; omitted parents are folded in);
                             after the scan they are used to recompute the finding's status over all paths
                             (web/validity.py)

    A source module may override the freshness of a single event with a `freshness-current` /
    `freshness-historical` tag (e.g. FOFA: the result is also in a search limited to recent observations).

    Recent observation (`recent_days`): a finding of a historical source whose last_seen (the source's own date of
    the observation, D-028) is at most `recent_days` days before the scan start is current - the index saw the port /
    name / service a few days ago, so it is treated as live (tag `seen-recently`). Older dates or no date - historical.
    The checks still apply: a recently seen name that does not resolve now is historical.
    """

    watched_events = ["*"]
    produced_events = []
    meta = {
        "description": "Mark every finding as valid, historical or false based on source freshness, its parent and checks",
        "created_date": "2026-11-04",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        drop_false: bool = Field(
            True, description="Do not pass false findings to the scan (they are logged to validity_false.jsonl)"
        )
        dns_check: bool = Field(
            True, description="Check DNS names by their resolution: not resolving -> historical, resolving -> verified"
        )
        relation_check: bool = Field(
            True,
            description="Out-of-scope DNS names are false unless the relation is proven (DNS record, related_domains)",
        )
        junk_check: bool = Field(
            True,
            description="False for names/emails without a public suffix, reserved domains, placeholder emails "
            "and events tagged owner-unverified",
        )
        http_check: bool = Field(
            True, description="Check URLs by the live HTTP status: 404/410 -> historical, any other answer -> verified"
        )
        recent_days: int = Field(
            7,
            description="A finding of a historical source that the source itself saw at most this many days before "
            "the scan (its last_seen date) is current (valid); 0 turns this off",
        )
        seed_status_file: str = Field(
            "",
            description="JSON {seed data: valid|historical} - the status seeds already have (a scan that enriches an "
            "earlier one is seeded with its findings: a historical finding stays historical)",
        )
        promote_resolved: str = Field(
            "in_scope",
            description="Which resolving names and answering URLs are verified as valid regardless of the discovery "
            "path: in_scope (target hosts by name) or none",
        )

    scope_distance_modifier = None
    # after dnsresolve (1), cloudcheck and ipowner (3): the checks need DNS records, cloud and ownership tags
    _priority = 4

    async def setup(self):
        self.drop_false = self.config.get("drop_false", True)
        self.seed_status = {}
        seed_status_file = self.config.get("seed_status_file", "")
        if seed_status_file:
            try:
                with open(seed_status_file, encoding="utf-8") as fh:
                    self.seed_status = {str(k): str(v) for k, v in json.load(fh).items()}
            except (OSError, ValueError) as e:
                return False, f"cannot read seed_status_file {seed_status_file}: {e}"
        try:
            self.recent_days = max(0, float(self.config.get("recent_days", 7) or 0))
        except (TypeError, ValueError):
            return False, f"recent_days must be a number of days, got {self.config.get('recent_days')!r}"
        self.promote_resolved = self.config.get("promote_resolved", "in_scope")
        if self.promote_resolved not in PROMOTE_POLICIES:
            return False, f"promote_resolved must be one of {PROMOTE_POLICIES}, got {self.promote_resolved!r}"
        self.checks = []
        if self.config.get("junk_check", True):
            self.checks.append(self.check_junk)
        if self.config.get("relation_check", True):
            self.checks.append(self.check_relation)
        if self.config.get("dns_check", True):
            self.checks.append(self.check_dns)
        if self.config.get("http_check", True):
            self.checks.append(self.check_http)
        # event uuid -> [status, own freshness, verdict reason, hidden, third-party]
        # (events use __slots__, so the state is kept in the module)
        self._state = {}
        self._false_file = None
        self.false_count = 0
        return True

    # --- source freshness ---

    def source_freshness(self, event):
        """The event's own freshness: VALID / HISTORICAL / None (inherits the parent)."""
        # a seed taken from an earlier scan keeps the status it had there
        if self.seed_status and "seed" in event.tags:
            known = {"valid": VALID, "historical": HISTORICAL}.get(self.seed_status.get(str(event.data)))
            if known is not None:
                return known
        # explicit override by the module (based on a record date, etc.)
        for level in ("current", "historical"):
            if f"freshness-{level}" in event.tags:
                return FRESHNESS[level]
        module = event.module
        level = getattr(module, "meta", {}).get("freshness")
        if level is None:
            level = FRESHNESS_BY_DUMMY_TYPE.get(getattr(module, "_type", ""))
        if level is None:
            # a module without declared freshness is conservatively treated as an archive
            self.debug(f"Module {module} has no meta freshness, treating {event} as historical")
            level = "historical"
        if level == "historical" and self.seen_recently(event):
            event.add_tag("seen-recently")
            return VALID
        return FRESHNESS[level]

    def seen_recently(self, event):
        """The source's own date of the observation is within recent_days of the scan start."""
        seen = getattr(event, "last_seen", None)
        if not self.recent_days or seen is None:
            return False
        start = self.scan.start_time.timestamp() if self.scan.start_time is not None else time.time()
        # a date slightly ahead of the scan (source clock / time zone) is still recent
        return start - seen <= self.recent_days * 86400

    # --- stage 2 checks ---

    def check_dns(self, event):
        if event.type not in DNS_NAME_TYPES or "seed" in event.tags:
            return None
        tags = event.tags
        errored = any(t.endswith("-error") for t in tags)
        if "unresolved" in tags or event.type == "DNS_NAME_UNRESOLVED":
            if errored:
                event.add_tag("dns-check-error")
                return None
            event.add_tag("dns-check-nxdomain")
            return VERDICT_HISTORICAL, "does not resolve"
        if any("wildcard" in t for t in tags) or event.data.startswith("_wildcard."):
            event.add_tag("dns-check-wildcard")
            return None
        has_address = "a-record" in tags or "aaaa-record" in tags
        if "cname-record" in tags and not has_address and not errored:
            event.add_tag("dns-check-dangling")
            return VERDICT_HISTORICAL, "CNAME without address"
        event.add_tag("dns-check-ok")
        if self.promote_resolved == "in_scope" and self.scan.in_target(event.host):
            return VERDICT_VERIFIED, "in-scope name resolves"
        return None

    def check_junk(self, event):
        if "seed" in event.tags:
            return None
        if OWNER_UNVERIFIED_TAG in event.tags:
            return VERDICT_FALSE, "owner not verified"
        if str(event.host or "").startswith(WILDCARD_PLACEHOLDER):
            return (
                VERDICT_FALSE,
                f"wildcard placeholder, not a host: every name under {str(event.host)[len(WILDCARD_PLACEHOLDER) :]} resolves",
            )
        if event.type not in DNS_NAME_TYPES + ("EMAIL_ADDRESS",):
            return None
        if getattr(event.module, "_type", "") == "DNS":
            # a name from a real DNS record (MX to mail.corp.local, etc.): the record exists, it is a finding, not junk
            return None
        host = str(event.host or "")
        if not host or self.helpers.is_ip(host):
            return None
        if not self.helpers.tldextract(host).suffix:
            return VERDICT_FALSE, f"no public suffix: {host}"
        domain = self.helpers.tldextract(host).top_domain_under_public_suffix
        if domain in RESERVED_DOMAINS:
            return VERDICT_FALSE, f"reserved domain: {domain}"
        if event.type == "EMAIL_ADDRESS" and not self.scan.in_target(host):
            local = str(event.data).split("@", 1)[0].lower()
            if local in PLACEHOLDER_LOCALS or local == domain.split(".", 1)[0]:
                return VERDICT_FALSE, f"placeholder email: {event.data}"
        return None

    def check_relation(self, event):
        if "seed" in event.tags:
            return None
        if event.type in HOST_FINDING_TYPES:
            return self.check_host_relation(event)
        if event.type not in DNS_NAME_TYPES:
            return None
        module = event.module
        if getattr(module, "meta", {}).get("proves_relation"):
            return VERDICT_VERIFIED, f"relation proven by {module}"
        if event.scope_distance <= 0:
            return None
        if getattr(module, "_type", "") == "DNS":
            # a DNS record of a valid parent: the target uses this resource now
            return None
        return VERDICT_UNRELATED, f"out-of-scope name without proven relation ({module})"

    def check_host_relation(self, event):
        host = str(event.host or "")
        if event.scope_distance <= 0 or not host or self.helpers.is_ip(host):
            return None
        module = event.module
        if getattr(module, "_type", "") == "DNS" or getattr(module, "meta", {}).get("proves_relation"):
            return None
        parent = event.parent
        if parent is not None and parent is not event and str(getattr(parent, "host", "") or "") == host:
            # found on the name itself (speculate port of a name, http answer of a URL): the name was checked
            return None
        if self.scan.in_scope(host):
            return None
        return VERDICT_FALSE, f"{event.type} on an out-of-scope host without proven relation ({module})"

    def check_http(self, event):
        if event.type != "URL":
            return None
        status = next((t[len("status-") :] for t in event.tags if t.startswith("status-")), None)
        if status is None or not status.isdigit():
            return None
        status = int(status)
        if status in HTTP_GONE:
            return VERDICT_HISTORICAL, f"HTTP {status}: resource is gone"
        if 500 <= status or status == 400:
            # a server error / malformed request says nothing about whether the resource exists
            return None
        if self.promote_resolved == "in_scope" and self.scan.in_target(event.host):
            return VERDICT_VERIFIED, f"HTTP {status}: target resource answers now"
        return None

    def run_checks(self, event):
        """The strongest verdict among the checks: false > unrelated > historical > verified."""
        found = {}
        for check in self.checks:
            result = check(event)
            if result is not None:
                verdict, reason = result
                found.setdefault(verdict, reason)
        for verdict in (VERDICT_FALSE, VERDICT_UNRELATED, VERDICT_HISTORICAL, VERDICT_VERIFIED):
            if verdict in found:
                return verdict, found[verdict]
        return None, ""

    # --- status ---

    def state_of(self, event):
        """[status, freshness, reason, hidden, third-party]; if the event is not tagged yet
        (queue race), tags it by walking up the parent chain."""
        if event.type == "SCAN":
            return [VALID, VALID, "", False, False]
        state = self._state.get(event.uuid)
        if state is None:
            state = self.assign(event)
        return state

    def assign(self, event):
        own = self.source_freshness(event)
        parent = event.parent
        has_parent = parent is not None and parent is not event
        parent_state = self.state_of(parent) if has_parent else [VALID, VALID, "", False, False]
        parent_status, parent_own = parent_state[:2]

        verdict, reason = self.run_checks(event)
        if verdict == VERDICT_HISTORICAL:
            own = HISTORICAL if own is None else min(own, HISTORICAL)
        elif verdict == VERDICT_VERIFIED:
            own = VERIFIED

        if verdict in (VERDICT_FALSE, VERDICT_UNRELATED):
            status = FALSE
            own = FALSE
        elif own != VERIFIED and parent_status == FALSE:
            # descendant of a false finding (e.g. a speculate port guess for a hidden foreign name)
            status = FALSE
            reason = f"parent is false ({parent.type}: {parent.pretty_string})"
        elif own == VERIFIED:
            status = VALID
        else:
            status = parent_status if own is None else min(own, parent_status)

        # freshness relative to the parent in the output: omitted parents are skipped in the output,
        # so their own freshness is folded into the child
        rel = own
        if has_parent and parent.type != "SCAN" and parent._omit and parent_own not in (None, VERIFIED):
            if rel is None:
                rel = parent_own
            elif rel not in (VERIFIED, FALSE):
                rel = min(rel, parent_own)

        # third-party infrastructure: an out-of-scope name from a target DNS record (mail, DNS, cloud, monitoring -
        # the target uses it, but it is not its asset) and its out-of-scope descendants (IP, ASN, geolocation)
        # ... and an address that ipowner found to be the front of someone else's service (CNAME to a provider,
        # anti-DDoS/CDN network) together with what is found on it
        third_party = status != FALSE and (
            (event.type == "IP_ADDRESS" and IP_PROXY_TAG in event.tags)
            or (
                event.scope_distance > 0
                and ((event.type in DNS_NAME_TYPES and getattr(event.module, "_type", "") == "DNS") or parent_state[4])
            )
        )

        state = [status, rel, reason, verdict == VERDICT_UNRELATED, third_party]
        self._state[event.uuid] = state
        return state

    def tag(self, event, state):
        status, rel = state[:2]
        for name in STATUS_NAMES.values():
            event.remove_tag(f"validity-{name}")
        for level in OWN_NAMES.values():
            event.remove_tag(f"freshness-{level}")
        event.add_tag(f"validity-{STATUS_NAMES[status]}")
        event.add_tag(f"freshness-{OWN_NAMES[rel]}")
        if state[4]:
            event.add_tag(THIRD_PARTY_TAG)

    async def handle_event(self, event, **kwargs):
        if event.type == "SCAN":
            return True
        state = self.state_of(event)
        if state[0] == FALSE:
            hidden = state[3]
            self.log_false(event, state[2], hidden)
            if hidden:
                # candidate domain: not in the output, but relation analysers see the event
                event.internal = True
                # the affiliate tag forces the event into the output - a false finding must not have it
                event.remove_tag("affiliate")
            elif self.drop_false:
                return False, f"false finding: {state[2]}"
        self.tag(event, state)
        return True

    # --- false findings log ---

    def log_false(self, event, reason, hidden=False):
        self.false_count += 1
        if self._false_file is None:
            self._false_file = open(self.scan.home / "validity_false.jsonl", "a")
        record = {
            "type": event.type,
            "data": event.pretty_string,
            "module": str(event.module),
            "parent": getattr(event.parent, "id", None),
            "reason": reason,
            "hidden": hidden,
        }
        self._false_file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._false_file.flush()

    async def report(self):
        if self.false_count:
            self.info(f"{self.false_count:,} false findings dropped or hidden (see validity_false.jsonl)")

    async def cleanup(self):
        if self._false_file is not None:
            self._false_file.close()
