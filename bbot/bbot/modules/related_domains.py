import asyncio
import re

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class related_domains(BaseModule):
    """
    Validate relations between the scan target and out-of-scope domains seen during the scan, and promote
    strongly related ones (same organisation) into the target so they are searched like the target itself.

    Every out-of-scope registrable domain that shows up next to the target (hostnames, emails) becomes a candidate.
    Evidence is collected from public DNS records:

    - backref (candidate's own records point at the target): NS / MX host in scope, SPF include in scope,
      DMARC reports sent to an in-scope address. A provider never points its records at its customer,
      so at least one backref is required for promotion.
    - forward (target's records point at the candidate): SPF include / NS / MX of an in-scope domain.
      Weak on its own: mail and DNS providers (google.com, cloudns.net) look exactly like this.
    - neighbor / email: a hostname or an email address of the candidate was found next to the target.

    Candidates are re-evaluated whenever the scope grows, so relations chain (target.com -> corp-mail.com -> corp-tips.com).
    """

    watched_events = ["DNS_NAME", "EMAIL_ADDRESS"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "passive", "affiliates"]
    meta = {
        "freshness": "current",
        # продвигает домен в скоуп по DNS-доказательствам: связь с целью доказана (validity → verified)
        "proves_relation": True,
        "description": "Validate relations of out-of-scope domains to the target via DNS and promote related ones into scope",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        min_score: int = Field(4, description="Minimum evidence score to promote a domain into the target")
        max_promoted: int = Field(20, description="Maximum number of domains to promote per scan")

    # candidates are one hop away from in-scope events
    scope_distance_modifier = 1

    # evidence kind -> (weight, is backref)
    evidence_weights = {
        "ns": (3, True),
        "mx": (3, True),
        "spf": (3, True),
        "dmarc": (3, True),
        "forward-spf": (1, False),
        "forward-ns": (1, False),
        "forward-mx": (1, False),
        "neighbor": (1, False),
        "email": (1, False),
    }
    evidence_desc = {
        "ns": "its NS is in scope",
        "mx": "its MX is in scope",
        "spf": "its SPF includes an in-scope domain",
        "dmarc": "its DMARC reports go to an in-scope address",
        "forward-spf": "in-scope SPF includes it",
        "forward-ns": "in-scope NS is hosted on it",
        "forward-mx": "in-scope MX is hosted on it",
        "neighbor": "its hostnames were found next to the target",
        "email": "its email addresses were found next to the target",
    }

    spf_regex = re.compile(r"(?:include:|redirect=)([^\s\"]+)", re.I)
    dmarc_regex = re.compile(r"(?:rua|ruf)=([^;\"]+)", re.I)

    async def setup(self):
        self.min_score = self.config.get("min_score", 4)
        self.max_promoted = self.config.get("max_promoted", 20)
        # candidate domain -> {"records": {...}, "evidence": set(), "parent": event}
        self.candidates = {}
        # in-scope root domain -> records
        self.roots = {}
        # promoted domain -> evidence
        self.promoted = {}
        return True

    async def handle_event(self, event):
        host = event.host if event.type == "DNS_NAME" else str(event.data).rsplit("@", 1)[-1]
        if not host or self.helpers.is_ip(host):
            return
        _, domain = self.helpers.split_domain(str(host))
        if not domain:
            return

        if self.scan.in_target(domain):
            if domain not in self.roots:
                self.roots[domain] = await self.get_records(domain)
                await self.evaluate_all()
            return
        if self.scan.blacklisted(domain) or domain in self.promoted:
            return

        candidate = self.candidates.get(domain)
        if candidate is None:
            candidate = {"records": await self.get_records(domain), "evidence": set(), "parent": event}
            self.candidates[domain] = candidate
        candidate["evidence"].add("email" if event.type == "EMAIL_ADDRESS" else "neighbor")
        await self.evaluate_all()

    async def get_records(self, domain):
        ns, mx, txt, dmarc = await asyncio.gather(
            self.helpers.dns.resolve(domain, "NS"),
            self.helpers.dns.resolve(domain, "MX"),
            self.helpers.dns.resolve(domain, "TXT"),
            self.helpers.dns.resolve(f"_dmarc.{domain}", "TXT"),
        )
        return {
            "ns": {self._rdata_host(r) for r in ns},
            "mx": {self._rdata_host(r) for r in mx},
            "spf": {h.lower().rstrip(".") for r in txt if "v=spf1" in r.lower() for h in self.spf_regex.findall(r)},
            "dmarc": {
                addr.rsplit("@", 1)[-1].split("!")[0].strip().lower().rstrip(".")
                for r in dmarc
                for uris in self.dmarc_regex.findall(r)
                for addr in uris.split(",")
                if "@" in addr
            },
        }

    @staticmethod
    def _rdata_host(rdata):
        # "10 mx.example.com." -> "mx.example.com"
        return str(rdata).split()[-1].strip('"').lower().rstrip(".")

    def get_evidence(self, domain, candidate):
        evidence = set(candidate["evidence"])
        records = candidate["records"]
        for kind in ("ns", "mx", "spf", "dmarc"):
            if any(self.scan.in_target(h) for h in records[kind] if h):
                evidence.add(kind)
        for root_records in self.roots.values():
            for kind in ("spf", "ns", "mx"):
                if any(h == domain or h.endswith(f".{domain}") for h in root_records[kind]):
                    evidence.add(f"forward-{kind}")
        return evidence

    def score(self, evidence):
        score = sum(self.evidence_weights[e][0] for e in evidence)
        has_backref = any(self.evidence_weights[e][1] for e in evidence)
        return score, has_backref

    async def evaluate_all(self):
        """Promote every candidate that qualifies; repeat while the scope keeps growing (relations chain)."""
        promoted_any = True
        while promoted_any and len(self.promoted) < self.max_promoted:
            promoted_any = False
            for domain, candidate in list(self.candidates.items()):
                evidence = self.get_evidence(domain, candidate)
                score, has_backref = self.score(evidence)
                if has_backref and score >= self.min_score:
                    await self.promote(domain, candidate, evidence, score)
                    promoted_any = True
                    if len(self.promoted) >= self.max_promoted:
                        self.warning(f"Reached max_promoted ({self.max_promoted}), not promoting more domains")
                        break

    async def promote(self, domain, candidate, evidence, score):
        self.candidates.pop(domain, None)
        self.promoted[domain] = (score, evidence)
        self.roots[domain] = candidate["records"]
        # extend the target first, so the scan treats the domain (and everything under it) as in-scope
        self.scan.target.target.add(domain)
        reasons = "; ".join(self.evidence_desc[e] for e in sorted(evidence))
        self.info(f"Promoting {domain} into the target (score {score}): {reasons}")
        parent = candidate["parent"]
        # the candidate may have been first seen as the bare domain itself; an event can't be its own parent
        if parent.type == "DNS_NAME" and parent.data == domain:
            parent = parent.get_parent()
        await self.emit_event(
            domain,
            "DNS_NAME",
            parent=parent,
            tags=["related-org"] + [f"relation-{e}" for e in sorted(evidence)],
            context=f"{{module}} validated relation to the target and promoted {{event.type}}: {{event.pretty_string}} into scope (score {score}: {reasons})",
        )

    async def report(self):
        rows = []
        for domain, (score, evidence) in sorted(self.promoted.items(), key=lambda x: -x[1][0]):
            rows.append([domain, "promoted", str(score), ", ".join(sorted(evidence))])
        # near misses: some DNS evidence, but not enough
        for domain, candidate in self.candidates.items():
            evidence = self.get_evidence(domain, candidate)
            if evidence - {"neighbor", "email"}:
                score, _ = self.score(evidence)
                rows.append([domain, "candidate", str(score), ", ".join(sorted(evidence))])
        if rows:
            self.log_table(rows, ["Domain", "Status", "Score", "Evidence"], table_name="related-domains")
