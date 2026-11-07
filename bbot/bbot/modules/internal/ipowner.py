import regex as re

from bbot.modules.base import BaseInterceptModule
from bbot.core.config.models import BaseModuleConfig, Field

# Ownership tags of an IP address (read by validity):
#   ip-owner-target - the target's own address: PTR into the target, or an AS named after the target
#   ip-proxy        - the front of someone else's service: the name reaches it through a CNAME to a foreign domain
#                     (SaaS, site builder, mail, storage) or the AS is an anti-DDoS / CDN proxy; shared by many
#                     customers, so the IP and what is found on it are third-party infrastructure
#   ip-hosting      - rented cloud / hosting capacity: may be the target's own VM, so the status is unchanged
OWN_TAG, PROXY_TAG, HOSTING_TAG = "ip-owner-target", "ip-proxy", "ip-hosting"

# AS name/description keywords (word match, case-insensitive). Anti-DDoS and CDN networks terminate traffic
# for many customers on the same addresses.
DEFAULT_PROXY_PROVIDERS = [
    "cloudflare", "akamai", "fastly", "incapsula", "imperva", "sucuri", "stackpath", "edgecast", "edgio",
    "limelight", "cdn77", "cdnvideo", "ngenix", "qrator", "curator", "hll", "ddos-guard", "ddos guard",
    "stormwall", "variti", "servicepipe", "edgecenter", "g-core", "gcore", "bunny", "cdn",
    # site builders / SaaS hosting: one address serves the sites of many customers
    "automattic", "wix", "squarespace", "shopify", "tilda", "netlify", "vercel", "webflow", "github",
]  # fmt: skip
# Cloud and hosting networks: the address is rented, it may be a dedicated VM of the target or shared hosting.
DEFAULT_HOSTING_PROVIDERS = [
    "amazon", "aws", "microsoft", "azure", "google cloud", "digitalocean", "hetzner", "ovh", "linode", "vultr",
    "leaseweb", "contabo", "scaleway", "oracle", "alibaba", "tencent", "ionos", "godaddy", "hostinger",
    "namecheap", "yandexcloud", "yandex.cloud", "selectel", "timeweb", "beget", "sprinthost", "reg.ru", "regru",
    "jino", "masterhost", "firstvds", "aeza", "vdsina", "ruvds", "sbercloud", "cloud.ru", "mchost", "hosting",
]  # fmt: skip
# The shortest brand label matched against AS names (shorter labels like "cp" match too much).
MIN_BRAND_LENGTH = 4


def _keyword_regex(words):
    words = [w.strip().lower() for w in words if w and w.strip()]
    if not words:
        return None
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(w) for w in words) + r")(?![a-z0-9])")


class ipowner(BaseInterceptModule):
    """
    Decides whose an IP address is, from what is known without contacting it:

      1. PTR into the target's domains                          -> own (ip-owner-target)
      2. the name resolves to it through a CNAME out of the target -> proxy: someone else's service (ip-proxy)
         ... or it is the address of an out-of-scope name (a provider's host the target points to) -> proxy
      3. the AS (asndb, the same lookup the asn module makes):
           name/description contains the target's brand          -> own
           anti-DDoS / CDN network                                -> proxy
           cloud / hosting network                                -> ip-hosting (status unchanged)
      4. cloudcheck tags (cdn-*)                                  -> proxy

    The provider behind a proxy/hosting verdict is kept in a tag `ip-provider-<slug>` (the CNAME domain or AS name).
    validity turns ip-proxy into the third-party tag, inherited by what is found on the address.
    Targets given as IPs/ranges are never classified: the user said they are the target's.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = []
    meta = {
        "description": "Classify IP addresses as the target's own, a third-party proxy/SaaS front or rented hosting",
        "created_date": "2026-11-06",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        asn_lookup: bool = Field(True, description="Look up the AS of each address (asndb, cached per subnet)")
        proxy_providers: list = Field(
            DEFAULT_PROXY_PROVIDERS, description="AS name keywords of anti-DDoS/CDN networks (third-party fronts)"
        )
        hosting_providers: list = Field(
            DEFAULT_HOSTING_PROVIDERS, description="AS name keywords of cloud/hosting networks (tagged ip-hosting)"
        )

    scope_distance_modifier = 2
    # after dnsresolve (1, PTR and CNAME records) and before validity (4)
    _priority = 3

    async def setup(self):
        self.asn_lookup = self.config.get("asn_lookup", True)
        # an unset option comes as None: fall back to the built-in lists
        self.proxy_re = _keyword_regex(self.config.get("proxy_providers") or DEFAULT_PROXY_PROVIDERS)
        self.hosting_re = _keyword_regex(self.config.get("hosting_providers") or DEFAULT_HOSTING_PROVIDERS)
        self._brands_for = None
        return True

    @property
    def brand_re(self):
        """Brand regex of the target; rebuilt when related_domains promotes a domain into the target."""
        hosts = len(self.scan.target.target.hosts)
        if self._brands_for != hosts:
            self._brands_for = hosts
            self._brand_re = _keyword_regex(self._target_brands())
        return self._brand_re

    def _target_brands(self):
        """Brand labels of the target's domains: target.example -> "target"."""
        brands = set()
        for host in self.scan.target.target.hosts:
            if not isinstance(host, str) or "/" in host or self.helpers.is_ip(host):
                continue
            label = self.helpers.tldextract(host).domain.lower()
            if len(label) >= MIN_BRAND_LENGTH:
                brands.add(label)
        return sorted(brands)

    def _slug(self, text):
        return re.sub(r"[^a-z0-9.]+", "-", str(text).lower()).strip("-")[:60]

    def _tag(self, event, tag, provider=None):
        event.add_tag(tag)
        if provider:
            event.add_tag(f"ip-provider-{self._slug(provider)}")

    async def handle_event(self, event, **kwargs):
        ip = event.host
        if "seed" in event.tags or self.scan.in_target(ip):
            return True

        # 1. PTR into the target: the address was delegated to the target
        for ptr in (event.dns_children or {}).get("PTR", []):
            if self.scan.in_target(ptr):
                self._tag(event, OWN_TAG)
                return True

        # 2. the parent name reaches this address through a CNAME out of the target
        parent = event.parent
        if parent is not None and parent is not event and parent.type == "DNS_NAME":
            children = parent.dns_children or {}
            addresses = {str(a) for t in ("A", "AAAA") for a in children.get(t, [])}
            foreign = [c for c in children.get("CNAME", []) if not self.scan.in_target(c)]
            if foreign and str(ip) in addresses:
                domain = self.helpers.tldextract(str(foreign[-1])).top_domain_under_public_suffix or foreign[-1]
                self._tag(event, PROXY_TAG, domain)
                return True
            if parent.scope_distance > 0 and not self.scan.in_target(parent.host) and str(ip) in addresses:
                # the address of someone else's name (lb.provider.example reached through the target's CNAME)
                domain = self.helpers.tldextract(str(parent.host)).top_domain_under_public_suffix or str(parent.host)
                self._tag(event, PROXY_TAG, domain)
                return True

        # 3. the AS
        if self.asn_lookup and getattr(ip, "is_global", False):
            info = await self.helpers.asn.ip_to_subnets(str(ip))
            if info.get("asn"):
                text = f"{info.get('name', '')} {info.get('description', '')}".lower()
                if self.brand_re is not None and self.brand_re.search(text):
                    self._tag(event, OWN_TAG)
                    return True
                if self.proxy_re is not None and self.proxy_re.search(text):
                    self._tag(event, PROXY_TAG, info.get("name") or f"as{info['asn']}")
                    return True
                if self.hosting_re is not None and self.hosting_re.search(text):
                    self._tag(event, HOSTING_TAG, info.get("name") or f"as{info['asn']}")
                    return True

        # 4. cloudcheck (when enabled) knows CDN ranges by provider
        cdn = next((t for t in event.tags if t.startswith("cdn-")), None)
        if cdn:
            self._tag(event, PROXY_TAG, cdn[len("cdn-") :])
        return True
