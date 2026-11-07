from bbot.core.config.models import BaseModuleConfig, Field


class SharedHostingConfig(BaseModuleConfig):
    max_reverse_names: int = Field(
        10, description="Ignore reverse lookups of IPs that more than this many names point to (shared hosting / CDN)"
    )
    own_network_max_reverse_names: int = Field(
        100,
        description="Same limit for IPs in the target's own network (network owner named like the target domain)",
    )


class shared_hosting_filter:
    """
    Mixin for modules that look up "names on an IP" (reverse DNS / reverse IP).

    On shared hosting and CDNs those names belong to unrelated sites, so results are only used when:
    - the IP isn't tagged as CDN / cloud (cloudcheck), and
    - the number of names is small, or larger but the network owner is named like the target
      organisation (evilcorp.com -> "evilcorp" in "EVILCORP LLC"), i.e. the target's own network.

    Modules call `remember_org_name()` for in-scope names and `reverse_names_allowed()` before using results.
    """

    shared_hosting_tags = ("cdn-", "cloud-")

    def _org_names(self):
        if not hasattr(self, "_shared_hosting_org_names"):
            self._shared_hosting_org_names = set()
        return self._shared_hosting_org_names

    def remember_org_name(self, hostname):
        _, domain = self.helpers.split_domain(hostname)
        org_name = domain.split(".")[0].lower()
        # very short names ("t", "ab") would match unrelated network descriptions
        if len(org_name) >= 4:
            self._org_names().add(org_name)

    # ipowner: the address is the front of someone else's service (CNAME to a provider, anti-DDoS/CDN network)
    shared_hosting_exact_tags = ("ip-proxy",)

    def is_shared_infrastructure(self, event):
        return any(t.startswith(self.shared_hosting_tags) or t in self.shared_hosting_exact_tags for t in event.tags)

    def own_network_owner(self, *owner_descriptions):
        """Returns the first owner description that names the target organisation, else ''."""
        for owner in owner_descriptions:
            owner = str(owner or "")
            if any(org_name in owner.lower() for org_name in self._org_names()):
                return owner
        return ""

    async def reverse_names_allowed(self, ip, num_names, get_owner):
        """
        Whether `num_names` names found on `ip` may be used.
        `get_owner` is an async callable returning owner descriptions of the IP's network (only called when needed).
        """
        max_names = self.config.get("max_reverse_names", 10)
        if num_names <= max_names:
            return True
        owner = self.own_network_owner(*(await get_owner()))
        if owner:
            max_names = self.config.get("own_network_max_reverse_names", 100)
            self.verbose(f"{ip} is in the target's own network ({owner}), allowing up to {max_names} names")
        if num_names > max_names:
            self.verbose(f"Ignoring {num_names:,} names on {ip} (> {max_names}), likely shared hosting")
            return False
        return True
