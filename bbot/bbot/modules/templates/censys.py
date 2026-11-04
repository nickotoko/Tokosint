from bbot.modules.base import BaseModule


class censys(BaseModule):
    """
    Base template for Censys Platform API modules (https://docs.censys.com/reference/get-started).
    Authenticates with a Personal Access Token. Requests without an organization id run with the
    permissions of a Free account, which allows asset lookups (host, certificate) but not search.
    """

    base_url = "https://api.platform.censys.io/v3/global"
    _api_failure_abort_threshold = 3

    async def setup(self):
        api_keys = []
        for module_name in ("censys", "censys_dns", "censys_ip"):
            api_key = self.scan.config.get("modules", {}).get(module_name, {}).get("api_key", "")
            if isinstance(api_key, str):
                api_key = [api_key]
            for key in api_key:
                key = key.strip()
                if key and key not in api_keys:
                    api_keys.append(key)
        if not api_keys:
            return None, "No API key set"
        # Platform API has no free endpoint to validate a token without spending credits,
        # so a bad token is detected on the first lookup (see check_auth)
        self.api_key = api_keys
        return True

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = f"Bearer {self.api_key}"
        kwargs["headers"].setdefault("Accept", "application/json")
        return url, kwargs

    def check_auth(self, resp):
        """Sets error state on authentication / permission errors. Returns True if the response is usable."""
        status_code = getattr(resp, "status_code", 0)
        if status_code in (401, 403):
            try:
                detail = resp.json().get("detail", "")
            except Exception:
                detail = getattr(resp, "text", "")
            self.set_error_state(f"Censys API refused the request (HTTP {status_code}): {detail}")
            return False
        return True
