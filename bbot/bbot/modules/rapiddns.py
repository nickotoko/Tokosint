import regex as re

from bbot.modules.templates.subdomain_enum import subdomain_enum


class rapiddns(subdomain_enum):
    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "freshness": "historical",
        "description": "Query rapiddns.io for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
    }

    base_url = "https://rapiddns.io"
    # anonymous users only get the first page (100 records); the page still reports the real total
    total_regex = re.compile(r"Total:\s*<span[^>]*>\s*([\d,]+)")
    row_regex = re.compile(r'<th scope="row\s*">\d+</th>')

    async def request_url(self, query):
        url = f"{self.base_url}/subdomain/{self.helpers.quote(query)}?full=1#result"
        response = await self.api_request(url, timeout=self.http_timeout_infrastructure + 10)
        return response

    async def parse_results(self, r, query):
        text = getattr(r, "text", "")
        total = self.total_regex.search(text)
        rows = len(self.row_regex.findall(text))
        if total and int(total.group(1).replace(",", "")) > rows:
            self.warning(
                f'Results for "{query}" truncated: got {rows:,} of {total.group(1)} records (anonymous access is limited to the first page)'
            )
        return await self.scan.extract_in_scope_hostnames(text)
