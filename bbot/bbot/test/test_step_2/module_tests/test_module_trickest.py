from .base import ModuleTestBase


class TestTrickest(ModuleTestBase):
    config_overrides = {"modules": {"trickest": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/dataset",
            match_headers={"Authorization": "Token deadbeef"},
            json={
                "results": [
                    {"id": "7d2143ef-406e-4443-8ac1-c6903df82bbb", "name": "DNS Records"},
                    {"id": "e00a3115-5dfa-4272-ab8d-3bc398452484", "name": "Subdomains"},
                ]
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/view?q=hostname%20~%20%22.blacklanternsecurity.com%22&dataset_id=e00a3115-5dfa-4272-ab8d-3bc398452484&limit=500&offset=0&select=hostname&orderby=hostname",
            match_headers={"Authorization": "Token deadbeef"},
            json={"results": [{"hostname": "asdf.blacklanternsecurity.com"}]},
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/view?q=hostname%20~%20%22.blacklanternsecurity.com%22&dataset_id=e00a3115-5dfa-4272-ab8d-3bc398452484&limit=500&offset=500&select=hostname&orderby=hostname",
            match_headers={"Authorization": "Token deadbeef"},
            json={"results": [{"hostname": "www.blacklanternsecurity.com"}]},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "www.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
