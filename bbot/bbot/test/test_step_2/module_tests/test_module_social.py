from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestSocial(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "excavate", "social"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": """
            <html>
                <a href="https://discord.gg/asdf"/><a href="https://github.com/blacklanternsecurity/bbot"/>
                <a href="https://hub.docker.com/r/blacklanternsecurity"/>
                <a href="https://hub.docker.com/r/blacklanternsecurity/bbot"/>
                <a href="https://hub.docker.com/r/blacklanternSECURITY/bbot"/>
                <a href="https://www.postman.com/blacklanternsecurity/bbot"/>
                <a href="https://linktr.ee/blacklanternsecurity"/>
            </html>
            """
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert 5 == len([e for e in events if e.type == "SOCIAL"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL" and e.data["platform"] == "discord" and e.data["profile_name"] == "asdf"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "docker"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "postman"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "linktree"
                and e.data["profile_name"] == "blacklanternsecurity"
                and e.data["url"] == "https://linktr.ee/blacklanternsecurity"
            ]
        )


class TestSocial_ModernPlatforms(TestSocial):
    """x.com, Telegram, VK and TikTok profiles are detected; share/invite links and tracking pixels
    (vk.com/rtrg, facebook.com/tr) are not mistaken for profiles."""

    module_name = "social"

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": """
            <html>
                <a href="https://x.com/blacklantern"/>
                <a href="https://x.com/intent/tweet?url=https://example.com"/>
                <a href="https://t.me/blacklanternsec"/>
                <a href="https://t.me/joinchat/AAAAAEkk"/>
                <a href="https://vk.com/blacklantern"/>
                <a href="https://vk.com/share.php?url=https://example.com"/>
                <img src="https://vk.com/rtrg?p=VK-RTRG-123"/>
                <img src="https://www.facebook.com/tr?id=123&ev=PageView"/>
                <a href="https://www.tiktok.com/@bls.ops"/>
            </html>
            """
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        found = {(e.data["platform"], e.data["profile_name"]) for e in events if e.type == "SOCIAL"}
        assert found == {
            ("twitter", "blacklantern"),
            ("telegram", "blacklanternsec"),
            ("vk", "blacklantern"),
            ("tiktok", "bls.ops"),
        }, found
