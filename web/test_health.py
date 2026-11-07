"""The health check must never kill the user's scan: `bbot/.venv/bin/pytest web/test_health.py -q`."""

import os
import subprocess
import sys
import threading

import health
import scans
import server

ROOT = health.ROOT

# What health.py does on its timeout: an in-process BBoT scan stopped with scan.async_stop() -> kill_children();
# the 0.01 s limit makes sure the scan is stopped (not finished) every time
STOPPED_SCAN = """
import asyncio
from bbot.scanner import Scanner

async def main():
    scan = Scanner("127.0.0.1", config={"cloudcheck": False, "deps": {"behavior": "disable"}})
    try:
        await asyncio.wait_for(scan.async_start_without_generator(), 0.01)
    except asyncio.TimeoutError:
        await scan.async_stop()

asyncio.run(main())
"""


def test_isolated_check_does_not_kill_server_children(tmp_path):
    script = tmp_path / "stopped_scan.py"
    script.write_text(STOPPED_SCAN)
    user_scan = subprocess.Popen(["sleep", "30"])  # a scan the server started
    try:
        env = dict(os.environ, BBOT_CONFIG_DIR=str(ROOT / "config"))
        health.run_isolated(env=env, script=script)
        assert user_scan.poll() is None, "the health check killed a child of the server"
    finally:
        user_scan.kill()
        user_scan.wait()


def test_health_loop_waits_for_running_scan(monkeypatch):
    busy = ["user_scan", "user_scan", None]
    calls = []
    monkeypatch.setattr(health, "is_stale", lambda: True)
    monkeypatch.setattr(scans, "running_job", lambda: busy.pop(0) if busy else None)
    monkeypatch.setattr(health, "run_all", lambda: calls.append("in-process"))

    def isolated(env=None, script=None):
        calls.append(("isolated", list(busy)))
        raise SystemExit  # stop the endless loop

    monkeypatch.setattr(health, "run_isolated", isolated)
    t = threading.Thread(target=lambda: _run_loop(), daemon=True)
    t.start()
    t.join(5)
    assert calls == [("isolated", [])], calls


def _run_loop():
    try:
        server.health_loop(idle_poll=0)
    except SystemExit:
        pass


assert sys.executable
