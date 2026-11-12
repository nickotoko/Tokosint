"""The scan pool: bounded concurrency with a queue and per-scan isolated BBoT home.

The real bin/osint is never run: subprocess.Popen is replaced with a fake process whose exit is controlled by the
test, so the pool's scheduling (slots, queue, dispatch on finish, cancel) is exercised deterministically.
"""

import threading
import time

import pytest
import quota

import scans


class FakeProc:
    """Stands in for the BBoT subprocess: stays running until finish() is called."""

    def __init__(self, cmd):
        self.cmd = cmd
        self.pid = 1
        self._rc = None
        self._done = threading.Event()

    def poll(self):
        return self._rc

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise TimeoutError
        return self._rc

    def finish(self, rc=0):
        self._rc = rc
        self._done.set()


@pytest.fixture
def pool(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(scans, "HOMES_DIR", tmp_path / "scans" / ".homes")
    monkeypatch.setattr(scans, "OSINT", tmp_path / "bin" / "osint")
    monkeypatch.setattr(scans, "MAX_CONCURRENT", 2)
    monkeypatch.setattr(scans, "_jobs", {})
    monkeypatch.setattr(scans, "_lock", threading.Lock())
    monkeypatch.setattr(quota, "snapshot", lambda *a, **k: {})
    monkeypatch.setattr(quota, "save_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(scans, "_scan_home", lambda name: tmp_path / "home" / name)

    procs = {}

    def fake_popen(cmd, **kwargs):
        p = FakeProc(cmd)
        # the scan name is the argument right after "-n"
        name = cmd[cmd.index("-n") + 1]
        procs[name] = p
        return p

    monkeypatch.setattr(scans.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(scans.os, "killpg", lambda pid, sig: None)
    return procs


def _wait(cond, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def start(name, known=frozenset()):
    return scans.start_scan(
        {"targets": ["example.com"], "name": name, "modules": []}, known
    )


def test_runs_up_to_limit_then_queues(pool):
    start("a")
    start("b")
    assert _wait(lambda: "a" in pool and "b" in pool)
    assert scans.job_info("a")["running"] and scans.job_info("b")["running"]

    j3 = start("c")
    assert j3["state"] == "queued" and j3["queued"]
    assert j3["queue_position"] == 1
    assert "c" not in pool  # not launched while the pool is full
    assert scans.pool_status() == {"max_concurrent": 2, "running": 2, "queued": 1}

    pool["a"].finish(0)  # a slot frees -> c starts
    assert _wait(lambda: "c" in pool)
    assert scans.job_info("c")["running"]
    assert scans.job_info("a")["state"] == "done"


def test_cancel_queued(pool):
    start("a")
    start("b")
    start("c")
    assert _wait(lambda: "a" in pool and "b" in pool)
    info = scans.stop_scan("c")
    assert info["state"] == "cancelled"
    pool["a"].finish(0)
    # c was cancelled, so the freed slot stays idle (nothing else queued)
    assert not _wait(lambda: "c" in pool, timeout=0.3)


def test_stop_running_sigints(pool):
    killed = []
    pool  # noqa: B018
    scans.os.killpg = lambda pid, sig: killed.append((pid, sig))
    start("a")
    assert _wait(lambda: "a" in pool)
    scans.stop_scan("a")
    assert killed and scans.job_info("a")["stopping"]
    pool["a"].finish(0)


def test_duplicate_name_rejected(pool):
    start("a")
    with pytest.raises(scans.ScanError) as e:
        start("a")
    assert e.value.code == 409


def test_on_finish_called_and_slot_freed(pool):
    done = []
    scans.start_scan(
        {"targets": ["example.com"], "name": "a", "modules": []},
        frozenset(),
        on_finish=lambda name, rc: done.append((name, rc)),
    )
    assert _wait(lambda: "a" in pool)
    pool["a"].finish(7)
    assert _wait(lambda: done == [("a", 7)])
    assert scans.has_capacity()
