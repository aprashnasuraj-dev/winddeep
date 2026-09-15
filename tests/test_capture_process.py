"""Lifecycle tests for the isolated packaged mitmproxy runtime."""

from __future__ import annotations

import subprocess

import pytest

import app.capture.process as process_module
from app.capture.process import CaptureProcess, CaptureProcessError


def _capture(tmp_path) -> CaptureProcess:
    root = tmp_path / "app-root"
    (root / "app" / "capture").mkdir(parents=True)
    (root / "app" / "capture" / "standalone.py").write_text("# addon", encoding="utf-8")
    scripts = root / "runtime" / "capture-python" / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "mitmdump.exe").write_bytes(b"MZ")
    return CaptureProcess(root, state_dir=tmp_path / "state", capture_token="secret", port=18080, app_port=17331)


def test_capture_command_environment_and_status(tmp_path) -> None:
    capture = _capture(tmp_path)
    command = capture.command()
    assert command[0].endswith("mitmdump.exe")
    assert command[-2] == "-s"
    assert command[-1].endswith("standalone.py")
    env = capture.environment()
    assert env["WINDEEP_CAPTURE_TOKEN"] == "secret"
    assert env["WINDEEP_RESOLVE_ENDPOINT"].endswith(":17331/api/capture/resolve")
    assert env["WINDEEP_EVENT_ENDPOINT"].endswith(":17331/api/capture/events")
    assert str(capture.app_root) in env["PYTHONPATH"]
    status = capture.status()
    assert status == {"running": False, "host": "127.0.0.1", "port": 18080, "runtime_present": True, "pid": None}


def test_capture_requires_packaged_runtime_and_addon(tmp_path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    capture = CaptureProcess(root, state_dir=tmp_path / "state", capture_token="secret")
    with pytest.raises(CaptureProcessError, match="not installed"):
        capture.executable()
    assert capture.status()["runtime_present"] is False
    scripts = root / "runtime" / "capture-python" / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "mitmdump").write_text("stub", encoding="utf-8")
    with pytest.raises(CaptureProcessError, match="addon missing"):
        capture.command()


def test_capture_start_success_is_idempotent_and_stop_terminates(tmp_path, monkeypatch) -> None:
    capture = _capture(tmp_path)

    class FakeProcess:
        pid = 4321
        returncode = None

        def __init__(self):
            self.terminated = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.terminated = True

    fake = FakeProcess()
    calls = {"popen": 0, "port": 0}

    def fake_popen(*args, **kwargs):
        calls["popen"] += 1
        assert kwargs["shell"] if "shell" in kwargs else True
        return fake

    def port_open():
        calls["port"] += 1
        return calls["port"] >= 2

    monkeypatch.setattr(process_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(capture, "_port_open", port_open)
    capture.start(timeout=1)
    assert capture.is_running() is True
    assert capture.status()["pid"] == 4321
    capture.start(timeout=1)
    assert calls["popen"] == 1
    capture.stop()
    assert capture.process is None
    assert fake.terminated is True
    capture.stop()


def test_capture_start_rejects_busy_port(tmp_path, monkeypatch) -> None:
    capture = _capture(tmp_path)
    monkeypatch.setattr(capture, "_port_open", lambda: True)
    with pytest.raises(CaptureProcessError, match="already in use"):
        capture.start()


def test_capture_start_detects_early_exit(tmp_path, monkeypatch) -> None:
    capture = _capture(tmp_path)

    class DeadProcess:
        returncode = 7
        pid = 1

        def poll(self):
            return 7

    monkeypatch.setattr(capture, "_port_open", lambda: False)
    monkeypatch.setattr(process_module.subprocess, "Popen", lambda *args, **kwargs: DeadProcess())
    with pytest.raises(CaptureProcessError, match="code 7"):
        capture.start(timeout=1)
    assert capture.process is None


def test_capture_start_timeout_stops_process(tmp_path, monkeypatch) -> None:
    capture = _capture(tmp_path)

    class LiveProcess:
        returncode = None
        pid = 1
        terminated = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.terminated = True

    fake = LiveProcess()
    clock = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(capture, "_port_open", lambda: False)
    monkeypatch.setattr(process_module.subprocess, "Popen", lambda *args, **kwargs: fake)
    monkeypatch.setattr(process_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(process_module.time, "sleep", lambda _seconds: None)
    with pytest.raises(CaptureProcessError, match="did not open"):
        capture.start(timeout=1)
    assert fake.terminated is True


def test_capture_stop_kills_after_wait_timeout(tmp_path) -> None:
    capture = _capture(tmp_path)

    class SlowProcess:
        pid = 2
        killed = False
        waits = 0

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("mitmdump", timeout)
            return 0

        def kill(self):
            self.killed = True

    fake = SlowProcess()
    capture.process = fake  # type: ignore[assignment]
    capture.stop(timeout=0.1)
    assert fake.killed is True
    assert capture.process is None


def test_capture_context_manager_calls_start_and_stop(tmp_path, monkeypatch) -> None:
    capture = _capture(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(capture, "start", lambda **_kwargs: calls.append("start"))
    monkeypatch.setattr(capture, "stop", lambda **_kwargs: calls.append("stop"))
    with capture as entered:
        assert entered is capture
    assert calls == ["start", "stop"]
