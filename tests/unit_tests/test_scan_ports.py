"""scan_ports: subprocess invocation and failure handling, nmap mocked.

Pure output-parsing and command-construction logic lives in
tests/unit_tests/test_scanner.py; this file only covers scan_ports's own
orchestration around a mocked subprocess boundary.
"""

import subprocess

import pytest

from app.scanner import HostResolutionError, ScanError, scan_ports

OPEN_PORTS_OUTPUT = """\
Starting Nmap 7.991 ( https://nmap.org ) at 2026-08-13 17:28 -0700
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000039s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 0.02 seconds
"""

UNRESOLVABLE_OUTPUT = """\
Starting Nmap 7.991 ( https://nmap.org ) at 2026-08-13 17:28 -0700
Error resolving not-a-real-host-asdf123: nodename nor servname provided, or not known
Failed to resolve "not-a-real-host-asdf123".
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.56 seconds
"""


def _fake_run(stdout="", stderr="", returncode=0, raises=None):
    def run(*args, **kwargs):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    return run


def test_scan_returns_open_ports(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=OPEN_PORTS_OUTPUT))
    assert scan_ports("localhost") == [22, 443, 8000]


def test_unresolvable_host_raises_even_though_nmap_exits_zero(monkeypatch):
    """nmap exits 0 on a resolution failure, so the exit code alone is a trap."""
    monkeypatch.setattr(
        subprocess, "run", _fake_run(stdout=UNRESOLVABLE_OUTPUT, returncode=0)
    )
    with pytest.raises(HostResolutionError, match="could not be resolved"):
        scan_ports("not-a-real-host-asdf123")


def test_missing_nmap_binary_gives_actionable_error(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(raises=FileNotFoundError()))
    with pytest.raises(ScanError, match="not installed"):
        scan_ports("localhost")


def test_timeout_is_reported_as_scan_error(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(raises=subprocess.TimeoutExpired(cmd="nmap", timeout=120)),
    )
    with pytest.raises(ScanError, match="timed out"):
        scan_ports("10.255.255.1")


def test_nonzero_exit_is_reported_as_scan_error(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", _fake_run(stderr="permission denied", returncode=1)
    )
    with pytest.raises(ScanError, match="permission denied"):
        scan_ports("localhost")
