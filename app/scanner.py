"""NMAP invocation and output parsing.

The only module in the app that touches an external process, which makes it
the only thing tests need to mock.
"""

import re
import subprocess

from app.config import NMAP_TIMEOUT, PORT_RANGE_END, PORT_RANGE_START

# Matches "22/tcp   open  ssh". The trailing (\s|$) matters: it stops
# "open|filtered" — nmap's "we can't tell" verdict — from counting as open.
_OPEN_PORT_LINE = re.compile(r"^(\d+)/tcp\s+open(?:\s|$)", re.MULTILINE)

_RESOLUTION_FAILED = "failed to resolve"


class ScanError(RuntimeError):
    """A scan could not be completed."""


class HostResolutionError(ScanError):
    """The target is syntactically fine but does not resolve to an address."""


def build_command(target: str) -> list[str]:
    """The nmap command line for a target.

    -Pn skips host discovery. Without it, a host that drops ping probes is
    reported as "down" and scanned for nothing — exactly the firewalled hosts
    this tool exists to inspect. -T4 keeps the scan from crawling.
    """
    return [
        "nmap",
        "-Pn",
        "-T4",
        "-p",
        f"{PORT_RANGE_START}-{PORT_RANGE_END}",
        target,
    ]


def parse_open_ports(nmap_output: str) -> list[int]:
    """Extract the open TCP ports from nmap's stdout, sorted ascending."""
    ports = {int(match) for match in _OPEN_PORT_LINE.findall(nmap_output)}
    return sorted(ports)


def scan_ports(target: str) -> list[int]:
    """Run nmap against `target` and return its open ports in 0-1000.

    `target` is passed as a list argument with shell=False, so it is never
    interpreted by a shell regardless of its contents.
    """
    try:
        completed = subprocess.run(
            build_command(target),
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScanError(
            "nmap is not installed or not on PATH. Install it and try again."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(
            f"Scan of '{target}' timed out after {NMAP_TIMEOUT} seconds."
        ) from exc

    output = f"{completed.stdout}\n{completed.stderr}"

    # nmap exits 0 even when it cannot resolve the target, so the exit code
    # alone is not enough to tell success from failure.
    if _RESOLUTION_FAILED in output.lower():
        raise HostResolutionError(
            f"'{target}' could not be resolved to an IP address."
        )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ScanError(f"nmap failed for '{target}': {detail}")

    return parse_open_ports(completed.stdout)
