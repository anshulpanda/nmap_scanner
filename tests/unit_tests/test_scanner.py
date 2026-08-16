"""nmap output parsing and command construction — pure functions, no subprocess.

The sample outputs below are real nmap 7.9 output, trimmed.
"""

from app.scanner import build_command, parse_open_ports

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

NO_OPEN_PORTS_OUTPUT = """\
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000025s latency).
Not shown: 1000 closed tcp ports (conn-refused)
PORT  STATE    SERVICE
0/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds
"""


def test_parses_open_ports():
    assert parse_open_ports(OPEN_PORTS_OUTPUT) == [22, 443, 8000]


def test_ignores_filtered_and_closed_ports():
    assert parse_open_ports(NO_OPEN_PORTS_OUTPUT) == []


def test_ignores_ambiguous_open_filtered_state():
    """"open|filtered" means nmap could not tell — that is not a confirmed open port."""
    output = "PORT    STATE         SERVICE\n53/tcp  open|filtered domain\n80/tcp  open  http\n"
    assert parse_open_ports(output) == [80]


def test_ignores_empty_output():
    assert parse_open_ports("") == []


def test_ports_are_sorted_and_deduplicated():
    output = "443/tcp open https\n22/tcp open ssh\n443/tcp open https\n"
    assert parse_open_ports(output) == [22, 443]


def test_command_scans_the_assigned_port_range():
    command = build_command("example.com")
    assert command[0] == "nmap"
    assert "0-1000" in command
    # The target is a separate list element — no shell, nothing to inject into.
    assert command[-1] == "example.com"
