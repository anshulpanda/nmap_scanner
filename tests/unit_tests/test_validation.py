"""Host validation and normalization."""

import pytest

from app.validation import InvalidHostError, normalize_target


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("192.168.1.1", "192.168.1.1"),
        ("8.8.8.8", "8.8.8.8"),
        ("::1", "::1"),
        ("localhost", "localhost"),
        ("scanme.nmap.org", "scanme.nmap.org"),
        ("a-host.example.co.uk", "a-host.example.co.uk"),
        ("x", "x"),
    ],
)
def test_accepts_valid_targets(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("  localhost  ", "localhost"),          # surrounding whitespace
        ("Google.COM", "google.com"),            # DNS is case-insensitive
        ("google.com.", "google.com"),           # trailing dot / FQDN form
        ("  EXAMPLE.Org. ", "example.org"),      # all three at once
    ],
)
def test_normalizes_targets(raw, expected):
    assert normalize_target(raw) == expected


def test_ip_addresses_are_canonicalized():
    assert normalize_target("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_localhost_and_loopback_ip_stay_distinct():
    """Documented choice: they are different inputs, so they get separate history."""
    assert normalize_target("localhost") != normalize_target("127.0.0.1")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        ".",                    # all dots — empty after stripping the trailing one
        "not a host",           # space
        "foo_bar.com",          # underscore is not a legal DNS character
        "-leading-hyphen.com",
        "trailing-hyphen-.com",
        "host..com",            # empty label
        "999.999.999.999",      # looks like an IP, isn't one
        "12345",
        "host;rm -rf /",        # shell metacharacters
        "host && whoami",
        "192.168.1.1/24",       # CIDR range, not a single host
        "http://example.com",   # URL, not a host
        "a" * 254,
        "a" * 64 + ".com",      # label over 63 characters
    ],
)
def test_rejects_invalid_targets(raw):
    with pytest.raises(InvalidHostError):
        normalize_target(raw)


def test_error_message_names_the_offending_input():
    with pytest.raises(InvalidHostError, match="not-a-host!"):
        normalize_target("not-a-host!")


def test_rejects_non_string():
    with pytest.raises(InvalidHostError):
        normalize_target(None)
