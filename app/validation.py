"""Host validation and normalization — pure syntax checks, no network I/O.

Whether a syntactically valid hostname actually *resolves* is nmap's problem
(see scanner.HostResolutionError). Keeping this module I/O-free makes it
trivially unit-testable and keeps a DNS outage from looking like bad input.
"""

import ipaddress
import re

# A DNS label: 1-63 chars of alphanumerics and hyphens, no leading/trailing hyphen.
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

MAX_HOSTNAME_LENGTH = 253


class InvalidHostError(ValueError):
    """Raised when a target is not a plausible IP address or hostname."""


def normalize_target(target: str) -> str:
    """Validate a target and return its canonical form.

    Normalization rules (documented in the README):
      - surrounding whitespace stripped
      - hostnames lowercased, since DNS is case-insensitive
      - a single trailing dot (fully-qualified form) stripped
      - IPv4/IPv6 addresses collapsed to their canonical text form
      - `localhost` and `127.0.0.1` stay DISTINCT — they are different inputs,
        and resolving them together would need DNS lookups this layer avoids.

    Raises InvalidHostError with a human-readable message when the target is
    not usable. Callers translate that into a 400 before nmap ever runs.
    """
    if target is None or not isinstance(target, str):
        raise InvalidHostError("Target is required.")

    candidate = target.strip()
    if not candidate:
        raise InvalidHostError("Target is required.")

    # An IP address is unambiguous — accept it in its canonical form.
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    hostname = candidate.lower().rstrip(".")
    if not hostname:
        raise InvalidHostError(f"'{target}' is not a valid IP address or hostname.")

    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise InvalidHostError(
            f"Hostname is too long (max {MAX_HOSTNAME_LENGTH} characters)."
        )

    # A bare number that isn't a valid IP (e.g. "999.999.999.999" or "12345")
    # is a mistyped address, not a hostname — say so explicitly.
    if re.fullmatch(r"[0-9.]+", hostname):
        raise InvalidHostError(f"'{target}' is not a valid IP address.")

    labels = hostname.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise InvalidHostError(f"'{target}' is not a valid IP address or hostname.")

    return hostname
