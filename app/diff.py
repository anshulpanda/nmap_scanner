"""Port diffing — pure logic, no I/O.

Deliberately free of DB and network calls so it can be unit-tested with
plain lists.
"""

from collections.abc import Iterable


def compute_diff(
    old_ports: Iterable[int] | None, new_ports: Iterable[int]
) -> dict[str, list[int]]:
    """Return which ports opened and which closed since the previous scan.

    `old_ports` is None when a host has never been scanned before. That is not
    an error and not "everything was added" — there is simply no baseline to
    compare against, so both lists come back empty.
    """
    new_set = set(new_ports)
    if old_ports is None:
        return {"added": [], "removed": []}

    old_set = set(old_ports)
    return {
        "added": sorted(new_set - old_set),
        "removed": sorted(old_set - new_set),
    }
