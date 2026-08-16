"""Diff logic — pure functions, no DB, no mocking."""

from app.diff import compute_diff


def test_port_added():
    assert compute_diff([22, 443], [22, 443, 8080]) == {"added": [8080], "removed": []}


def test_port_removed():
    assert compute_diff([22, 443, 8080], [22, 443]) == {"added": [], "removed": [8080]}


def test_no_change():
    assert compute_diff([22, 443], [22, 443]) == {"added": [], "removed": []}


def test_added_and_removed_together():
    assert compute_diff([22, 80], [22, 443]) == {"added": [443], "removed": [80]}


def test_first_ever_scan_is_not_all_additions():
    """No previous scan means no baseline — not "everything was added"."""
    assert compute_diff(None, [22, 443]) == {"added": [], "removed": []}


def test_previous_scan_with_no_open_ports_differs_from_no_previous_scan():
    assert compute_diff([], [22]) == {"added": [22], "removed": []}


def test_all_ports_closed():
    assert compute_diff([22, 443], []) == {"added": [], "removed": [22, 443]}


def test_results_are_sorted_regardless_of_input_order():
    assert compute_diff([443, 22], [22, 8080, 443, 80]) == {
        "added": [80, 8080],
        "removed": [],
    }


def test_duplicates_are_collapsed():
    assert compute_diff([22, 22], [22, 443, 443]) == {"added": [443], "removed": []}


def test_inputs_are_not_mutated():
    old, new = [22, 443], [22]
    compute_diff(old, new)
    assert old == [22, 443] and new == [22]
