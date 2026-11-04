"""Validate game state against canonical received history before every grant."""
from .seed import sha, grant_payload


def history_rows(items):
    return [[int(item.item), int(item.location), int(item.player)] for item in items]


def next_actions(manifest, state, received, server_checked=()):
    if not isinstance(state, dict) or state.get("t") != "state":
        raise ValueError("Expected game state")
    cursor = state.get("cursor")
    if type(cursor) is not int or cursor < 0:
        raise ValueError("Invalid game delivery cursor")
    if type(state.get("ready")) is not bool or type(state.get("victory")) is not bool:
        raise ValueError("Invalid ready/victory flags")
    checks = state.get("checks")
    valid = {row["location_id"] for row in manifest["placements"]}
    if not isinstance(checks, list) or any(type(x) is not int or x not in valid for x in checks):
        raise ValueError("Invalid game checks")
    rows = history_rows(received)
    if cursor > len(rows):
        return {"sync_required": True, "checks": [], "goal": False, "grant": None}
    if state.get("history_hash") != sha(rows[:cursor]):
        raise ValueError("Game receipt history does not match this AP session")
    grant = None
    if state["ready"] and cursor < len(rows):
        grant = {"t": "deliver", "expected_cursor": cursor, "expected_hash": sha(rows[:cursor]),
                 "next_hash": sha(rows[:cursor + 1]),
                 "grant": grant_payload(rows[cursor][0], cursor, [row[0] for row in rows])}
    return {"sync_required": False, "checks": sorted(set(checks) - set(server_checked)),
            "goal": state["victory"], "grant": grant}
