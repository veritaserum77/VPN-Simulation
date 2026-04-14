"""
event_log.py — Thread-safe in-memory event bus for the dashboard.

Every significant action (encrypt, NAT rewrite, deliver, etc.) is
appended here.  The Flask API reads this list and streams it to the
browser via SSE so the dashboard updates in real time.
"""
import threading, time

_lock   = threading.Lock()
_events = []          # list of dicts
_MAX    = 500         # keep last N events


def push(kind: str, **fields):
    """Append one event.  kind is a short tag like 'encrypt', 'nat', 'drop'."""
    entry = {"id": int(time.time() * 1000), "kind": kind,
             "ts": round(time.time(), 3), **fields}
    with _lock:
        _events.append(entry)
        if len(_events) > _MAX:
            _events.pop(0)


def since(after_id: int) -> list:
    """Return events newer than after_id."""
    with _lock:
        return [e for e in _events if e["id"] > after_id]


def all_events() -> list:
    with _lock:
        return list(_events)


def clear():
    with _lock:
        _events.clear()
