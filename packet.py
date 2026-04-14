"""
packet.py — JSON envelope format + NAT rewrite
Envelope: {src, dst, proto, payload}
"""
import json

def make_packet(src, dst, payload, proto="APP"):
    return {"src": src, "dst": dst, "proto": proto, "payload": payload}

def encode(env: dict) -> bytes:
    return json.dumps(env, separators=(",", ":")).encode()

def decode(raw: bytes) -> dict:
    return json.loads(raw.decode())

def rewrite_src(env: dict, new_src: str) -> dict:
    """NAT rewrite — replaces source IP (core VPN masking step)."""
    r = dict(env)
    r["src"] = new_src
    return r
