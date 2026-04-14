"""
tunnel.py — Encapsulation, decapsulation, WAN simulation
Packet: [VERSION(1)] [SEQ(4)] [LEN(4)] [PAYLOAD]
"""
import random, time, struct
from config import PROTOCOL_VERSION

_FMT  = '>BII'
_HLEN = struct.calcsize(_FMT)   # 9 bytes
_seq  = 0

def encapsulate(data: bytes) -> bytes:
    global _seq
    _seq += 1
    return struct.pack(_FMT, ord(PROTOCOL_VERSION), _seq, len(data)) + data

def decapsulate(packet: bytes) -> tuple:
    if len(packet) < _HLEN:
        raise ValueError("Packet too short")
    ver, seq, length = struct.unpack(_FMT, packet[:_HLEN])
    if ver != ord(PROTOCOL_VERSION):
        raise ValueError(f"Bad protocol version: {ver}")
    payload = packet[_HLEN:_HLEN + length]
    if len(payload) != length:
        raise ValueError("Truncated payload")
    return seq, payload

def simulate_network(packet: bytes, latency_ms: float, loss_rate: float,
                     bw_kbps: float) -> bytes | None:
    if random.random() < loss_rate:
        return None
    bps = (bw_kbps * 1000) / 8
    time.sleep(len(packet) / bps)
    time.sleep(latency_ms / 1000.0)
    return packet
