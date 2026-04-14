"""
client.py — Sends packets in VPN mode or direct mode.

VPN mode:   client → VPN server → destination
Direct mode: client → destination (no masking, no tunnel)

Called by the Flask API (api.py) — not run standalone.
"""
import socket, time, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from config import (SERVER_IP, VPN_PORT, DEST_PORT, BUFFER_SIZE,
                    CLIENT_VIP, VPN_SERVER_VIP, DEST_SERVER_VIP)
from crypto_utils import encrypt, decrypt, hex_preview
from tunnel import encapsulate, decapsulate, simulate_network
from packet import make_packet, encode, decode
import event_log, state

RESP_TIMEOUT = 8.0

def send(message: str, mode: str) -> dict:
    """
    Send *message* in the given mode and return a result dict.
    mode: "vpn" | "direct"
    """
    cfg = state.get_cfg()

    env        = make_packet(CLIENT_VIP,
                             DEST_SERVER_VIP, message)
    env_bytes  = encode(env)
    enc        = encrypt(env_bytes)
    pkt        = encapsulate(enc)

    # Choose destination port based on mode
    target_port = VPN_PORT if mode == "vpn" else DEST_PORT

    event_log.push("client_send",
        mode=mode, src=CLIENT_VIP, dst=DEST_SERVER_VIP,
        payload=message, enc_preview=hex_preview(enc),
        target_port=target_port,
        note=("→ VPN server (will mask IP)" if mode=="vpn"
              else "→ destination DIRECTLY (IP exposed)"))

    start = time.time()
    sim   = simulate_network(pkt, cfg["latency_ms"],
                              cfg["loss_rate"], cfg["bw_kbps"])

    if sim is None:
        state.record_drop(mode)
        state.record_sent(mode, len(env_bytes), len(pkt))
        event_log.push("client_drop", mode=mode, payload=message)
        return {"status":"dropped","mode":mode,"msg":message}

    state.record_sent(mode, len(env_bytes), len(pkt))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(RESP_TIMEOUT)
    sock.sendto(sim, (SERVER_IP, target_port))

    try:
        raw, _ = sock.recvfrom(BUFFER_SIZE)
    except socket.timeout:
        event_log.push("client_timeout", mode=mode)
        return {"status":"timeout","mode":mode,"msg":message}
    finally:
        sock.close()

    rtt_ms = (time.time() - start) * 1000
    _, resp_enc  = decapsulate(raw)
    resp_env     = decode(decrypt(resp_enc))

    state.record_recv(mode, rtt_ms)

    event_log.push("client_recv",
        mode=mode, src_seen=resp_env["src"],
        payload=resp_env["payload"],
        enc_preview=hex_preview(resp_enc),
        rtt_ms=round(rtt_ms,1),
        note=("Source = VPN server (client IP was hidden)"
              if mode=="vpn"
              else "Source = destination (client IP was VISIBLE)"))

    return {
        "status":   "ok",
        "mode":     mode,
        "msg":      message,
        "src_seen": resp_env["src"],
        "payload":  resp_env["payload"],
        "rtt_ms":   round(rtt_ms, 1),
        "enc_preview": hex_preview(resp_enc),
    }
