"""
server.py — VPN gateway (port VPN_PORT).

For VPN mode:
  1. Decapsulate + decrypt → read CLIENT_VIP
  2. NAT rewrite src → VPN_SERVER_VIP  (IP masking)
  3. Re-encrypt + forward to destination
  4. Receive response → repack → return to client

For direct mode: client speaks directly to destination — server not involved.
"""
import socket, threading, time, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from config import (SERVER_IP, VPN_PORT, DEST_PORT, BUFFER_SIZE,
                    VPN_SERVER_VIP, CLIENT_VIP)
from crypto_utils import encrypt, decrypt, hex_preview
from tunnel import encapsulate, decapsulate, simulate_network
from packet import decode, encode, rewrite_src, make_packet
import event_log, state

RESP_TIMEOUT = 5.0

def _handle(raw, client_addr, sock):
    try:
        cfg = state.get_cfg()
        seq, enc = decapsulate(raw)

        event_log.push("vpn_recv",
            seq=seq, from_addr=str(client_addr),
            enc_preview=hex_preview(enc),
            raw_bytes=len(raw))

        plain = decrypt(enc)
        env   = decode(plain)

        event_log.push("vpn_decrypted",
            seq=seq, src_ip=env["src"],
            dst_ip=env["dst"], payload=env["payload"])

        # ── NAT rewrite — the core IP-masking step ────────────────────────
        original_src = env["src"]
        rewritten    = rewrite_src(env, VPN_SERVER_VIP)

        event_log.push("vpn_nat",
            before=original_src, after=VPN_SERVER_VIP,
            note="Client IP replaced with VPN server IP")

        # ── Forward to destination ─────────────────────────────────────────
        fwd_enc = encrypt(encode(rewritten))
        fwd_pkt = encapsulate(fwd_enc)
        sim     = simulate_network(fwd_pkt, cfg["latency_ms"],
                                   cfg["loss_rate"], cfg["bw_kbps"])
        if not sim:
            event_log.push("vpn_fwd_drop"); return

        event_log.push("vpn_forward",
            to_port=DEST_PORT, forwarding_as=VPN_SERVER_VIP,
            enc_preview=hex_preview(fwd_enc))

        ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ds.settimeout(RESP_TIMEOUT)
        ds.sendto(sim, (SERVER_IP, DEST_PORT))

        # ── Receive destination response ──────────────────────────────────
        try:
            raw_resp, _ = ds.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            event_log.push("vpn_dest_timeout"); ds.close(); return
        finally:
            ds.close()

        _, resp_enc  = decapsulate(raw_resp)
        resp_env     = decode(decrypt(resp_enc))

        event_log.push("vpn_dest_resp",
            src_from_dest=resp_env["src"], payload=resp_env["payload"],
            enc_preview=hex_preview(resp_enc))

        # ── Return to client ──────────────────────────────────────────────
        client_env = make_packet(VPN_SERVER_VIP, CLIENT_VIP,
                                 resp_env["payload"], "RESPONSE")
        client_enc = encrypt(encode(client_env))
        client_pkt = encapsulate(client_enc)
        sim2       = simulate_network(client_pkt, cfg["latency_ms"],
                                      cfg["loss_rate"], cfg["bw_kbps"])
        if sim2:
            sock.sendto(sim2, client_addr)
            event_log.push("vpn_client_resp",
                to=str(client_addr), src=VPN_SERVER_VIP, dst=CLIENT_VIP,
                enc_preview=hex_preview(client_enc))

    except Exception as e:
        event_log.push("vpn_error", detail=str(e))
        import traceback; traceback.print_exc()

def start():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, VPN_PORT))
    event_log.push("vpn_up", address=f"{SERVER_IP}:{VPN_PORT}",
                   identity=VPN_SERVER_VIP)
    while True:
        raw, addr = sock.recvfrom(BUFFER_SIZE)
        threading.Thread(target=_handle, args=(raw,addr,sock), daemon=True).start()

if __name__ == "__main__":
    start()
