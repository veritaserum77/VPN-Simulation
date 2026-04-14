"""
destination.py — Simulated public internet server (port DEST_PORT).

Only ever receives traffic from the VPN server.
Logs what source IP it sees — proves CLIENT_VIP is hidden.
"""
import socket, threading, time, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from config import SERVER_IP, DEST_PORT, BUFFER_SIZE, DEST_SERVER_VIP
from crypto_utils import encrypt, decrypt, hex_preview
from tunnel import encapsulate, decapsulate, simulate_network
from packet import decode, make_packet, encode
import event_log, state

_RESP_TIMEOUT = 4.0

def _handle(raw, vpn_addr, sock):
    try:
        cfg = state.get_cfg()
        seq, enc = decapsulate(raw)
        plain    = decrypt(enc)
        env      = decode(plain)

        event_log.push("dest_recv",
            seq=seq, src_seen=env["src"], dst=env["dst"],
            payload=env["payload"], enc_preview=hex_preview(enc),
            note="CLIENT IP IS HIDDEN — dest only sees VPN server IP")

        # Build response
        resp_env   = make_packet(DEST_SERVER_VIP, env["src"],
                                 f"200 OK · echo: {env['payload']}", "RESPONSE")
        resp_enc   = encrypt(encode(resp_env))
        resp_pkt   = encapsulate(resp_enc)
        sim        = simulate_network(resp_pkt, cfg["latency_ms"],
                                      cfg["loss_rate"], cfg["bw_kbps"])
        if sim:
            sock.sendto(sim, vpn_addr)
            event_log.push("dest_send", to=str(vpn_addr),
                           enc_preview=hex_preview(resp_enc),
                           payload=resp_env["payload"])
        else:
            event_log.push("dest_drop", reason="WAN loss on return")
    except Exception as e:
        event_log.push("dest_error", detail=str(e))

def start():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, DEST_PORT))
    event_log.push("dest_up", address=f"{SERVER_IP}:{DEST_PORT}",
                   identity=DEST_SERVER_VIP)
    while True:
        raw, addr = sock.recvfrom(BUFFER_SIZE)
        threading.Thread(target=_handle, args=(raw,addr,sock), daemon=True).start()

if __name__ == "__main__":
    start()
