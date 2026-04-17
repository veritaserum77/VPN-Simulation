"""
Destination server node for the 4-laptop IPsec simulation.

It receives plain forwarded requests from the VPN gateway and returns a response.
This is where you demonstrate that the destination sees only VPN identity, not client IP.
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
from typing import Dict, Tuple

from ipsec_sim_common import DHPeer, SessionCrypto, b64d, b64e, recv_json, send_json
from ipsec_lab_config import DEST_SERVER_BIND_HOST, DEST_SERVER_PORT, DEST_SERVER_IP


def _preview(value: str, limit: int = 48) -> str:
    return value[:limit] + ("..." if len(value) > limit else "")


def _preview_bytes(value: bytes, limit: int = 24) -> str:
    return value[:limit].hex() + ("..." if len(value) > limit else "")


def _establish_secure_session(conn: socket.socket, vpn_server_ip: str, username: str) -> SessionCrypto:
    print(f"[DEST] Starting VPN↔DEST IKE handshake for user={username} from {vpn_server_ip}")

    server_dh = DHPeer()
    salt = b"vpn-dest-session-v1"
    print(f"[DEST] Generated DEST DH public key preview: {_preview_bytes(server_dh.public_bytes())}")

    send_json(
        conn,
        {
            "type": "vpn_hello_ack",
            "ok": True,
            "server_pub": b64e(server_dh.public_bytes()),
            "salt": b64e(salt),
        },
    )
    print(f"[DEST] Sent DEST DH public key and salt to VPN")

    key_msg = recv_json(conn)
    if not key_msg or key_msg.get("type") != "vpn_key":
        raise RuntimeError(f"missing vpn_key message: {key_msg}")

    vpn_pub = b64d(key_msg["client_pub"])
    print(f"[DEST] Received VPN DH public key preview: {_preview_bytes(vpn_pub)}")

    shared_secret = server_dh.shared_secret(vpn_pub)
    info = f"vpn-dest:{vpn_server_ip}:{username}".encode("utf-8")
    keys = SessionCrypto.build_keys(shared_secret, salt=salt, info=info)
    print(f"[DEST] Derived VPN↔DEST shared secret preview: {_preview_bytes(shared_secret)}")
    print(f"[DEST] Built VPN↔DEST SA keys (enc+hmac)")
    return SessionCrypto(keys=keys)

class DestinationServer:
    def __init__(self, bind_host: str, bind_port: int):
        self.bind_host = bind_host
        self.bind_port = bind_port

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_host, self.bind_port))
        sock.listen(20)
        print(f"[DEST] Listening on {self.bind_host}:{self.bind_port}")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            print(f"[DEST] TCP connected from VPN transport {addr[0]}:{addr[1]}")
            hello = recv_json(conn)
            if not hello or hello.get("type") != "vpn_hello":
                raise RuntimeError(f"missing vpn_hello message: {hello}")

            vpn_server_ip = hello.get("vpn_server_ip", addr[0])
            username = hello.get("username", "unknown")
            print(f"[DEST] VPN→DEST IKE hello: {hello}")

            crypto = _establish_secure_session(conn, vpn_server_ip=vpn_server_ip, username=username)

            secure_req_msg = recv_json(conn)
            if not secure_req_msg or secure_req_msg.get("type") != "vpn_secure_request":
                raise RuntimeError(f"missing vpn_secure_request message: {secure_req_msg}")

            secure_req = secure_req_msg["packet"]
            print(
                f"[DEST] Received encrypted request -> outer_header={secure_req.get('outer_header')} "
                f"seq={secure_req.get('seq')} hmac={str(secure_req.get('hmac', ''))[:32]}..."
            )
            print(f"[DEST] VPN→DEST ESP ciphertext preview: {secure_req['payload']['ciphertext'][:48]}...")

            decrypted_req = crypto.unwrap(secure_req)
            print(f"[DEST] Decrypted request payload: {decrypted_req}")

            data = decrypted_req.get("data", "")
            print(f"[DEST] Interpreting forwarded packet as plain payload from VPN server {vpn_server_ip}")

            response_inner: Dict[str, str] = {
                "type": "dest_response",
                "status": "ok",
                "source_identity": DEST_SERVER_IP,
                "data": f"ACK from destination at {time.strftime('%H:%M:%S')}: {data}",
            }
            print(f"[DEST] Generated response payload: {_preview(response_inner['data'])}")

            secure_resp = crypto.wrap(
                inner_packet=response_inner,
                mode="esp",
                seq=2,
                outer_src=f"dest:{DEST_SERVER_IP}",
                outer_dst=f"vpn:{vpn_server_ip}",
            )
            print(
                f"[DEST] Encrypted response -> outer_header={secure_resp['outer_header']} "
                f"seq={secure_resp['seq']} hmac={secure_resp['hmac'][:32]}..."
            )
            print(f"[DEST] DEST→VPN ESP ciphertext preview: {secure_resp['payload']['ciphertext'][:48]}...")
            send_json(conn, {"type": "vpn_secure_response", "packet": secure_resp})
            print(f"[DEST] Sent encrypted response back to VPN transport {addr[0]}:{addr[1]}")
        except Exception as exc:
            print(f"[DEST] handler error: {exc}")
        finally:
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="IPsec simulation destination server")
    parser.add_argument("--bind-host", default=DEST_SERVER_BIND_HOST)
    parser.add_argument("--bind-port", type=int, default=DEST_SERVER_PORT)
    args = parser.parse_args()

    DestinationServer(bind_host=args.bind_host, bind_port=args.bind_port).start()


if __name__ == "__main__":
    main()
