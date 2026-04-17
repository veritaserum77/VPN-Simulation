"""
Client node for the 4-laptop IPsec simulation.

Can be launched as:
- Authorized client (correct username/password)
- Unauthorized client (wrong credentials) to demonstrate rejection
"""

from __future__ import annotations

import argparse
import socket
import sys
from typing import Dict

from ipsec_sim_common import DHPeer, SessionCrypto, b64d, b64e, recv_json, send_json


class VPNClient:
    def __init__(
        self,
        server_host: str,
        server_port: int,
        username: str,
        password: str,
        mode: str,
        client_id: str,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.password = password
        self.mode = mode
        self.client_id = client_id
        self.seq = 1

    def run(self, message: str) -> int:
        with socket.create_connection((self.server_host, self.server_port), timeout=8) as sock:
            auth_msg = {
                "type": "auth",
                "username": self.username,
                "password": self.password,
                "mode": self.mode,
            }
            send_json(sock, auth_msg)

            auth_result = recv_json(sock)
            if not auth_result or not auth_result.get("ok"):
                reason = "no response" if not auth_result else auth_result.get("reason", "unknown")
                print(f"[CLIENT:{self.client_id}] Authentication failed: {reason}")
                return 1

            server_pub = b64d(auth_result["server_pub"])
            salt = b64d(auth_result["salt"])

            dh = DHPeer()
            send_json(sock, {"type": "client_key", "client_pub": b64e(dh.public_bytes())})

            shared_secret = dh.shared_secret(server_pub)
            info = f"ipsec-sim:{self.username}:{self.mode}".encode("utf-8")
            keys = SessionCrypto.build_keys(shared_secret, salt=salt, info=info)
            crypto = SessionCrypto(keys=keys)

            done = recv_json(sock)
            if not done or not done.get("ok"):
                print(f"[CLIENT:{self.client_id}] IKE completion failed")
                return 1

            print(f"[CLIENT:{self.client_id}] Auth + DH successful, secure mode={self.mode.upper()}")

            inner = {
                "type": "request",
                "dest": "destination_server",
                "data": message,
            }
            tunnel_packet = crypto.wrap(
                inner_packet=inner,
                mode=self.mode,
                seq=self.seq,
                outer_src=f"client:{self.client_id}",
                outer_dst="vpn_gateway",
            )
            send_json(sock, tunnel_packet)

            response = recv_json(sock)
            if not response:
                print(f"[CLIENT:{self.client_id}] No response from VPN server")
                return 1

            if response.get("type") in ("drop", "error"):
                print(f"[CLIENT:{self.client_id}] Packet dropped/rejected: {response}")
                return 1

            try:
                inner_resp: Dict[str, str] = crypto.unwrap(response)
            except Exception as exc:
                print(f"[CLIENT:{self.client_id}] Failed to verify/decrypt response: {exc}")
                return 1

            print(f"[CLIENT:{self.client_id}] Destination response: {inner_resp.get('data', '')}")
            print(
                f"[CLIENT:{self.client_id}] Destination saw source identity as: "
                f"{inner_resp.get('dest_seen_source', 'unknown')}"
            )
            return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="IPsec simulation client node")
    parser.add_argument("--server-host", required=True)
    parser.add_argument("--server-port", type=int, default=7000)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--mode", choices=["ah", "esp"], default="esp")
    parser.add_argument("--client-id", default="laptop-client")
    parser.add_argument("--message", default="Hello from client")
    args = parser.parse_args()

    code = VPNClient(
        server_host=args.server_host,
        server_port=args.server_port,
        username=args.username,
        password=args.password,
        mode=args.mode,
        client_id=args.client_id,
    ).run(message=args.message)
    sys.exit(code)


if __name__ == "__main__":
    main()
