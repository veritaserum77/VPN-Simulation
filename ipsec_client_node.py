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
from ipsec_lab_config import VPN_SERVER_IP, VPN_SERVER_PORT


def _preview(data: bytes, limit: int = 24) -> str:
    return data[:limit].hex() + ("..." if len(data) > limit else "")


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
        if self.server_host.upper() in ("VPN_IP", "DEST_IP"):
            print(
                f"[CLIENT:{self.client_id}] Invalid --server-host '{self.server_host}'. "
                "Use the actual VPN server LAN IP, e.g. 192.168.1.20"
            )
            return 1

        try:
            sock = socket.create_connection((self.server_host, self.server_port), timeout=8)
        except socket.gaierror:
            print(
                f"[CLIENT:{self.client_id}] Could not resolve host '{self.server_host}'. "
                "Pass a real IP/hostname for --server-host."
            )
            return 1
        except TimeoutError:
            print(
                f"[CLIENT:{self.client_id}] Connection to {self.server_host}:{self.server_port} timed out."
            )
            return 1
        except ConnectionRefusedError:
            print(
                f"[CLIENT:{self.client_id}] Connection refused by {self.server_host}:{self.server_port}. "
                "Check if VPN server is running and firewall allows port 7000."
            )
            return 1
        except OSError as exc:
            print(f"[CLIENT:{self.client_id}] Network error: {exc}")
            return 1

        with sock:
            print(f"[CLIENT:{self.client_id}] TCP connected to VPN server {self.server_host}:{self.server_port}")

            auth_msg = {
                "type": "auth",
                "username": self.username,
                "password": self.password,
                "mode": self.mode,
            }
            print(f"[CLIENT:{self.client_id}] IKE phase 1 auth -> {self.username} / {'*' * len(self.password)}")
            send_json(sock, auth_msg)

            auth_result = recv_json(sock)
            if not auth_result or not auth_result.get("ok"):
                reason = "no response" if not auth_result else auth_result.get("reason", "unknown")
                print(f"[CLIENT:{self.client_id}] Authentication failed: {reason}")
                return 1

            server_pub = b64d(auth_result["server_pub"])
            salt = b64d(auth_result["salt"])
            print(f"[CLIENT:{self.client_id}] Received VPN DH public key preview: {_preview(server_pub)}")
            print(f"[CLIENT:{self.client_id}] Received session salt: {salt.hex()}")

            dh = DHPeer()
            client_pub = dh.public_bytes()
            print(f"[CLIENT:{self.client_id}] Generated client DH public key preview: {_preview(client_pub)}")
            send_json(sock, {"type": "client_key", "client_pub": b64e(client_pub)})

            shared_secret = dh.shared_secret(server_pub)
            info = f"ipsec-sim:{self.username}:{self.mode}".encode("utf-8")
            keys = SessionCrypto.build_keys(shared_secret, salt=salt, info=info)
            crypto = SessionCrypto(keys=keys)
            print(f"[CLIENT:{self.client_id}] Derived shared secret preview: {_preview(shared_secret)}")
            print(f"[CLIENT:{self.client_id}] Built SA keys for mode={self.mode.upper()} (enc+hmac)")

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
            print(f"[CLIENT:{self.client_id}] Inner packet before tunneling: {inner}")
            tunnel_packet = crypto.wrap(
                inner_packet=inner,
                mode=self.mode,
                seq=self.seq,
                outer_src=f"client:{self.client_id}",
                outer_dst="vpn_gateway",
            )
            print(
                f"[CLIENT:{self.client_id}] Encapsulated packet -> outer_header={tunnel_packet['outer_header']} "
                f"mode={tunnel_packet['mode']} seq={tunnel_packet['seq']} hmac={tunnel_packet['hmac'][:32]}..."
            )
            if self.mode == "esp":
                payload = tunnel_packet["payload"]
                print(f"[CLIENT:{self.client_id}] ESP ciphertext preview: {payload['ciphertext'][:48]}...")
            else:
                print(f"[CLIENT:{self.client_id}] AH plaintext preview: {tunnel_packet['payload']['plaintext'][:48]}...")
            send_json(sock, tunnel_packet)
            print(f"[CLIENT:{self.client_id}] Sent tunneled packet to VPN server")

            response = recv_json(sock)
            if not response:
                print(f"[CLIENT:{self.client_id}] No response from VPN server")
                return 1

            if response.get("type") in ("drop", "error"):
                print(f"[CLIENT:{self.client_id}] Packet dropped/rejected: {response}")
                return 1

            print(
                f"[CLIENT:{self.client_id}] Received response tunnel -> outer_header={response.get('outer_header')} "
                f"mode={response.get('mode')} seq={response.get('seq')} hmac={str(response.get('hmac', ''))[:32]}..."
            )
            if response.get("mode") == "esp":
                print(f"[CLIENT:{self.client_id}] Response ESP ciphertext preview: {response['payload']['ciphertext'][:48]}...")
            else:
                print(f"[CLIENT:{self.client_id}] Response AH plaintext preview: {response['payload']['plaintext'][:48]}...")

            try:
                inner_resp: Dict[str, str] = crypto.unwrap(response)
            except Exception as exc:
                print(f"[CLIENT:{self.client_id}] Failed to verify/decrypt response: {exc}")
                return 1

            print(f"[CLIENT:{self.client_id}] Decrypted response inner packet: {inner_resp}")

            print(f"[CLIENT:{self.client_id}] Destination response: {inner_resp.get('data', '')}")
            print(
                f"[CLIENT:{self.client_id}] Destination saw source identity as: "
                f"{inner_resp.get('dest_seen_source', 'unknown')}"
            )
            return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="IPsec simulation client node")
    parser.add_argument("--server-host", default=VPN_SERVER_IP)
    parser.add_argument("--server-port", type=int, default=VPN_SERVER_PORT)
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
