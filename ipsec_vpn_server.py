"""
VPN gateway node for 4-laptop IPsec-style simulation.

Phases implemented:
1) Authentication (username/password)
2) Diffie-Hellman key exchange (X25519)
3) Secure channel (AH or ESP)
4) Tunnel packet verification/decryption
5) Forwarding to destination server and returning encrypted response
"""

from __future__ import annotations

import argparse
import socket
import threading
from dataclasses import dataclass
from typing import Dict, Tuple

from ipsec_sim_common import (
    DHPeer,
    SessionCrypto,
    b64d,
    b64e,
    now_ts,
    recv_json,
    send_json,
)


@dataclass
class ClientSession:
    username: str
    mode: str
    crypto: SessionCrypto
    last_seq: int = 0


class VPNServer:
    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        dest_host: str,
        dest_port: int,
        credentials: Dict[str, str],
    ):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.credentials = credentials

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_host, self.bind_port))
        sock.listen(20)
        print(f"[VPN] Listening on {self.bind_host}:{self.bind_port}")
        print(f"[VPN] Forward destination is {self.dest_host}:{self.dest_port}")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        print(f"[VPN] New client connection from {addr[0]}:{addr[1]}")
        try:
            session = self._authenticate_and_negotiate(conn)
            if session is None:
                return

            print(f"[VPN] Session established for user={session.username}, mode={session.mode}")

            while True:
                packet = recv_json(conn)
                if not packet:
                    print(f"[VPN] Client disconnected user={session.username}")
                    return

                if packet.get("type") != "vpn_data":
                    send_json(conn, {"type": "error", "message": "expected vpn_data packet"})
                    continue

                seq = int(packet.get("seq", 0))
                if seq <= session.last_seq:
                    send_json(conn, {"type": "drop", "reason": "replay_or_out_of_order", "seq": seq})
                    continue
                session.last_seq = seq

                try:
                    inner = session.crypto.unwrap(packet)
                except Exception as exc:
                    send_json(conn, {"type": "drop", "reason": f"integrity_or_decrypt_failed: {exc}"})
                    continue

                dest_req = {
                    "type": "dest_request",
                    "username": session.username,
                    "data": inner.get("data", ""),
                    "ts": now_ts(),
                }
                dest_resp = self._forward_to_destination(dest_req)

                outer_src = f"vpn:{self.bind_host}"
                outer_dst = packet.get("outer_header", {}).get("src", "client")
                response_inner = {
                    "type": "response",
                    "from": "destination",
                    "data": dest_resp.get("data", ""),
                    "dest_seen_source": dest_resp.get("source_identity", "unknown"),
                    "status": dest_resp.get("status", "ok"),
                }
                response_packet = session.crypto.wrap(
                    inner_packet=response_inner,
                    mode=session.mode,
                    seq=seq,
                    outer_src=outer_src,
                    outer_dst=outer_dst,
                )
                send_json(conn, response_packet)

        except Exception as exc:
            print(f"[VPN] Error with client {addr}: {exc}")
        finally:
            conn.close()

    def _authenticate_and_negotiate(self, conn: socket.socket) -> ClientSession | None:
        auth = recv_json(conn)
        if not auth or auth.get("type") != "auth":
            send_json(conn, {"type": "auth_result", "ok": False, "reason": "invalid_auth_message"})
            return None

        username = auth.get("username", "")
        password = auth.get("password", "")
        mode = auth.get("mode", "esp").lower()

        if mode not in ("ah", "esp"):
            send_json(conn, {"type": "auth_result", "ok": False, "reason": "mode must be ah or esp"})
            return None

        expected = self.credentials.get(username)
        if expected is None or expected != password:
            print(f"[VPN] Auth failed for username={username!r}")
            send_json(conn, {"type": "auth_result", "ok": False, "reason": "unauthorized"})
            return None

        server_dh = DHPeer()
        salt = b"vpn-sim-ike-salt-v1"
        send_json(
            conn,
            {
                "type": "auth_result",
                "ok": True,
                "server_pub": b64e(server_dh.public_bytes()),
                "salt": b64e(salt),
                "note": "send client_key to finish DH",
            },
        )

        key_msg = recv_json(conn)
        if not key_msg or key_msg.get("type") != "client_key":
            send_json(conn, {"type": "error", "message": "missing client_key"})
            return None

        client_pub = b64d(key_msg["client_pub"])
        shared_secret = server_dh.shared_secret(client_pub)
        info = f"ipsec-sim:{username}:{mode}".encode("utf-8")
        keys = SessionCrypto.build_keys(shared_secret, salt=salt, info=info)
        session = ClientSession(username=username, mode=mode, crypto=SessionCrypto(keys=keys))

        send_json(conn, {"type": "ike_done", "ok": True})
        return session

    def _forward_to_destination(self, payload: Dict[str, str]) -> Dict[str, str]:
        with socket.create_connection((self.dest_host, self.dest_port), timeout=5) as ds:
            send_json(ds, payload)
            resp = recv_json(ds)
            if not resp:
                return {"status": "error", "data": "No response from destination", "source_identity": "vpn_gateway"}
            return resp


def parse_credentials(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError("credentials must be username:password pairs")
        user, pwd = item.split(":", 1)
        out[user.strip()] = pwd.strip()
    if not out:
        raise ValueError("at least one credential pair is required")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="IPsec simulation VPN gateway")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--bind-port", type=int, default=7000)
    parser.add_argument("--dest-host", required=True)
    parser.add_argument("--dest-port", type=int, default=7100)
    parser.add_argument(
        "--users",
        default="client1:secure123",
        help="Comma-separated credentials, e.g. client1:secure123,client2:abc",
    )
    args = parser.parse_args()

    users = parse_credentials(args.users)
    VPNServer(
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        dest_host=args.dest_host,
        dest_port=args.dest_port,
        credentials=users,
    ).start()


if __name__ == "__main__":
    main()
