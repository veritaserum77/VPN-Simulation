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
from ipsec_lab_config import (
    DEST_SERVER_IP,
    DEST_SERVER_PORT,
    VPN_SERVER_IP,
    VPN_SERVER_BIND_HOST,
    VPN_SERVER_PORT,
    VPN_USERS,
)


def _preview(value: bytes | str, limit: int = 24) -> str:
    if isinstance(value, bytes):
        return value[:limit].hex() + ("..." if len(value) > limit else "")
    return value[:limit] + ("..." if len(value) > limit else "")


def _secure_forward_to_destination(
    dest_host: str,
    dest_port: int,
    vpn_server_ip: str,
    username: str,
    plaintext_request: Dict[str, str],
) -> Dict[str, str]:
    print(f"[VPN] Establishing encrypted VPN↔DEST tunnel to {dest_host}:{dest_port}")
    with socket.create_connection((dest_host, dest_port), timeout=5) as ds:
        print(f"[VPN] VPN→DEST TCP connected as {vpn_server_ip}")

        hello = {
            "type": "vpn_hello",
            "vpn_server_ip": vpn_server_ip,
            "username": username,
        }
        print(f"[VPN] VPN→DEST IKE phase 1 hello: {hello}")
        send_json(ds, hello)

        hello_ack = recv_json(ds)
        if not hello_ack or hello_ack.get("type") != "vpn_hello_ack":
            raise RuntimeError(f"destination handshake failed: {hello_ack}")

        dest_pub = b64d(hello_ack["server_pub"])
        salt = b64d(hello_ack["salt"])
        print(f"[VPN] Received DEST DH public key preview: {_preview(dest_pub)}")
        print(f"[VPN] Received DEST salt: {salt.hex()}")

        vpn_dh = DHPeer()
        vpn_pub = vpn_dh.public_bytes()
        print(f"[VPN] Generated VPN DH public key for DEST preview: {_preview(vpn_pub)}")
        send_json(ds, {"type": "vpn_key", "client_pub": b64e(vpn_pub)})

        shared_secret = vpn_dh.shared_secret(dest_pub)
        info = f"vpn-dest:{vpn_server_ip}:{username}".encode("utf-8")
        keys = SessionCrypto.build_keys(shared_secret, salt=salt, info=info)
        secure_session = SessionCrypto(keys=keys)
        print(f"[VPN] Derived VPN↔DEST shared secret preview: {_preview(shared_secret)}")
        print(f"[VPN] Built VPN↔DEST SA keys (enc+hmac)")

        secure_req = secure_session.wrap(
            inner_packet=plaintext_request,
            mode="esp",
            seq=1,
            outer_src=f"vpn:{vpn_server_ip}",
            outer_dst=f"dest:{dest_host}",
        )
        print(
            f"[VPN] Encrypted request to DEST -> outer_header={secure_req['outer_header']} "
            f"seq={secure_req['seq']} hmac={secure_req['hmac'][:32]}..."
        )
        print(f"[VPN] VPN→DEST ESP ciphertext preview: {secure_req['payload']['ciphertext'][:48]}...")
        send_json(ds, {"type": "vpn_secure_request", "packet": secure_req})

        secure_resp_msg = recv_json(ds)
        if not secure_resp_msg or secure_resp_msg.get("type") != "vpn_secure_response":
            raise RuntimeError(f"missing encrypted destination response: {secure_resp_msg}")

        secure_resp = secure_resp_msg["packet"]
        print(
            f"[VPN] Received encrypted response from DEST -> outer_header={secure_resp.get('outer_header')} "
            f"seq={secure_resp.get('seq')} hmac={str(secure_resp.get('hmac', ''))[:32]}..."
        )
        print(f"[VPN] DEST response ESP ciphertext preview: {secure_resp['payload']['ciphertext'][:48]}...")

        decrypted_resp = secure_session.unwrap(secure_resp)
        print(f"[VPN] Decrypted response from DEST: {decrypted_resp}")
        return decrypted_resp


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
        print(f"[VPN] Advertised VPN identity is {VPN_SERVER_IP}")
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
            print(f"[VPN] SA active for {session.username}: AH/ESP protection enabled")

            while True:
                packet = recv_json(conn)
                if not packet:
                    print(f"[VPN] Client disconnected user={session.username}")
                    return

                if packet.get("type") != "vpn_data":
                    send_json(conn, {"type": "error", "message": "expected vpn_data packet"})
                    continue

                print(
                    f"[VPN] Received tunnel packet -> outer_header={packet.get('outer_header')} "
                    f"mode={packet.get('mode')} seq={packet.get('seq')} hmac={str(packet.get('hmac', ''))[:32]}..."
                )
                if packet.get("mode") == "esp":
                    print(f"[VPN] Encrypted ESP ciphertext preview: {packet['payload']['ciphertext'][:48]}...")
                else:
                    print(f"[VPN] AH plaintext preview: {packet['payload']['plaintext'][:48]}...")

                seq = int(packet.get("seq", 0))
                if seq <= session.last_seq:
                    send_json(conn, {"type": "drop", "reason": "replay_or_out_of_order", "seq": seq})
                    continue
                session.last_seq = seq

                print(f"[VPN] Verifying integrity and decrypting packet seq={seq}")
                try:
                    inner = session.crypto.unwrap(packet)
                except Exception as exc:
                    send_json(conn, {"type": "drop", "reason": f"integrity_or_decrypt_failed: {exc}"})
                    continue

                print(f"[VPN] Decrypted inner packet: {inner}")

                dest_req = {
                    "type": "dest_request",
                    "username": session.username,
                    "vpn_server_ip": VPN_SERVER_IP,
                    "data": inner.get("data", ""),
                    "ts": now_ts(),
                }
                print(f"[VPN] Forwarding plaintext to destination {self.dest_host}:{self.dest_port} as {VPN_SERVER_IP}")
                dest_resp = _secure_forward_to_destination(
                    dest_host=self.dest_host,
                    dest_port=self.dest_port,
                    vpn_server_ip=VPN_SERVER_IP,
                    username=session.username,
                    plaintext_request=dest_req,
                )
                print(f"[VPN] Destination replied with: {dest_resp}")

                outer_src = f"vpn:{VPN_SERVER_IP}"
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
                print(
                    f"[VPN] Re-encapsulated response -> outer_header={response_packet['outer_header']} "
                    f"mode={response_packet['mode']} seq={response_packet['seq']} hmac={response_packet['hmac'][:32]}..."
                )
                if session.mode == "esp":
                    print(f"[VPN] Response ESP ciphertext preview: {response_packet['payload']['ciphertext'][:48]}...")
                else:
                    print(f"[VPN] Response AH plaintext preview: {response_packet['payload']['plaintext'][:48]}...")
                send_json(conn, response_packet)
                print(f"[VPN] Sent secured response back to client {session.username}")

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
        print(f"[VPN] IKE auth accepted for {username}; generating server DH key pair")
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
        print(f"[VPN] Received client DH public key preview: {_preview(client_pub)}")
        shared_secret = server_dh.shared_secret(client_pub)
        info = f"ipsec-sim:{username}:{mode}".encode("utf-8")
        keys = SessionCrypto.build_keys(shared_secret, salt=salt, info=info)
        session = ClientSession(username=username, mode=mode, crypto=SessionCrypto(keys=keys))
        print(f"[VPN] Derived shared secret preview: {_preview(shared_secret)}")
        print(f"[VPN] Created SA for {username} with mode={mode.upper()} and HMAC integrity")

        send_json(conn, {"type": "ike_done", "ok": True})
        return session

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
    parser.add_argument("--bind-host", default=VPN_SERVER_BIND_HOST)
    parser.add_argument("--bind-port", type=int, default=VPN_SERVER_PORT)
    parser.add_argument("--dest-host", default=DEST_SERVER_IP)
    parser.add_argument("--dest-port", type=int, default=DEST_SERVER_PORT)
    parser.add_argument(
        "--users",
        default=VPN_USERS,
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
