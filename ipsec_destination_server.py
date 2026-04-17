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

from ipsec_sim_common import recv_json, send_json
from ipsec_lab_config import DEST_SERVER_BIND_HOST, DEST_SERVER_PORT


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
            req = recv_json(conn)
            if not req:
                return

            username = req.get("username", "unknown")
            data = req.get("data", "")
            vpn_server_ip = req.get("vpn_server_ip", addr[0])
            print(
                f"[DEST] request from VPN transport {addr[0]}:{addr[1]}"
                f" | user={username} | payload={data!r}"
            )

            response: Dict[str, str] = {
                "type": "dest_response",
                "status": "ok",
                "source_identity": vpn_server_ip,
                "data": f"ACK from destination at {time.strftime('%H:%M:%S')}: {data}",
            }
            send_json(conn, response)
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
