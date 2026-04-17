"""
Shared protocol, crypto, and socket helpers for the 4-node IPsec simulation.

This module implements:
- IKE-like authentication + ephemeral X25519 key exchange
- Session key derivation with HKDF-SHA256
- AH mode: integrity only (HMAC-SHA256)
- ESP mode: AES-256-GCM + HMAC-SHA256
- Simple JSON-over-TCP framing (newline-delimited)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def now_ts() -> float:
    return time.time()


def recv_json(sock: socket.socket) -> Optional[Dict[str, Any]]:
    """Read one newline-delimited JSON object."""
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)
        if b"\n" in chunk:
            line, _, _ = bytes(buf).partition(b"\n")
            if not line:
                return None
            return json.loads(line.decode("utf-8"))


def send_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    wire = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(wire)


@dataclass
class SessionKeys:
    enc_key: bytes
    hmac_key: bytes


class SessionCrypto:
    """Wrap/unwrap packets in AH or ESP mode using per-session keys."""

    def __init__(self, keys: SessionKeys):
        self.keys = keys
        self._aes = AESGCM(keys.enc_key)

    @staticmethod
    def build_keys(shared_secret: bytes, salt: bytes, info: bytes) -> SessionKeys:
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=info,
        ).derive(shared_secret)
        return SessionKeys(enc_key=key_material[:32], hmac_key=key_material[32:])

    def _sign(self, seq: int, mode: str, body: bytes) -> bytes:
        msg = seq.to_bytes(8, "big") + mode.encode("ascii") + body
        return hmac.new(self.keys.hmac_key, msg, hashlib.sha256).digest()

    def _verify(self, seq: int, mode: str, body: bytes, mac: bytes) -> bool:
        expected = self._sign(seq, mode, body)
        return hmac.compare_digest(expected, mac)

    def wrap(self, inner_packet: Dict[str, Any], mode: str, seq: int, outer_src: str, outer_dst: str) -> Dict[str, Any]:
        if mode not in ("ah", "esp"):
            raise ValueError("mode must be 'ah' or 'esp'")

        plain = json.dumps(inner_packet, separators=(",", ":")).encode("utf-8")

        if mode == "esp":
            nonce = time.time_ns().to_bytes(12, "big", signed=False)[-12:]
            ciphertext = self._aes.encrypt(nonce, plain, None)
            body = nonce + ciphertext
            mac = self._sign(seq, mode, body)
            payload = {
                "nonce": b64e(nonce),
                "ciphertext": b64e(ciphertext),
            }
        else:
            body = plain
            mac = self._sign(seq, mode, body)
            payload = {
                "plaintext": b64e(plain),
            }

        return {
            "type": "vpn_data",
            "outer_header": {
                "src": outer_src,
                "dst": outer_dst,
            },
            "mode": mode,
            "seq": seq,
            "payload": payload,
            "hmac": b64e(mac),
        }

    def unwrap(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        mode = packet.get("mode")
        seq = int(packet.get("seq"))
        payload = packet.get("payload", {})
        recv_mac = b64d(packet["hmac"])

        if mode == "esp":
            nonce = b64d(payload["nonce"])
            ciphertext = b64d(payload["ciphertext"])
            body = nonce + ciphertext
            if not self._verify(seq, mode, body, recv_mac):
                raise ValueError("HMAC verification failed")
            plain = self._aes.decrypt(nonce, ciphertext, None)
        elif mode == "ah":
            plain = b64d(payload["plaintext"])
            if not self._verify(seq, mode, plain, recv_mac):
                raise ValueError("HMAC verification failed")
        else:
            raise ValueError("unknown mode")

        return json.loads(plain.decode("utf-8"))


class DHPeer:
    """Ephemeral X25519 peer for the key exchange stage."""

    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def shared_secret(self, peer_public_bytes: bytes) -> bytes:
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self.private_key.exchange(peer_public)
