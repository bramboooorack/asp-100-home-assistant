"""Syncleo/Ballu UDP protocol — encrypted session crypto + framing.

Reverse-engineered from the Hommyn app and verified on hardware (fw 1.38).
See PROTOCOL.md §2/§3 for the full derivation. Same logic as tools/asp100_proto.py,
bundled into the integration so it is self-contained.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# on-wire frame type bytes (oh/a.java)
TYPE_ACK = 0x00
TYPE_CMD = 0x01
TYPE_AUX = 0x02
TYPE_NAK = 0xFF

CMD_HANDSHAKE = 0x00
CMD_TIMESYNC = 0x80


def _rotl(b: bytes, n: int) -> bytes:
    n &= 0x0F
    return b[n:] + b[:n]


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _pkcs7_pad(data: bytes) -> bytes:
    p = 16 - (len(data) % 16)
    return data + bytes([p]) * p


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    p = data[-1]
    return data[:-p] if 0 < p <= 16 else data


class Session:
    """One ECDH session: derives AES keys and builds/parses frames.

    The three byte-reversals (rh.a.m) are essential — device pubkey in, shared
    secret out, and our own pubkey out — or decryption silently fails.
    """

    def __init__(self, device_pub: bytes) -> None:
        self._priv = X25519PrivateKey.generate()
        # l8/a.java:818 -> app sends its OWN pubkey byte-reversed
        self.app_pub = self._priv.public_key().public_bytes_raw()[::-1]
        # nh/d.java:765 -> SHA256( rev( X25519( rev(devicePub), appPriv ) ) )
        shared = self._priv.exchange(X25519PublicKey.from_public_bytes(device_pub[::-1]))
        digest = hashlib.sha256(shared[::-1]).digest()
        self._h0 = digest[0:16]   # recv key base / send iv base
        self._h1 = digest[16:32]  # send key base / recv iv base

    # ---- app -> device ----
    def build_handshake(self, token16: bytes) -> bytes:
        """Handshake frame: zero token = pairing, real token = authenticate."""
        assert len(token16) == 16
        enc_token = _aes_cbc_encrypt(self._h1, self._h0, token16)  # NoPadding, 16B
        inner = bytes([CMD_HANDSHAKE]) + self.app_pub + enc_token  # 1+32+16
        return self._frame(seq=0, ftype=TYPE_CMD, payload=inner)

    def build_cmd(self, cmd: int, payload: bytes, seq: int) -> bytes:
        plain = bytes([seq, cmd]) + payload
        key = _rotl(self._h1, seq & 0x0F)
        iv = _rotl(self._h0, (seq >> 4) & 0x0F)
        enc = _aes_cbc_encrypt(key, iv, _pkcs7_pad(plain))
        return self._frame(seq=seq, ftype=TYPE_CMD, payload=enc)

    def build_ack(self, seq: int) -> bytes:
        key = _rotl(self._h1, seq & 0x0F)
        iv = _rotl(self._h0, (seq >> 4) & 0x0F)
        enc = _aes_cbc_encrypt(key, iv, _pkcs7_pad(bytes([seq])))
        return self._frame(seq=seq, ftype=TYPE_ACK, payload=enc)

    @staticmethod
    def _frame(seq: int, ftype: int, payload: bytes) -> bytes:
        return struct.pack("<BBH", seq & 0xFF, ftype, len(payload)) + payload

    # ---- device -> app ----
    def parse_frame(self, data: bytes):
        """Return (seq, ftype, inner) where inner = [cmd][payload] for CMD frames."""
        if len(data) < 4:
            return None
        seq, ftype, length = struct.unpack("<BBH", data[:4])
        payload = data[4 : 4 + length]
        if ftype != TYPE_CMD:
            return seq, ftype, b""
        key = _rotl(self._h0, seq & 0x0F)
        iv = _rotl(self._h1, (seq >> 4) & 0x0F)
        try:
            dec = _pkcs7_unpad(_aes_cbc_decrypt(key, iv, payload))
        except Exception:
            return seq, ftype, None
        if dec and dec[0] == seq:
            dec = dec[1:]
        return seq, ftype, dec


def parse_handshake_reply(inner: bytes):
    """inner = [0x00][proto:2 LE][fwMaj][fwMin][mode][token:16]  (mh/b.java)."""
    if not inner or inner[0] != CMD_HANDSHAKE:
        return None
    body = inner[1:]
    if len(body) < 21:
        return None
    return {
        "protocol": struct.unpack("<H", body[0:2])[0],
        "firmware": f"{body[2]}.{body[3]}",
        "mode": body[4],
        "token": body[5:21],
    }
