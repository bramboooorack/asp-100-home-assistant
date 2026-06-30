#!/usr/bin/env python3
"""
asp100_proto.py — the Syncleo/Ballu UDP protocol library (shared by the tools).

Exposes:
  * Session            — per-connection X25519 ECDH + AES-128-CBC framing
  * discover()         — mDNS (_syncleo._udp) device discovery
  * parse_handshake_reply(), token_path()

See PROTOCOL.md for the full description. The protocol was reconstructed by
observing the official app; no proprietary code is included here.

Running this file directly performs an on-LAN reset-and-pair (for devices that
pair on the home LAN rather than via SoftAP). For the ASP-100 use pair.py.

Requirements:  pip install zeroconf cryptography
Usage:         python asp100_proto.py --mac c4:d8:d5:90:0c:80
"""

import argparse
import hashlib
import os
import socket
import struct
import sys
import time

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
except ImportError:
    sys.exit("Missing dependency. Run:  pip install zeroconf cryptography")

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("Missing dependency. Run:  pip install cryptography")

SERVICE_TYPE = "_syncleo._udp.local."

# on-wire frame type bytes (oh/a.java parse constructor)
TYPE_ACK = 0x00
TYPE_CMD = 0x01   # data/handshake (FRAME_CMD)
TYPE_AUX = 0x02
TYPE_NAK = 0xFF

CMD_HANDSHAKE = 0x00


def token_path(name: str = "asp100.token") -> str:
    """Path to a token file next to these scripts (cwd-independent)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


# ---------------------------------------------------------------- crypto helpers
def rotl(b: bytes, n: int) -> bytes:
    """Left-rotate a 16-byte block by n bytes (nh/d.java key/iv schedule)."""
    n &= 0x0F
    return b[n:] + b[:n]


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def pkcs7_pad(data: bytes) -> bytes:
    p = 16 - (len(data) % 16)
    return data + bytes([p]) * p


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    p = data[-1]
    return data[:-p] if 0 < p <= 16 else data


class Session:
    """Holds the derived AES key/iv halves and builds/parses frames."""

    def __init__(self, device_pub: bytes):
        self.priv = X25519PrivateKey.generate()
        # l8/a.java:818 -> this.A = rh.a.m(keypair.getPublicKey()): the app sends its
        # OWN public key byte-REVERSED. h.java then sends dVar.A unmodified.
        self.app_pub = self.priv.public_key().public_bytes_raw()[::-1]  # 32 bytes, reversed
        # nh/d.java:765 -> SHA256( rh.a.m( X25519( rh.a.m(devicePub), appPriv ) ) )
        # rh.a.m() is a byte-reversal: the device advertises its pubkey big-endian,
        # and the shared secret is reversed before hashing.
        shared = self.priv.exchange(X25519PublicKey.from_public_bytes(device_pub[::-1]))
        digest = hashlib.sha256(shared[::-1]).digest()            # 32 bytes
        self.h0 = digest[0:16]    # f15315y  (recv key base / send iv base)
        self.h1 = digest[16:32]   # f15316z  (send key base / recv iv base)
        self.tx_seq = 0           # our outgoing seq (first frame = 0)

    # --- app -> device ---
    def build_handshake(self, token16: bytes) -> bytes:
        """Pairing/auth handshake frame. token16 = 16 zero bytes to pair."""
        assert len(token16) == 16
        # inner token encrypted AES-CBC NoPadding, key=h1, iv=h0 (h.java:119)
        enc_token = aes_cbc_encrypt(self.h1, self.h0, token16)     # 16 bytes
        inner = bytes([CMD_HANDSHAKE]) + self.app_pub + enc_token  # 1+32+16 = 49
        # frame is NOT frame-level encrypted (withEncrypt=false)
        return self._frame(seq=self.tx_seq, ftype=TYPE_CMD, payload=inner)

    def build_encrypted_cmd(self, cmd: int, payload: bytes, seq: int) -> bytes:
        """Normal encrypted command frame: AES-CBC-PKCS7([seq][cmd][payload])."""
        plain = bytes([seq, cmd]) + payload
        key = rotl(self.h1, seq & 0x0F)
        iv = rotl(self.h0, (seq >> 4) & 0x0F)
        enc = aes_cbc_encrypt(key, iv, pkcs7_pad(plain))
        return self._frame(seq=seq, ftype=TYPE_CMD, payload=enc)

    def build_ack(self, seq: int) -> bytes:
        """Encrypted ACK for a received frame (empty payload)."""
        key = rotl(self.h1, seq & 0x0F)
        iv = rotl(self.h0, (seq >> 4) & 0x0F)
        enc = aes_cbc_encrypt(key, iv, pkcs7_pad(bytes([seq])))
        return self._frame(seq=seq, ftype=TYPE_ACK, payload=enc)

    @staticmethod
    def _frame(seq: int, ftype: int, payload: bytes) -> bytes:
        # header: [seq][type][len:uint16 LE] + payload
        return struct.pack("<BBH", seq & 0xFF, ftype, len(payload)) + payload

    # --- device -> app ---
    def parse_frame(self, data: bytes):
        """Return (seq, ftype, decrypted_inner) or None."""
        if len(data) < 4:
            return None
        seq, ftype, length = struct.unpack("<BBH", data[:4])
        payload = data[4:4 + length]
        if ftype != TYPE_CMD:
            return seq, ftype, b""        # ACK/NAK/AUX: no cmd payload we need
        # decrypt: key=h0 rot(seq&0xF), iv=h1 rot((seq>>4)&0xF)
        key = rotl(self.h0, seq & 0x0F)
        iv = rotl(self.h1, (seq >> 4) & 0x0F)
        try:
            dec = aes_cbc_decrypt(key, iv, payload)
        except Exception as e:
            print(f"  [!] decrypt failed (seq={seq}): {e}")
            return seq, ftype, None
        dec = pkcs7_unpad(dec)
        if dec and dec[0] == seq:
            dec = dec[1:]                  # strip seq byte -> [cmd][cmdpayload]
        return seq, ftype, dec


def parse_handshake_reply(inner: bytes):
    """inner = [cmd=0x00][proto:2 LE][fwMaj][fwMin][mode][token:16]  (mh/b.java)."""
    if not inner or inner[0] != CMD_HANDSHAKE:
        return None
    body = inner[1:]
    if len(body) < 21:
        return None
    protocol = struct.unpack("<H", body[0:2])[0]
    fw = f"{body[2]}.{body[3]}"
    mode = body[4]
    token = body[5:21]
    return {"protocol": protocol, "firmware": fw, "mode": mode, "token": token}


# ---------------------------------------------------------------- discovery
def discover(target_mac=None, timeout: int = 12):
    """Return dict with ip, port, pubkey for a device.

    If target_mac is given, return the device whose macaddr matches. If it is
    None, return the first _syncleo._udp device found (handy on a device AP
    where there is only one).
    """
    target_mac = target_mac.lower().replace("-", ":") if target_mac else None
    found = {}

    class L(ServiceListener):
        def add_service(self, zc, t, name):
            self._h(zc, t, name)
        def update_service(self, zc, t, name):
            self._h(zc, t, name)
        def remove_service(self, zc, t, name):
            pass
        def _h(self, zc, t, name):
            if "ip" in found:
                return
            info = zc.get_service_info(t, name, timeout=3000)
            if not info:
                return
            props = {(k.decode() if isinstance(k, bytes) else k):
                     (v.decode() if isinstance(v, bytes) else v)
                     for k, v in (info.properties or {}).items()}
            mac = (props.get("macaddr") or "").lower()
            if target_mac is not None and mac != target_mac:
                return
            found["mac"] = mac
            addrs = info.parsed_addresses()
            ipv4 = next((a for a in addrs if ":" not in a), addrs[0] if addrs else None)
            found.update(
                ip=ipv4, port=info.port,
                protocol=int(props.get("protocol", "1")),
                curve=int(props.get("curve", "0")),
                pubkey=props.get("public", ""),
                pairing=props.get("pairing"),
                firmware=props.get("firmware"),
            )

    zc = Zeroconf()
    ServiceBrowser(zc, SERVICE_TYPE, L())
    deadline = time.time() + timeout
    try:
        while time.time() < deadline and "ip" not in found:
            time.sleep(0.3)
    finally:
        zc.close()
    return found if "ip" in found else None


# ---------------------------------------------------------------- main
def do_handshake(dev, attempts=5):
    pub_hex = dev["pubkey"]
    if len(pub_hex) != 64:
        sys.exit(f"Device pubkey is {len(pub_hex)//2} bytes, expected 32. Aborting.")
    sess = Session(bytes.fromhex(pub_hex))
    frame = sess.build_handshake(b"\x00" * 16)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    dest = (dev["ip"], dev["port"])
    print(f"--> sending pairing handshake to {dest[0]}:{dest[1]} "
          f"({len(frame)} bytes, app pubkey {sess.app_pub.hex()[:16]}…)")

    for i in range(1, attempts + 1):
        sock.sendto(frame, dest)
        try:
            while True:
                data, _ = sock.recvfrom(4096)
                parsed = sess.parse_frame(data)
                if not parsed:
                    continue
                seq, ftype, inner = parsed
                if ftype != TYPE_CMD or inner is None:
                    continue
                reply = parse_handshake_reply(inner)
                if reply is None:
                    print(f"  <-- frame seq={seq} cmd=0x{inner[0]:02x} (not handshake)")
                    continue
                # ACK it
                sock.sendto(sess.build_ack(seq), dest)
                return reply
        except socket.timeout:
            print(f"  … no reply (attempt {i}/{attempts}), retrying")
    return None


def main():
    ap = argparse.ArgumentParser(description="Pair with a factory-reset Syncleo breezer and capture its token.")
    ap.add_argument("--mac", required=True, help="target device MAC, e.g. c4:d8:d5:90:0c:80")
    ap.add_argument("--no-prompt", action="store_true", help="skip the reset prompt (device already in pairing mode)")
    args = ap.parse_args()

    print(f"[1] Locating device {args.mac} on the LAN …")
    dev = discover(args.mac)
    if not dev:
        sys.exit("    Device not found. Same Wi-Fi? Correct MAC? Is it powered on?")
    print(f"    found: ip={dev['ip']} port={dev['port']} protocol={dev['protocol']} "
          f"fw={dev['firmware']} pairing={dev['pairing']}")
    if dev["protocol"] < 2:
        sys.exit("    protocol < 2 (plaintext) — this script targets the encrypted path; ping me to adjust.")

    if not args.no_prompt:
        print("\n" + "!" * 64)
        print("  RESET THE DEVICE NOW.")
        print(f"  Factory-reset breezer {args.mac} so it enters pairing mode,")
        print("  then wait for it to reconnect to Wi-Fi (a few seconds).")
        print("!" * 64)
        input("\n  Press Enter once the device is reset and back online… ")

        print("\n[2] Re-discovering after reset (pubkey may have changed) …")
        dev2 = discover(args.mac, timeout=20)
        if not dev2:
            sys.exit("    Device did not reappear. Give it a moment and re-run.")
        dev = dev2
        print(f"    found: ip={dev['ip']} port={dev['port']} pairing={dev['pairing']}")

    print("\n[3] Performing ECDH + pairing handshake …")
    reply = do_handshake(dev)
    if reply is None:
        sys.exit("    No handshake reply. Device may not be in pairing mode — reset and retry.")

    token = reply["token"]
    print("\n" + "=" * 64)
    if any(token):
        token_hex = token.hex()
        print(f"  PAIRED ✓   protocol={reply['protocol']} fw={reply['firmware']} mode={reply['mode']}")
        print(f"  DEVICE TOKEN = {token_hex}")
        path = token_path(f"{args.mac.replace(':', '')}.token")
        with open(path, "w") as f:
            f.write(token_hex + "\n")
        print(f"  saved -> {path}")
        print("  This token is your permanent credential. control.py replays it to connect.")
    else:
        print("  Device returned a ZERO token = 'auth required'.")
        print("  It is NOT in pairing mode. Factory-reset it and run again.")
    print("=" * 64)


if __name__ == "__main__":
    main()