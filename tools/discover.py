#!/usr/bin/env python3
"""
Stage 0 — passive discovery of Syncleo / Hommyn / Ballu breezers on the LAN.

This is READ-ONLY. It browses the mDNS service type `_syncleo._udp` (exactly what
the Hommyn app does, lh/d.java:283) and prints each device's address, control
PORT, and TXT records. It sends NO commands and cannot change anything on the
device. Safe to run as many times as you like.

What it tells you (the unknowns we still need to confirm for the ASP-100):
  * the UDP CONTROL PORT       -> from the resolved SRV record (g6/d.java onServiceResolved)
  * protocol version           -> TXT 'protocol'  (1 = plaintext, >=2 = AES-encrypted)
  * whether AES is needed       -> derived, mirroring the app's own validation
  * the device Curve25519 pubkey-> TXT 'public'   (needed later for the handshake)
  * pairing state              -> TXT 'pairing'
  * mac / vendor / devtype / firmware

Requirements:
    pip install zeroconf

Run (laptop must be on the SAME Wi-Fi as the breezer; no AP/guest isolation, VPN off):
    python discover.py            # browse for ~15s
    python discover.py --timeout 30
"""

import argparse
import sys
import time

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
except ImportError:
    sys.exit("Missing dependency. Run:  pip install zeroconf")

SERVICE_TYPE = "_syncleo._udp.local."

# TXT keys the app reads (g6/d.java:404-438)
KNOWN_KEYS = [
    "macaddr", "vendor", "devtype", "basetype",
    "protocol", "pairing", "firmware", "curve", "public",
]


def ip_strings(info):
    """Return human-readable IPv4/IPv6 addresses from a ServiceInfo."""
    addrs = []
    try:
        addrs = info.parsed_addresses()  # zeroconf >= 0.40
    except Exception:
        import socket
        for raw in getattr(info, "addresses", []) or []:
            try:
                addrs.append(socket.inet_ntoa(raw))
            except Exception:
                pass
    return addrs


def decode_txt(info):
    """Return {str: str} of the TXT key/value pairs."""
    out = {}
    for k, v in (info.properties or {}).items():
        key = k.decode("utf-8", "replace") if isinstance(k, (bytes, bytearray)) else str(k)
        if v is None:
            val = ""
        elif isinstance(v, (bytes, bytearray)):
            val = v.decode("utf-8", "replace")
        else:
            val = str(v)
        out[key] = val
    return out


def analyze(txt):
    """Mirror the app's protocol/crypto validation (g6/d.java:474-482)."""
    notes = []
    try:
        protocol = int(txt.get("protocol", "1"))
    except ValueError:
        protocol = 1

    pub = (txt.get("public") or "").strip()
    try:
        curve = int(txt.get("curve") or "0")
    except ValueError:
        curve = 0

    pub_len = len(pub) // 2 if pub else 0  # hex chars -> bytes

    encrypted = False
    if protocol >= 2:
        if curve == 29 and pub_len == 32:
            encrypted = True
            notes.append("protocol>=2 with curve=29 + 32-byte pubkey -> AES-128-CBC session REQUIRED.")
        else:
            notes.append(
                f"protocol>=2 but curve={curve} / pubkey={pub_len}B -> app DOWNGRADES to plaintext (protocol 1)."
            )
    else:
        notes.append("protocol=1 -> PLAINTEXT frames, no Curve25519/AES needed.")

    pairing = txt.get("pairing")
    if pairing is not None:
        notes.append(f"pairing flag = {pairing} (device-advertised pairing state).")

    return {"protocol": protocol, "curve": curve, "pubkey_bytes": pub_len,
            "encrypted": encrypted, "notes": notes}


class Listener(ServiceListener):
    def __init__(self, zc):
        self.zc = zc
        self.seen = {}

    def add_service(self, zc, type_, name):
        self._resolve(zc, type_, name, "FOUND")

    def update_service(self, zc, type_, name):
        self._resolve(zc, type_, name, "UPDATED")

    def remove_service(self, zc, type_, name):
        print(f"\n[-] LOST    {name}")

    def _resolve(self, zc, type_, name, tag):
        info = zc.get_service_info(type_, name, timeout=3000)
        if not info:
            print(f"\n[{tag}] {name}  (could not resolve details)")
            return
        self.seen[name] = info
        self._print(name, info, tag)

    def _print(self, name, info, tag):
        addrs = ip_strings(info)
        txt = decode_txt(info)
        a = analyze(txt)

        print("\n" + "=" * 70)
        print(f"[{tag}] {name}")
        print(f"  host        : {info.server}")
        print(f"  addresses   : {', '.join(addrs) or '(none)'}")
        print(f"  CONTROL PORT: {info.port}        <-- UDP control port (SRV record)")
        print("  --- TXT records ---")
        for k in KNOWN_KEYS:
            if k in txt:
                v = txt[k]
                if k == "public" and len(v) > 24:
                    v = f"{v[:16]}… ({len(v)//2} bytes)"
                print(f"    {k:<9}= {v}")
        extra = {k: v for k, v in txt.items() if k not in KNOWN_KEYS}
        for k, v in extra.items():
            print(f"    {k:<9}= {v}   (unrecognized)")
        print("  --- analysis ---")
        print(f"    protocol={a['protocol']}  curve={a['curve']}  "
              f"pubkey={a['pubkey_bytes']}B  encrypted={a['encrypted']}")
        for n in a["notes"]:
            print(f"    * {n}")


def main():
    ap = argparse.ArgumentParser(description="Passive mDNS discovery of Syncleo/_syncleo._udp devices.")
    ap.add_argument("--timeout", type=int, default=15, help="seconds to browse (default 15)")
    args = ap.parse_args()

    print(f"Browsing for {SERVICE_TYPE} for {args.timeout}s ...")
    print("(Same Wi-Fi as the breezer; disable VPN and AP/guest isolation if nothing shows up.)")

    zc = Zeroconf()
    listener = Listener(zc)
    ServiceBrowser(zc, SERVICE_TYPE, listener)
    try:
        time.sleep(args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        zc.close()

    print("\n" + "=" * 70)
    if listener.seen:
        print(f"Done. {len(listener.seen)} device(s) found.")
        print("Next: note the CONTROL PORT and whether encrypted=True, then we write Stage 1 (handshake).")
    else:
        print("Done. No devices found.")
        print("Troubleshoot: same Wi-Fi? VPN off? guest/AP isolation off? Breezer powered & on Wi-Fi?")
        print("Cross-check with the OS tool:  dns-sd -B _syncleo._udp   (macOS)")


if __name__ == "__main__":
    main()