#!/usr/bin/env python3
"""
pair.py — pair + Wi-Fi-provision a factory-reset breezer over its SoftAP.

A factory-reset unit hosts its own Wi-Fi AP (e.g. "ONEAIR ASP-100") and still
speaks the encrypted protocol there (192.168.4.1:41122, protocol 2). This pairs
with it, captures the device token, and hands it your home Wi-Fi credentials so
it joins your LAN — after which you control it with control.py.

Flow (run while your computer is joined to the device's AP):
  1. discover the device on the AP -> ip(192.168.4.1), port 41122, fresh pubkey
  2. X25519 ECDH -> SHA-256 -> AES key/iv halves
  3. handshake (zero token) -> device mints + returns a 16-byte token
  4. TimeSync, then Wi-Fi config (ssid + password) -> device joins your home Wi-Fi
  5. token saved next to this script as asp100.token (your permanent credential)

Requirements: pip install zeroconf cryptography

Usage (JOIN the device's AP Wi-Fi FIRST):
    python pair.py --home-ssid "MyWiFi" --home-pass "secret"
    # --pair-only             : just capture the token, skip Wi-Fi config (non-destructive)
    # --mac c4:d8:..          : pick a specific device (optional on the AP, only one is there)
    # --bssid ff:ff:..:ff     : any AP with that SSID (default)
"""

import argparse
import socket
import struct
import sys
import time
import calendar

from asp100_proto import Session, parse_handshake_reply, discover, token_path, TYPE_CMD, TYPE_ACK

CMD_TIMESYNC = 0x80
CMD_WIFI_CONFIG = 0x82


def wifi_config_payload(bssid6: bytes, ssid: str, password: str) -> bytes:
    s, p = ssid.encode(), password.encode()
    if len(s) > 255 or len(p) > 255:
        sys.exit("SSID/password too long.")
    # NOTE: the cmd byte (0x82) is added by Session.build_encrypted_cmd; this is zg.e.getPayload()
    return bssid6 + bytes([len(s)]) + s + bytes([len(p)]) + p


def timesync_payload() -> bytes:
    now = int(time.time())
    # tz offset in minutes (local - UTC); mh/d.java: int32 LE seconds + int16 LE minutes
    off_min = -(time.timezone // 60) if not time.daylight else -(time.altzone // 60)
    return struct.pack("<ih", now, off_min)


def local_source_ip(dest_ip):
    """The source IP the OS would use to reach dest_ip (reveals egress interface)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 41122))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def recv_cmd(sock, dest, sess, want_cmd, send_frame, attempts=6, debug=True):
    """Send send_frame, wait for a CMD frame with cmd==want_cmd; return inner payload.

    Logs EVERY datagram received (raw hex + parsed header), so non-CMD replies
    (ACK/NAK/AUX) are visible instead of being silently treated as 'no reply'.
    """
    if debug:
        print(f"  -> sending {len(send_frame)}B to {dest[0]}:{dest[1]}: {send_frame.hex()}")
    for i in range(1, attempts + 1):
        sock.sendto(send_frame, dest)
        try:
            while True:
                data, src = sock.recvfrom(4096)
                if debug:
                    hdr = data[:4].hex() if len(data) >= 4 else data.hex()
                    print(f"  <- {len(data)}B from {src[0]}:{src[1]}  hdr={hdr}  raw={data.hex()}")
                parsed = sess.parse_frame(data)
                if not parsed:
                    continue
                seq, ftype, inner = parsed
                if debug:
                    tname = {0x00: "ACK", 0x01: "CMD", 0x02: "AUX", 0xFF: "NAK"}.get(ftype, hex(ftype))
                    icmd = f" cmd=0x{inner[0]:02x}" if (ftype == TYPE_CMD and inner) else ""
                    print(f"     parsed: seq={seq} type={tname}{icmd} inner={inner.hex() if inner else ''}")
                if ftype != TYPE_CMD or not inner:
                    continue
                sock.sendto(sess.build_ack(seq), dest)  # ack any CMD frame
                if inner[0] == want_cmd:
                    return inner
        except socket.timeout:
            print(f"  … no datagram received (attempt {i}/{attempts})")
    return None


def main():
    ap = argparse.ArgumentParser(description="Encrypted SoftAP onboarding for a factory-reset ASP-100.")
    ap.add_argument("--mac", help="device MAC (optional; if omitted, use the only device found on the AP)")
    ap.add_argument("--home-ssid", help="HOME Wi-Fi SSID to provision into the device")
    ap.add_argument("--home-pass", default="", help="HOME Wi-Fi password")
    ap.add_argument("--bssid", default="ff:ff:ff:ff:ff:ff", help="home AP BSSID or ff:..:ff for any")
    ap.add_argument("--pair-only", action="store_true", help="only capture the token, skip Wi-Fi config")
    ap.add_argument("--no-timesync", action="store_true", help="skip the TimeSync step")
    ap.add_argument("--bind", help="force this local source IP (your laptop's 192.168.4.x on the AP)")
    ap.add_argument("--watch-secs", type=float, default=90.0,
                    help="how long to keep re-sending the handshake, waiting for the pairing "
                         "window (default 90s). Start this, THEN trigger pair mode on the device.")
    args = ap.parse_args()

    if not args.pair_only and not args.home_ssid:
        sys.exit("Provide --home-ssid (+ --home-pass), or --pair-only to just capture the token.")

    print(f"[1] Discovering {args.mac or 'the device'} on the AP …")
    dev = discover(args.mac, timeout=15)
    if not dev:
        sys.exit("    Not found. Joined to 'ONEAIR ASP-100'? Correct --mac (if given)?")
    print(f"    mac={dev.get('mac')} ip={dev['ip']} port={dev['port']} "
          f"protocol={dev['protocol']} fw={dev['firmware']} pairing={dev.get('pairing')}")
    if dev["protocol"] < 2 or len(dev["pubkey"]) != 64:
        sys.exit("    Unexpected: not protocol-2/32-byte-key on the AP. Ping me with this output.")

    # NOTE: ASP-100 fw 1.38 does NOT advertise a 'pairing' TXT field at all
    # (neither when bound nor when pairable), so it is not a usable signal here.
    # The device decides device-side whether to MINT a new 16-byte token: it only
    # mints when its stored token has been wiped by a FULL factory reset. If it
    # still holds a bound token it answers the zero-token handshake with a zero
    # token = "auth required" (nh/d.java:349). The app cannot force a mint.

    sess = Session(bytes.fromhex(dev["pubkey"]))
    dest = (dev["ip"], dev["port"])

    src_ip = local_source_ip(dev["ip"])
    print(f"    OS would send to {dev['ip']} from source IP: {src_ip}")
    if src_ip and not src_ip.startswith("192.168.4."):
        print(f"    [!] WARNING: source IP {src_ip} is NOT on the device's 192.168.4.x AP subnet.")
        print("        Your unicast may be leaving the wrong interface. Re-run with")
        print("        --bind <your 192.168.4.x address>  (find it: ipconfig getifaddr en0).")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if args.bind:
        sock.bind((args.bind, 0))
        print(f"    bound local socket to {args.bind}")
    sock.settimeout(0.4)

    # 2) handshake — POUNCE loop.
    # The device's minting window is only open for a few seconds after you trigger
    # pair mode. Instead of firing once, we keep resending the zero-token handshake
    # and inspect every reply: a ZERO token means "window not open yet" (keep going),
    # a NON-ZERO token means the device just minted -> capture it instantly.
    print("\n[2] Waiting for the pairing window …")
    print(f"    >>> Trigger PAIR mode on the device NOW. Resending for up to {args.watch_secs:.0f}s.")
    hs = sess.build_handshake(b"\x00" * 16)
    token, reply = None, None
    deadline = time.time() + args.watch_secs
    attempt = 0
    last_note = 0.0
    while time.time() < deadline:
        attempt += 1
        sock.sendto(hs, dest)
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        parsed = sess.parse_frame(data)
        if not parsed:
            continue
        seq, ftype, inner = parsed
        if ftype != TYPE_CMD or not inner or inner[0] != 0x00:
            continue
        sock.sendto(sess.build_ack(seq), dest)  # ack the handshake reply
        r = parse_handshake_reply(inner)
        if not r:
            continue
        if any(r["token"]):
            token, reply = r["token"], r
            break
        # zero token: window not open yet — keep hammering, nudge the user occasionally
        if time.time() - last_note > 5:
            print(f"    … device still returns ZERO (not in pairing window yet). "
                  f"Trigger/hold pair mode. [{int(deadline - time.time())}s left]")
            last_note = time.time()
        time.sleep(0.25)

    if token is None:
        sys.exit("    Never caught a non-zero token. Start this script FIRST, then trigger pair "
                 "mode on the device (window is only a few seconds). Stay joined to the AP.")

    print(f"    PAIRED ✓  protocol={reply['protocol']} fw={reply['firmware']} "
          f"mode={reply['mode']}  (after {attempt} handshakes)")
    print(f"    DEVICE TOKEN = {token.hex()}")
    tpath = token_path()
    with open(tpath, "w") as f:
        f.write(token.hex() + "\n")
    print(f"    saved -> {tpath}")

    seq = 1
    if args.pair_only:
        print("\n[done] --pair-only: token captured, Wi-Fi config skipped (device stays in AP mode).")
        return

    # 3) TimeSync (seq 1) — mirrors the app's post-connect behavior
    if not args.no_timesync:
        print("\n[3] TimeSync …")
        sock.sendto(sess.build_encrypted_cmd(CMD_TIMESYNC, timesync_payload(), seq), dest)
        time.sleep(0.3)
        seq += 1

    # 4) Wi-Fi config
    try:
        bssid6 = bytes(int(x, 16) for x in args.bssid.split(":"))
        assert len(bssid6) == 6
    except Exception:
        sys.exit("Bad --bssid; use ff:ff:ff:ff:ff:ff form.")
    print(f"\n[4] Wi-Fi config: ssid='{args.home_ssid}' bssid={args.bssid} …")
    payload = wifi_config_payload(bssid6, args.home_ssid, args.home_pass)
    wifi_frame = sess.build_encrypted_cmd(CMD_WIFI_CONFIG, payload, seq)
    for _ in range(4):
        sock.sendto(wifi_frame, dest)
        time.sleep(0.4)
    print("    sent. Device should leave its AP and join your home Wi-Fi.")
    print("\n[next] Reconnect your laptop to HOME Wi-Fi, then run:")
    print("        .venv/bin/python discover.py")
    print("       to confirm the breezer reappears on the LAN.")


if __name__ == "__main__":
    main()