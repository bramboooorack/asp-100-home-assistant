"""Blocking ASP-100 client: mDNS discovery + authenticated read/write.

All methods are synchronous (UDP + a short listen) and are intended to be run
from HA via hass.async_add_executor_job. Each call opens a fresh ECDH session
and authenticates with the stored token — stateless and robust for polling.
"""

from __future__ import annotations

import logging
import socket
import struct
import time

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

from .commands import (
    CMD_MODE,
    CMD_SPEED,
    CMD_TARGET_TEMPERATURE,
    decode_state,
    encode_temp,
)
from .protocol import CMD_TIMESYNC, TYPE_CMD, Session, parse_handshake_reply

_LOGGER = logging.getLogger(__name__)

SERVICE_TYPE = "_syncleo._udp.local."


class AuthError(Exception):
    """Device rejected our token (returned a zero token)."""


class DeviceUnavailable(Exception):
    """Device not found on the network or not responding."""


def _discover(mac: str, timeout: float = 6.0) -> dict | None:
    """Resolve a device by MAC via mDNS -> ip, port, pubkey (hex)."""
    mac = mac.lower().replace("-", ":")
    found: dict = {}

    class _L(ServiceListener):
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
            props = {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in (info.properties or {}).items()
            }
            if (props.get("macaddr") or "").lower() != mac:
                return
            addrs = info.parsed_addresses()
            ipv4 = next((a for a in addrs if ":" not in a), addrs[0] if addrs else None)
            found.update(ip=ipv4, port=info.port, pubkey=props.get("public", ""))

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, SERVICE_TYPE, _L())
        end = time.time() + timeout
        while time.time() < end and "ip" not in found:
            time.sleep(0.2)
    finally:
        zc.close()
    return found if "ip" in found else None


class Asp100Device:
    """High-level client for one breezer."""

    def __init__(self, mac: str, token: str, host: str | None = None) -> None:
        self._mac = mac
        self._token = bytes.fromhex(token)
        self._host = host
        self._port = 41122
        self._pubkey: bytes | None = None
        self.firmware: str | None = None

    @property
    def mac(self) -> str:
        return self._mac

    def _ensure_endpoint(self) -> None:
        """Discover ip + pubkey (cached). Pubkey only changes on factory reset."""
        if self._pubkey is not None and self._host is not None:
            return
        dev = _discover(self._mac)
        if not dev or not dev.get("pubkey"):
            raise DeviceUnavailable(f"{self._mac} not found via mDNS")
        if len(dev["pubkey"]) != 64:
            raise DeviceUnavailable("device not on encrypted protocol 2")
        self._host = self._host or dev["ip"]
        self._port = dev["port"]
        self._pubkey = bytes.fromhex(dev["pubkey"])

    def _open_session(self):
        """Discover, ECDH, authenticate. Returns (sock, sess, dest, seq)."""
        self._ensure_endpoint()
        sess = Session(self._pubkey)
        dest = (self._host, self._port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        hs = sess.build_handshake(self._token)
        for _ in range(5):
            sock.sendto(hs, dest)
            try:
                while True:
                    data, _src = sock.recvfrom(4096)
                    parsed = sess.parse_frame(data)
                    if not parsed:
                        continue
                    seq, ftype, inner = parsed
                    if ftype == TYPE_CMD and inner:
                        sock.sendto(sess.build_ack(seq), dest)
                        if inner[0] == 0x00:
                            reply = parse_handshake_reply(inner)
                            if reply and not any(reply["token"]):
                                sock.close()
                                raise AuthError("device rejected token")
                            if reply:
                                self.firmware = reply["firmware"]
                                return sock, sess, dest, 1
            except socket.timeout:
                continue
        sock.close()
        raise DeviceUnavailable("no handshake reply")

    def _pump(self, sock, sess, dest, duration, frames) -> None:
        end = time.time() + duration
        sock.settimeout(0.5)
        while time.time() < end:
            try:
                data, _src = sock.recvfrom(4096)
            except socket.timeout:
                continue
            parsed = sess.parse_frame(data)
            if not parsed:
                continue
            seq, ftype, inner = parsed
            if ftype != TYPE_CMD or not inner:
                continue
            sock.sendto(sess.build_ack(seq), dest)
            frames[inner[0]] = inner[1:]

    # ---- public API (call via executor) ----
    def read_state(self, listen: float = 3.0) -> dict[str, object]:
        sock, sess, dest, seq = self._open_session()
        try:
            off_min = -(time.timezone // 60) if not time.daylight else -(time.altzone // 60)
            sock.sendto(sess.build_cmd(CMD_TIMESYNC, struct.pack("<ih", int(time.time()), off_min), seq), dest)
            frames: dict[int, bytes] = {}
            self._pump(sock, sess, dest, listen, frames)
            return decode_state(frames)
        finally:
            sock.close()

    def _write(self, cmd: int, payload: bytes) -> None:
        sock, sess, dest, seq = self._open_session()
        try:
            sock.sendto(sess.build_cmd(cmd, payload, seq), dest)
            time.sleep(0.3)
            self._pump(sock, sess, dest, 1.0, {})  # drain echo
        finally:
            sock.close()

    def set_speed(self, value: int) -> None:
        self._write(CMD_SPEED, bytes([value & 0xFF]))

    def set_mode(self, value: int) -> None:
        """Select operating program via CmdMode (0x01): 0=Off,1=Manual,2=Auto,
        3=Night,4=Turbo,5=Fan. Turbo is program 4 (firmware ~15 min timer)."""
        self._write(CMD_MODE, bytes([value & 0xFF]))

    def set_target_temperature(self, value: float) -> None:
        self._write(CMD_TARGET_TEMPERATURE, encode_temp(value))

    def set_bool(self, cmd: int, on: bool) -> None:
        """Generic on/off for boolean features (child lock, ionization, …)."""
        self._write(cmd, bytes([1 if on else 0]))
