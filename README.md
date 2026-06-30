# Ballu ASP-100 Breezer — local Home Assistant integration

Control **Ballu ASP-100 / Electrolux EASP-100** breezers (and likely other
Syncleo/Rusklimat-platform devices) **entirely on your local network** from
Home Assistant — no cloud, no vendor app required.

The device speaks an encrypted UDP protocol on your LAN. This project
reimplements that protocol (discovery, key exchange, pairing, and commands) so
Home Assistant can talk to the breezer directly.

> **Unofficial project.** Not affiliated with, endorsed by, or supported by
> Ballu, Electrolux, Rusklimat, or Syncleo. "Ballu", "Electrolux" and other
> names are trademarks of their respective owners. Reverse-engineered for
> personal interoperability. Use at your own risk — it may void your warranty.
> No proprietary firmware or app code is included in this repository.

---

## Features

A single Home Assistant **device** with:

| Entity | What it does |
|--------|--------------|
| **Climate** | Target temperature (5–25 °C), fan speed (1–7), on/off, and **presets**: Manual / Auto / Night / **Turbo** / Fan |
| **Sensors** | Current temperature, filter life %, (CO₂ / humidity / PM2.5 if your unit has the sensors) |
| **Binary sensor** | Fault / error |
| **Switches** | Child lock, ionization, night (only those your unit reports) |

All local, all push-free polling (~30 s), authenticated with a per-device token.

## Supported hardware

- **Ballu ASP-100 / Electrolux EASP-100** (device type 69), firmware 1.38 tested.
- Other Syncleo-platform breezers may work but the entity/feature mapping is
  tuned for the ASP-100.

## How it works (short version)

- **Discovery:** the device advertises itself via mDNS as `_syncleo._udp` (its
  IP, control port `41122`, protocol version, and an X25519 public key).
- **Encryption:** every session does an ephemeral X25519 ECDH → SHA-256 →
  AES-128-CBC. Commands ride a small reliable-UDP framing layer.
- **Auth:** a 16-byte **token** minted by the device during pairing; you present
  it on every connect. No cloud is involved in the token check.

Full technical write-up: [PROTOCOL.md](PROTOCOL.md).

---

## Installation

### 1. Install the integration

**HACS (recommended):** add this repository as a custom repository (category
*Integration*), install "Ballu ASP-100 Breezer (Syncleo local)", then restart
Home Assistant.

**Manual:** copy `custom_components/asp100/` into your HA `config/custom_components/`
directory and restart.

### 2. Get your device token (one-time pairing)

Home Assistant needs the device on your LAN plus its **token**. Pairing requires
joining the device's own Wi-Fi briefly, which is easiest from a laptop using the
CLI tools in [`tools/`](tools/).

```bash
cd tools
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then:

1. **Factory-reset the breezer.** It stops joining your Wi-Fi and starts
   broadcasting its own access point (e.g. `ONEAIR ASP-100`).
2. **Join that access point** from your computer. (You'll have no internet while
   on it — that's fine.)
3. **Confirm the device is visible** on the AP and note its details:
   ```bash
   python discover.py
   ```
4. **Start the pairing script, then trigger pair mode on the device.** The
   device only mints a token during a brief (few-second) pairing window, so the
   script keeps re-sending the handshake and *pounces* the moment the window
   opens. **Run the command first, then press/hold the pair button** — not the
   other way around:
   ```bash
   # capture the token only (don't change the device's Wi-Fi):
   python pair.py --pair-only

   # or capture the token AND hand the device your home Wi-Fi in one shot:
   python pair.py --home-ssid "YourWiFi" --home-pass "YourPassword"
   ```
   It waits up to 90s (`--watch-secs` to change) printing a countdown; as soon as
   you trigger pair mode it prints `PAIRED ✓  DEVICE TOKEN = …`.
   Use a **2.4 GHz** SSID — these units don't join 5 GHz-only networks.
   The token is saved to `tools/asp100.token`.
5. **Reconnect your computer to your home Wi-Fi** and confirm the breezer
   rejoined the LAN:
   ```bash
   python discover.py
   ```
   Note the **MAC address** it prints (e.g. `c4:d8:d5:90:0c:80`).

### 3. Add the device in Home Assistant

Settings → Devices & Services → **Add Integration** → "Ballu ASP-100 Breezer".
Enter:

- **MAC address** — from `discover.py`
- **Token** — the hex string in `tools/asp100.token`
- **IP** — optional; leave blank for mDNS auto-discovery

The integration validates by authenticating with the device before finishing.

---

## CLI tools

The `tools/` scripts let you test everything **before** (or without) Home
Assistant. Run them from inside `tools/` with the venv activated.

| Script | Purpose |
|--------|---------|
| `discover.py` | Browse the LAN for breezers; print IP, port, protocol, keys |
| `pair.py` | SoftAP onboarding: pair, capture token, provision Wi-Fi |
| `control.py` | Authenticate with the token, read state, send commands |
| `asp100_proto.py` | The protocol library (imported by the others) |

Examples:
```bash
python control.py                       # read live state
python control.py --set-speed 3         # fan speed (Manual program)
python control.py --set-mode 4          # Turbo program (~15 min boost)
python control.py --set-target-temp 22  # heater setpoint °C
```
`--set-mode`: `0`=Off `1`=Manual `2`=Auto `3`=Night `4`=Turbo `5`=Fan.

---

## Notes & troubleshooting

- **The token is a credential.** Anyone with it *and* LAN access can control the
  breezer. It's git-ignored (`*.token`); keep it private. It only works on your
  local network.
- **Give the breezer a static DHCP lease** on your router for the most reliable
  Home Assistant discovery.
- **Nothing found on the AP / LAN?** Same Wi-Fi? VPN off? Some routers isolate
  clients on *guest* networks (AP isolation) — use your main SSID. On macOS with
  multiple interfaces, `pair.py` prints the source IP and accepts `--bind`.
- **Pairing returns a ZERO token / "not in pairing mode"?** The device only mints
  a token during a **short (few-second) pairing window**. If you trigger pair mode
  and *then* tab over to run the script, the window has already closed. Fix:
  **start `pair.py` first** (it keeps re-sending and pounces), *then* trigger pair
  mode on the device. A zero token simply means the window wasn't open when the
  handshake landed — it is **not** a bug in the script.
- **Turbo** is a whole operating *program* (mode 4), not a fan speed. In HA it's
  a climate **preset**; the firmware runs it for ~15 minutes then reverts.
- Re-pairing is only needed if you factory-reset the device (which wipes the token).

## License

[MIT](LICENSE). See the disclaimer at the top — this is an independent
interoperability project.
