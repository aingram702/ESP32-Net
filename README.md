# ESP32-Net

**A four-device, distributed wireless reconnaissance & WIDS toolkit for
authorized homelab experiments and penetration-testing engagements.**

One coordinator hosts a WiFi access point and a live web dashboard; three
headless ESP32-S3 nodes join it and stream WiFi, 802.11-monitor, and BLE
telemetry over JSON. Everything aggregates into a single terminal-styled
dashboard you can drive from a phone or laptop.

> [!WARNING]
> **Passive recon + defensive monitoring only.** At the radio layer this
> toolkit transmits only what a normal WiFi/BLE scan emits, plus a single
> on-demand GATT client connection. It does **not** deauth, inject, run a rogue
> AP, or store raw payloads/handshakes. Run it only on networks and devices you
> own or have **explicit written authorization** to test. See
> [Security & legal](#security--legal).

---

## Contents

- [Architecture](#architecture)
- [Devices at a glance](#devices-at-a-glance)
- [Hardware / bill of materials](#hardware--bill-of-materials)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [The nodes in detail](#the-nodes-in-detail)
  - [WarDriver](#wardriver--wifi-survey--gps)
  - [WarSniffer](#warsniffer--passive-80211-monitor--wids)
  - [BlueDriver](#bluedriver--ble-scanner--gatt)
- [The C2 dashboard](#the-c2-dashboard)
- [Status LEDs](#status-leds)
- [HTTP API & data export](#http-api--data-export)
- [/ingest protocol](#ingest-protocol)
- [Project layout](#project-layout)
- [Manual page](#manual-page)
- [Troubleshooting](#troubleshooting)
- [Security & legal](#security--legal)

---

## Architecture

```
   [WarDriver]   [WarSniffer]   [BlueDriver]      ESP32-S3 nodes (headless)
        \             |             /
         \            |            /     WiFi STA  →  POST /ingest (JSON)
          \           |           /
            [     C2 coordinator     ]            ESP32-S2, SoftAP "ESP32-NET"
                      │
                HTTP :80 dashboard                browser @ http://192.168.4.1/
```

The three S3 nodes are **headless** — no display, no local web UI. They
associate to the coordinator's SoftAP, POST a compact JSON snapshot to
`/ingest` every few seconds, and receive operator control commands back in the
response. The coordinator keeps a capped in-RAM inventory, aggregates all node
data, and serves the four-tab dashboard at `http://192.168.4.1/` (or
`http://esp32net.local/` where mDNS is supported).

---

## Devices at a glance

| Directory | Hardware | Role |
|---|---|---|
| [`c2-esp32s2/`](c2-esp32s2/) | ESP32-S2 (Flipper WiFi Dev Board) | SoftAP + unified web dashboard + command relay |
| [`wardriver-node/`](wardriver-node/) | ESP32-S3-DevKitC-1 N16R8 | WiFi survey + GPS + WigleWifi CSV log |
| [`warsniffer-node/`](warsniffer-node/) | ESP32-S3-DevKitC-1 N16R8 | Passive 802.11 monitor + WIDS + probe harvest |
| [`bluedriver-node/`](bluedriver-node/) | ESP32-S3-DevKitC-1 N16R8 | Continuous BLE scanner + GATT enumeration |

> [!NOTE]
> **ESP32-S3 = BLE 5.0 only.** No Bluetooth Classic (BR/EDR) — a hardware limit
> of the S3 silicon. Only the original ESP32 (non-S/C) has Classic.

---

## Hardware / bill of materials

| Qty | Part | Notes |
|---|---|---|
| 1 | ESP32-S2 board | Flipper Zero "WiFi Dev Board" (ESP32-S2-WROVER) or any S2 — runs the C2 |
| 3 | ESP32-S3-DevKitC-1 **N16R8** | 16 MB flash, 8 MB octal PSRAM — the scan nodes |
| 1 | NEO-6M GPS module | WarDriver only; UART + 3V3/GND |
| — | USB-C cables, a battery/power bank | for field use |

You can run a subset — e.g. just the C2 + WarDriver. Nodes that never report
simply show **OFFLINE** on the dashboard.

---

## Quick start

Each directory is a self-contained [PlatformIO](https://platformio.org/)
project. **Flash the C2 first** so its SoftAP exists before the nodes try to
join; order among the three nodes does not matter.

```bash
# 1) Coordinator (creates the ESP32-NET access point + dashboard)
cd c2-esp32s2 && pio pkg install && pio run -t upload

# 2) The three scan nodes
cd ../wardriver-node  && pio pkg install && pio run -t upload
cd ../warsniffer-node && pio pkg install && pio run -t upload
cd ../bluedriver-node && pio pkg install && pio run -t upload

# Watch any node's serial console (115200 baud)
pio device monitor
```

Then on your phone/laptop:

1. Join WiFi **`ESP32-NET`** (default password `dropnetc2!`).
2. Browse to **`http://192.168.4.1/`** (or `http://esp32net.local/`).

Common PlatformIO targets:

| Command | Action |
|---|---|
| `pio run` | Compile only |
| `pio run -t upload` | Compile + flash firmware over USB |
| `pio run -t uploadfs` | Flash the LittleFS data partition |
| `pio device monitor` | Serial console at 115200 baud |

---

## Configuration

Compile-time settings live in each project's **`src/config.h`** and must be
edited **before flashing**.

> [!IMPORTANT]
> **Change the default AP credentials before any field use.** The coordinator's
> `AP_SSID` / `AP_PASSWORD` (in `c2-esp32s2/src/config.h`) must match the
> `C2_SSID` / `C2_PASSWORD` in **every** node's config.

| Setting | Default | Where |
|---|---|---|
| AP SSID | `ESP32-NET` | C2 `AP_SSID`, nodes `C2_SSID` |
| AP password | `dropnetc2!` | C2 `AP_PASSWORD`, nodes `C2_PASSWORD` |
| Dashboard URL | `http://192.168.4.1/` | — |
| mDNS host | `esp32net.local` | C2 `MDNS_HOST` |

Other notable knobs:

- **WarDriver** — `GPS_RX_PIN` / `GPS_TX_PIN` / `GPS_BAUD`, `WIFI_LOG_PATH`,
  `LOG_MAX_BYTES`.
- **WarSniffer** — `CHANNEL_MIN` / `CHANNEL_MAX` / `HOP_INTERVAL_MS`, and the
  WIDS thresholds `DEAUTH_THRESHOLD`, `BEACON_FLOOD_THRESHOLD`,
  `EVIL_TWIN_RSSI_DELTA`.
- **BlueDriver** — `DEFAULT_ACTIVE_SCAN`, `SCAN_INTERVAL` / `SCAN_WINDOW`.
- **All nodes** — `STATUS_LED_ENABLED`, `STATUS_LED_PIN`, `LED_BRIGHTNESS`.

---

## The nodes in detail

### WarDriver — WiFi survey + GPS

Runs active WiFi scans, stamps each network with a NEO-6M GPS fix, writes a
**WigleWifi-1.4** CSV to LittleFS (`/wigle.csv`), and flags surveillance/rogue
patterns heuristically.

**GPS wiring (NEO-6M):**

| NEO-6M pin | ESP32-S3 GPIO |
|---|---|
| TX (GPS output) | GPIO 18 (firmware RX) |
| RX (GPS input) | GPIO 17 (firmware TX) |
| VCC | 3.3 V |
| GND | GND |

Change `GPS_RX_PIN` / `GPS_TX_PIN` in `wardriver-node/src/config.h` for other
GPIOs. CSV rows are written only once a network has a GPS-stamped position, so
the log doesn't fill with `0,0` coordinates before the first fix. SSIDs are
RFC-4180-quoted so a comma in a network name can't shift the CSV columns.

### WarSniffer — passive 802.11 monitor + WIDS

Channel-hops 1–13 in promiscuous mode and reports **metadata only**.

**Does:**
- Count frame types (mgmt / ctrl / data / beacon / probe / deauth / EAPOL).
- Build an AP + client-count inventory from beacon and data frames.
- **Harvest directed probe-request SSIDs** — the preferred-network lists devices
  broadcast while hunting for remembered APs. Useful client profiling, fully
  passive (it only listens; it never answers a probe).
- Raise WIDS alerts: **deauth flood** (>20/s), **beacon flood** (>40 unique
  SSIDs/s), **evil-twin** (same SSID, new BSSID, ≥25 dBm RSSI delta).

**Does not:**
- Transmit anything on the monitored band (no deauth, no injection, no rogue AP).
- Store EAPOL/WPA handshake payloads (EAPOL frames are *counted* only).
- Write PCAPs to flash.

### BlueDriver — BLE scanner + GATT

Continuous passive or active BLE advertisement scan via NimBLE v2.x, with
WiFi+BLE coexistence handled by the ESP32-S3 arbiter.

**Does:**
- Per-device inventory: MAC, name, address type, vendor OUI, advertised service
  UUIDs, manufacturer company ID, best RSSI, hit count.
- **GATT service/characteristic enumeration on demand** — click a device row in
  the dashboard (or send a `gatt` command). Reads service/char UUIDs, derived
  properties, and short readable values.

**Does not:**
- Scan Bluetooth Classic (hardware limitation of the ESP32-S3).
- Transmit advertisements or connect to anything without an explicit `gatt`
  command.
- Persist or exfiltrate characteristic values beyond the immediate POST to C2.

---

## The C2 dashboard

The coordinator serves a single-page dashboard with one tab per node. It polls
`/api/data` every 2 seconds; toolbar buttons queue control commands delivered
to nodes in their next `/ingest` response.

| Tab | Shows |
|---|---|
| **OVERVIEW** | Per-node online/offline state, uptime, free heap, aggregate counts |
| **WARDRIVER** | AP table (BSSID, SSID, channel, encryption, RSSI, vendor, threat flag) + GPS fix |
| **WARSNIFFER** | Frame-type counters, AP/STA inventory, WIDS alert log, harvested probe SSIDs |
| **BLUEDRIVER** | BLE device table (+ mfg company ID); click a row to run GATT, result shown below |

The C2's in-RAM stores **evict least-recently-seen entries once full**, so new
devices keep appearing during long runs, and the **`CLEAR` button wipes the
C2's mirror** of a node's data as well as the node's own store — the dashboard
no longer shows stale rows after a clear.

---

## Status LEDs

Each headless node drives its onboard WS2812 (GPIO 48 on the DevKitC-1) so you
can read its state in the field with no serial console:

| Colour | WarDriver | WarSniffer | BlueDriver |
|---|---|---|---|
| 🟢 green | scanning, GPS fix | sniffing | scanning |
| 🔵 cyan | scanning, no fix | — | — |
| 🔷 blue | reporting to C2 | reporting to C2 | reporting to C2 |
| 🟣 purple | — | — | GATT enum running |
| 🔴 red | — | recent WIDS alert | — |
| 🟠 amber | scan paused | capture stopped | scan paused |

Set `STATUS_LED_ENABLED false` in a node's `config.h` to disable it. The LED
uses the Arduino-ESP32 core's built-in `neopixelWrite()` — no extra dependency.

---

## HTTP API & data export

All endpoints are served by the coordinator on port 80.

| Method & path | Purpose |
|---|---|
| `GET /` | The dashboard (HTML) |
| `GET /api/data` | Full aggregate snapshot (JSON) — polled by the dashboard |
| `POST /api/cmd` | Queue a control command for a node |
| `GET /api/export/wifi` | WarDriver inventory as CSV |
| `GET /api/export/ble` | BlueDriver inventory as CSV |
| `GET /api/export/sniff` | WarSniffer AP inventory as CSV |
| `POST /ingest` | Node telemetry (see below) |

Each dashboard tab also has an **`EXPORT CSV`** button. Exports are RFC-4180 and
sent with a `Content-Disposition` attachment header, e.g.:

```bash
curl -OJ http://192.168.4.1/api/export/wifi      # -> wifi.csv

# Stop the WarDriver scan from the CLI
curl -X POST http://192.168.4.1/api/cmd \
     -H 'Content-Type: application/json' \
     -d '{"target":"wardriver","cmd":"scan","on":0}'

# Enumerate GATT on a BLE device (addrType 1 = random)
curl -X POST http://192.168.4.1/api/cmd \
     -H 'Content-Type: application/json' \
     -d '{"target":"bluedriver","cmd":"gatt","mac":"AA:BB:CC:DD:EE:FF","addrType":1}'
```

---

## /ingest protocol

All three nodes POST `application/json` to `http://192.168.4.1/ingest`.

**Request envelope:**
```json
{
  "source":    "ESP32-WarDriver | ESP32-WarSniffer | ESP32-BlueDriver",
  "ver":       "1.0.0",
  "linkEpoch": 0,
  "lastCmdId": 0,
  "status":    { "uptime": 0, "heap": 0, "...": "node-specific" },
  "count":     0,
  "devices | aps | alerts | probes": [ ]
}
```

**Response envelope:**
```json
{
  "ok":    1,
  "epoch": 3914820157,
  "commands": [ { "id": 7, "cmd": "scan", "on": 0 } ]
}
```

**Command grammar** (entries in the response `commands` array):

| `cmd` | Fields | Effect |
|---|---|---|
| `scan` | `on:1/0` | Start / stop scanning |
| `clear` | — | Wipe the node's device store |
| `hop` | `on:1/0` | WarSniffer: channel hopping on/off |
| `config` | `on:<ch>` | WarSniffer: lock to a specific channel |
| `config` | `activeScan:1/0` | BlueDriver: active vs passive BLE scan |
| `gatt` | `mac:"AA:..", addrType:0/1` | BlueDriver: connect + enumerate GATT (~8 s) |

Commands carry a monotonic `id`. A node acks by echoing its highest applied id
as `lastCmdId`; the coordinator then drops acked commands from the queue. The
`linkEpoch` / `epoch` handshake gives **exactly-once delivery across a reboot of
either board** — a fresh epoch resets the node's ack counter so stale
post-reboot acks can't silently drop new commands. The C2 command queue carries
the `gatt` target `mac` + `addrType` through to the node.

---

## Project layout

```
ESP32-Net/
├── c2-esp32s2/          Coordinator (SoftAP, dashboard, /ingest, command relay)
│   ├── src/
│   │   ├── main.cpp     HTTP server, aggregate store, command queue
│   │   ├── web_ui.h     Single-page dashboard (PROGMEM)
│   │   └── config.h     AP creds, store caps, timeouts
│   ├── platformio.ini
│   └── partitions.csv
├── wardriver-node/      WiFi survey + GPS + WigleWifi CSV
├── warsniffer-node/     Passive 802.11 monitor + WIDS + probe harvest
├── bluedriver-node/     BLE scanner + GATT enumeration
├── docs/
│   └── esp32-net.7      Project man page (section 7)
└── README.md
```

---

## Manual page

A groff man page ships in [`docs/esp32-net.7`](docs/esp32-net.7).

```bash
# View it in place
man ./docs/esp32-net.7

# Install it system-wide (Linux)
sudo cp docs/esp32-net.7 /usr/local/share/man/man7/
sudo mandb
man 7 esp32-net
```

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Node shows **OFFLINE** | Wrong `C2_SSID`/`C2_PASSWORD`, C2 not flashed/powered, or out of range. Check the node's serial console. |
| Dashboard won't load | Confirm you joined `ESP32-NET`; try `http://192.168.4.1/` directly if mDNS fails. |
| WarDriver GPS never fixes | Needs clear sky view; verify TX→RX/RX→TX wiring and `GPS_BAUD`. LED stays cyan until a fix. |
| `/wigle.csv` is empty | Rows are only logged after a GPS fix. No fix = no rows by design. |
| GATT enumeration fails | Device may require bonding, reject the connection, or use a different `addrType`. The error appears in the dashboard GATT panel. |
| BLE scan rate seems low | Expected: BLE shares the 2.4 GHz radio with WiFi via time-division coexistence. |
| Out-of-memory / resets on C2 | Lower the `MAX_*` store caps in `c2-esp32s2/src/config.h`. |

---

## Security & legal

This toolkit is for **authorized testing only**. Operate it solely on networks
and devices you own or have explicit written authorization to assess. Passive
802.11 monitoring, active WiFi/BLE scanning, probe-request collection, and GATT
enumeration may be regulated or prohibited in your jurisdiction — **you are
responsible for compliance**. Enable channel 14 or any transmit-related option
only where legally permitted.

By design, ESP32-Net does not send deauthentication or injection frames, does
not operate a rogue access point, and does not store raw packet payloads or WPA
handshakes (EAPOL frames are counted, never captured). The SoftAP is
WPA2-protected; **change the default credentials before use**.
