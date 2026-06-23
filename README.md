# ESP32-Net Toolkit

Four-device wireless reconnaissance and WIDS toolkit for authorized homelab
and pentest engagements.  
**Passive recon + defensive monitoring only. Run this only on networks you own
or have explicit written authorization to test.**

---

## Devices at a glance

| Directory | Hardware | Role |
|---|---|---|
| `c2-esp32s2/` | ESP32-S2 (Flipper WiFi Dev Board) | SoftAP + unified web dashboard |
| `wardriver-node/` | ESP32-S3-DevKitC-1 N16R8 | WiFi survey + GPS + WigleWifi CSV log |
| `warsniffer-node/` | ESP32-S3-DevKitC-1 N16R8 | Passive 802.11 monitor + WIDS |
| `bluedriver-node/` | ESP32-S3-DevKitC-1 N16R8 | Continuous BLE scanner + GATT enum |

The three S3 nodes are headless — no display, no local web UI.  They join
the C2's SoftAP (`ESP32-NET`) and POST JSON metadata to `/ingest` on a timer.
The C2 aggregates everything and serves the four-tab dashboard at
`http://192.168.4.1/`.

> **ESP32-S3 = BLE 5.0 only.** No Bluetooth Classic (BR/EDR). Hardware limit of
> the S3 silicon. Only the original ESP32 (non-S/C) has Classic.

---

## Credentials (change before field use)

| Setting | Default |
|---|---|
| C2 AP SSID | `ESP32-NET` |
| C2 AP password | `dropnetc2!` |
| C2 dashboard URL | `http://192.168.4.1/` |

Edit the `#define` values in each node's `src/config.h` before flashing.

---

## Flashing

Each directory is an independent PlatformIO project.

```bash
# Flash the C2 (connect the Flipper WiFi Dev Board via USB)
cd c2-esp32s2
pio run -t upload

# Flash the WarDriver node
cd ../wardriver-node
pio run -t upload

# Flash the WarSniffer node
cd ../warsniffer-node
pio run -t upload

# Flash the BlueDriver node
cd ../bluedriver-node
pio run -t upload

# Monitor any node's serial console (115200)
pio device monitor
```

If you're using PlatformIO from the CLI, run `pio pkg install` inside each
project directory first to pull dependencies.

---

## WarDriver — GPS wiring (NEO-6M)

| NEO-6M pin | ESP32-S3 GPIO |
|---|---|
| TX (GPS output) | GPIO 18 (configured as RX in firmware) |
| RX (GPS input) | GPIO 17 (configured as TX in firmware) |
| VCC | 3.3 V |
| GND | GND |

Change `GPS_RX_PIN` / `GPS_TX_PIN` in `wardriver-node/src/config.h` if you
use different GPIOs.  
WigleWifi CSV is written to `/wigle.csv` on LittleFS. Flash the filesystem
(`pio run -t uploadfs`) if you want to pre-populate the data partition.

---

## Dashboard tabs

| Tab | Shows |
|---|---|
| **OVERVIEW** | All-node status, aggregate counts, online/offline dots |
| **WARDRIVER** | Scanned AP table (BSSID, SSID, channel, encryption, RSSI, vendor, threat flags), GPS fix |
| **WARSNIFFER** | Frame counters (total / mgmt / ctrl / data / beacon / probe / deauth / EAPOL), AP inventory with client counts, WIDS alert log |
| **BLUEDRIVER** | BLE device table (address, name, addr type, vendor, RSSI, hit count, advertised service UUIDs) |

The dashboard polls `/api/data` every 2 seconds. Toolbar buttons queue
control commands that are delivered to nodes in the next `/ingest` response.

---

## /ingest protocol summary

All three nodes POST `application/json` to `http://192.168.4.1/ingest`.

**Request envelope:**
```json
{
  "source":    "ESP32-WarDriver|ESP32-WarSniffer|ESP32-BlueDriver",
  "ver":       "1.0.0",
  "linkEpoch": 0,
  "lastCmdId": 0,
  "status":    { ... },
  "count":     N,
  "devices|aps|alerts": [ ... ]
}
```

**Response envelope:**
```json
{
  "ok":    1,
  "epoch": 3914820157,
  "commands": [
    { "id": 7, "cmd": "scan", "on": 0 }
  ]
}
```

**Command grammar:**

| `cmd` | Fields | Effect |
|---|---|---|
| `scan` | `on:1/0` | Start / stop scanning |
| `clear` | — | Wipe node's device store |
| `config` | `activeScan:1/0` | BlueDriver: toggle active/passive BLE scan |
| `config` | `on:<ch>` | WarSniffer: lock to a specific channel |
| `hop` | `on:1/0` | WarSniffer: enable/disable channel hopping |
| `gatt` | `mac,addrType` | BlueDriver: connect + enumerate GATT (~8 s) |

Commands use monotonic `id`s; nodes ack via `lastCmdId` in subsequent
requests. The `linkEpoch` / `epoch` mechanism ensures exactly-once delivery
across reboots of either board.

---

## WarSniffer — what it does and does not do

**Does:**
- Channel-hop 1–13 in promiscuous mode
- Count frame types (mgmt / ctrl / data / beacon / probe / deauth / EAPOL)
- Build AP + client-count inventory from beacon and data frames
- Raise WIDS alerts: deauth flood (>20/s), beacon flood (>40 unique SSIDs/s),
  evil-twin (same SSID, new BSSID, ≥25 dBm RSSI delta)
- Report metadata only (no raw packet payloads, no handshakes)

**Does not:**
- Transmit anything on the monitored band (no deauth, no injection, no rogue AP)
- Store EAPOL/WPA handshake payloads (EAPOL frames are counted only)
- Write PCAPs to flash

---

## BlueDriver — what it does and does not do

**Does:**
- Continuous passive or active BLE advertisement scan (NimBLE v2.x)
- Per-device inventory: MAC, name, address type, vendor OUI, advertised service
  UUIDs, manufacturer company ID, best RSSI, hit count
- GATT service/characteristic enumeration on demand (via `gatt` command from C2)
- WiFi + BLE coexistence via the ESP32-S3 hardware arbiter

**Does not:**
- Scan Bluetooth Classic (hardware limitation of the ESP32-S3)
- Transmit BLE advertisements or connect to devices without a `gatt` command
- Store or exfiltrate characteristic values beyond the immediate POST to C2
