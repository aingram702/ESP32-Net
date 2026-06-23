// ===========================================================================
//  config.h  —  ESP32-WarSniffer node (headless, reports to the C2)
//
//  Passive 802.11 monitor + lightweight WIDS. Channel-hops in promiscuous mode,
//  tallies frame types, builds an AP/STA inventory, and raises defensive
//  detections (deauth flood / evil-twin / beacon flood). It transmits NOTHING
//  on the monitored band and stores no packet payloads — only metadata and
//  counters are reported to the C2 over WiFi during its report window.
//
//  AUTHORIZED TESTING ONLY.
// ===========================================================================
#pragma once
#include <Arduino.h>

// ---- C2 uplink (join the coordinator's SoftAP, POST metadata) --------------
#define C2_SSID        "ESP32-NET"
#define C2_PASSWORD    "dropnetc2!"
#define C2_HOST        "192.168.4.1"
#define C2_INGEST_PATH "/ingest"
#define SRC_NAME       "ESP32-WarSniffer"
#define FW_VERSION     "1.0.0"

// ---- Capture / report cadence (interleaved: can't sniff + associate at once)
#define SNIFF_WINDOW_MS   8000     // listen in promiscuous mode for this long...
#define REPORT_BUDGET_MS  6000     // ...then associate to C2, POST, max time
#define WIFI_CONNECT_MS   6000     // STA connect timeout per report cycle

// ---- Channel hopping -------------------------------------------------------
#define CHANNEL_MIN        1
#define CHANNEL_MAX        13      // set 14 only where legally permitted
#define HOP_INTERVAL_MS    250     // dwell per channel while sniffing

// ---- Inventory caps (internal RAM) -----------------------------------------
#define MAX_APS            96      // tracked BSSIDs
#define MAX_STAS           256     // tracked client MACs (for client counts)
#define MAX_ALERTS         24      // alert ring buffer
#define UPLINK_AP_MAX      40      // APs per POST (strongest first)
#define UPLINK_ALERT_MAX   16      // alerts per POST

// ---- WIDS thresholds -------------------------------------------------------
#define DEAUTH_WINDOW_MS       1000
#define DEAUTH_THRESHOLD       20    // deauth/disassoc frames/window -> alert
#define BEACON_FLOOD_WINDOW_MS 1000
#define BEACON_FLOOD_THRESHOLD 40    // unique SSIDs/window -> alert
#define EVIL_TWIN_RSSI_DELTA   25    // dBm jump, same SSID new BSSID -> alert

// ---- Onboard WS2812 status LED (DevKitC-1, GPIO48) -------------------------
#define STATUS_LED_PIN     48
#define LED_BRIGHTNESS     24
