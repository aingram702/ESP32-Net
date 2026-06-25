// ===========================================================================
//  config.h  —  ESP32-BlueDriver node (headless, reports to the C2)
//
//  BLE advertisement scanner. Joins the C2 SoftAP over WiFi to POST device
//  inventory. To stay reliable it INTERLEAVES the two radios instead of relying
//  on WiFi/BLE coexistence: scan BLE with WiFi off, then stop the scan, bring
//  WiFi up just long enough to POST, drop it, and resume scanning.
//
//  ESP32-S3 = BLE 5.0 ONLY. No Bluetooth Classic (BR/EDR). Hardware limit.
//
//  AUTHORIZED TESTING ONLY.
// ===========================================================================
#pragma once
#include <Arduino.h>

// ---- C2 uplink (join the coordinator's SoftAP) ----------------------------
#define C2_SSID        "ESP32-NET"
#define C2_PASSWORD    "dropnetc2!"
#define C2_HOST        "192.168.4.1"
#define C2_INGEST_PATH "/ingest"
#define SRC_NAME       "ESP32-BlueDriver"
#define FW_VERSION     "1.0.0"

// ---- Scan / report cadence (interleaved: BLE and WiFi never run at once) ----
#define SCAN_PHASE_MS       6000   // scan BLE (WiFi off) this long, then report
#define WIFI_CONNECT_MS     8000   // STA connect timeout per report cycle
#define UPLINK_BATCH_MAX    40     // max devices per POST (newest unsent first)

// ---- Reliability / self-healing watchdog -----------------------------------
#define WIFI_REBOOT_MS      180000 // no successful C2 report this long -> reboot

// ---- Device store ----------------------------------------------------------
#define MAX_BLE_DEVS   300

// ---- BLE scan defaults (tunable via "config" commands from the C2) ---------
#define DEFAULT_ACTIVE_SCAN  true  // active scan = send scan-request, get more data
                                   // passive scan = observe only (stealthier)
// NimBLE scan parameters (units: 0.625 ms per unit). The scan runs with WiFi
// fully off during the scan phase, so a high duty cycle is fine for fast finds.
#define SCAN_INTERVAL   100        // 62.5 ms scan period
#define SCAN_WINDOW     90         // ~90% duty while scanning

// ---- Onboard WS2812 status LED (DevKitC-1, GPIO48) -------------------------
// green=scanning, blue=reporting, purple=GATT enum in progress, amber=scan off.
#define STATUS_LED_ENABLED true
#define STATUS_LED_PIN  48
#define LED_BRIGHTNESS  24         // 0-255 master brightness scale
