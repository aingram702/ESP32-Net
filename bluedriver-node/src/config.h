// ===========================================================================
//  config.h  —  ESP32-BlueDriver node (headless, reports to the C2)
//
//  Continuous BLE advertisement scanner. Joins the C2 SoftAP over WiFi and
//  POSTs device inventory + status to /ingest every REPORT_INTERVAL_MS.
//  BLE and WiFi coexist via the ESP32-S3's software coexistence arbiter
//  (time-division on the shared 2.4 GHz radio); no manual interleaving needed.
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

// ---- Scan / report cadence ------------------------------------------------
#define REPORT_INTERVAL_MS  4000   // POST to C2 this often
#define WIFI_CONNECT_MS     8000   // STA connect timeout at startup / reconnect
#define UPLINK_BATCH_MAX    40     // max devices per POST (newest unsent first)

// ---- Reliability / self-healing watchdog -----------------------------------
// BLE and WiFi share one radio via software coexistence. These thresholds drive
// automatic recovery so the BLE scan or the C2 link don't silently die.
#define SCAN_WATCHDOG_MS    8000   // g_scanning but not actually scanning -> restart
#define WIFI_WATCHDOG_MS    45000  // no successful C2 report this long -> reset WiFi
#define WIFI_REBOOT_MS      180000 // no successful C2 report this long -> reboot

// ---- Device store ----------------------------------------------------------
#define MAX_BLE_DEVS   300

// ---- BLE scan defaults (tunable via "config" commands from the C2) ---------
#define DEFAULT_ACTIVE_SCAN  true  // active scan = send scan-request, get more data
                                   // passive scan = observe only (stealthier)
// NimBLE scan parameters (units: 0.625 ms per unit). The scan WINDOW must be
// shorter than the INTERVAL so the coexistence arbiter has radio time to keep
// the WiFi link to the C2 alive — a 100%% duty cycle (window==interval) starves
// WiFi and the node drops off after a few minutes.
#define SCAN_INTERVAL   160        // 160 × 0.625 = 100 ms (scan period)
#define SCAN_WINDOW     80         //  80 × 0.625 =  50 ms  (50%% duty; rest for WiFi)

// ---- Onboard WS2812 status LED (DevKitC-1, GPIO48) -------------------------
// green=scanning, blue=reporting, purple=GATT enum in progress, amber=scan off.
#define STATUS_LED_ENABLED true
#define STATUS_LED_PIN  48
#define LED_BRIGHTNESS  24         // 0-255 master brightness scale
