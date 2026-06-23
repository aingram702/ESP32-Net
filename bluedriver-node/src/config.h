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

// ---- Device store ----------------------------------------------------------
#define MAX_BLE_DEVS   300

// ---- BLE scan defaults (tunable via "config" commands from the C2) ---------
#define DEFAULT_ACTIVE_SCAN  true  // active scan = send scan-request, get more data
                                   // passive scan = observe only (stealthier)
// NimBLE scan parameters (units: 0.625 ms per unit)
#define SCAN_INTERVAL   80         //  80 × 0.625 = 50 ms
#define SCAN_WINDOW     80         //  same as interval = 100% duty-cycle while timeslot is ours

// ---- Onboard WS2812 status LED (DevKitC-1, GPIO48) -------------------------
#define STATUS_LED_PIN  48
#define LED_BRIGHTNESS  24
