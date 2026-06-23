// ===========================================================================
//  config.h  —  ESP32-WarDriver node (headless, reports to the C2)
//
//  WiFi survey (active scan) + NEO-6M GPS + WigleWifi CSV logging to LittleFS +
//  defensive rogue-AP / surveillance-camera flagging. Joins the C2 SoftAP and
//  POSTs newly-seen networks + a GPS-stamped status to /ingest on a timer.
//
//  AUTHORIZED TESTING ONLY. Passive recon (scan-only; nothing is transmitted at
//  the 802.11 layer beyond normal active-scan probe requests).
// ===========================================================================
#pragma once
#include <Arduino.h>

// ---- C2 uplink -------------------------------------------------------------
#define C2_SSID        "ESP32-NET"
#define C2_PASSWORD    "dropnetc2!"
#define C2_HOST        "192.168.4.1"
#define C2_INGEST_PATH "/ingest"
#define SRC_NAME       "ESP32-WarDriver"
#define FW_VERSION     "1.0.0"

// ---- Scan / report cadence -------------------------------------------------
#define SCAN_INTERVAL_MS   6000     // run a WiFi.scanNetworks() this often
#define REPORT_INTERVAL_MS 5000     // POST queued new networks + status
#define WIFI_CONNECT_MS    6000     // C2 association timeout per report
#define UPLINK_BATCH_MAX   40       // networks per POST

// ---- Inventory + logging ---------------------------------------------------
#define MAX_APS            300
#define LOG_TO_FLASH       true
#define WIFI_LOG_PATH      "/wigle.csv"
#define LOG_MAX_BYTES      (6UL * 1024UL * 1024UL)

// ---- GPS (NEO-6M on a hardware UART) ---------------------------------------
// GPS TX -> ESP RX_PIN, GPS RX -> ESP TX_PIN, 3V3, GND. Pick free S3 GPIOs.
#define GPS_ENABLED        true
#define GPS_RX_PIN         18       // ESP RX  (from GPS TX)
#define GPS_TX_PIN         17       // ESP TX  (to GPS RX)
#define GPS_BAUD           9600

// ---- Onboard WS2812 status LED (DevKitC-1, GPIO48) -------------------------
// green=scanning+GPS fix, cyan=scanning/no fix, blue=reporting, amber=scan off.
#define STATUS_LED_ENABLED true
#define STATUS_LED_PIN     48
#define LED_BRIGHTNESS     24      // 0-255 master brightness scale
