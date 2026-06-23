// ===========================================================================
//  config.h  —  Compile-time configuration for the ESP32-Net C2 coordinator
// ===========================================================================
#pragma once

// ---- SoftAP the three scan nodes (and your phone/laptop) join --------------
// Browse to http://192.168.4.1/ for the dashboard once connected.
#define AP_SSID        "ESP32-NET"
#define AP_PASSWORD    "dropnetc2!"   // >= 8 chars (WPA2), or "" for open AP
#define AP_CHANNEL     6
#define AP_MAX_CLIENTS 8              // 3 nodes + a few dashboard clients

// ---- HTTP ingest -----------------------------------------------------------
#define INGEST_PATH    "/ingest"      // nodes POST their JSON here
#define MAX_BODY_BYTES 9000           // reject oversized POST bodies

// ---- In-RAM store caps (keep modest: the S2 has limited heap) --------------
#define MAX_WIFI_APS    128           // WarDriver inventory
#define MAX_BLE_DEVS    128           // BlueDriver inventory
#define MAX_SNIFF_APS    96           // WarSniffer AP inventory
#define MAX_ALERTS       48           // WarSniffer WIDS alerts (rolling)
#define MAX_CMDS_PER_NODE 8           // queued control commands per node

// A node is shown "offline" if it hasn't POSTed within this window.
#define NODE_TIMEOUT_MS  15000

// ---- Firmware identity -----------------------------------------------------
#define FW_NAME    "ESP32-Net C2"
#define FW_VERSION "1.0.0"

// ---- Canonical node source identifiers (must match each node's `source`) ---
#define SRC_WARDRIVER  "ESP32-WarDriver"
#define SRC_WARSNIFFER "ESP32-WarSniffer"
#define SRC_BLUEDRIVER "ESP32-BlueDriver"
