// ===========================================================================
//  ESP32-BlueDriver node  —  main.cpp   (ESP32-S3-DevKitC-1 N16R8)
//
//  Continuous BLE advertisement scanner + optional GATT enumerator for
//  authorized penetration testing. WiFi STA connects to the C2 SoftAP and
//  POSTs device inventory + status to /ingest every REPORT_INTERVAL_MS.
//
//  Architecture:
//    Core 0 — NimBLE host task (BLE controller + coexistence arbiter)
//    Core 1 — Arduino loop() — WiFi STA, HTTPClient POST, command dispatch
//
//  BLE and WiFi coexist via ESP32-S3 software coexistence (time-division on
//  the shared 2.4 GHz radio). Scan rate drops ~50% while WiFi is active,
//  which is acceptable for a continuous passive/active BLE survey.
//
//  Commands received from C2 (via /ingest response):
//    scan   on:1/0      — start/stop scanning
//    clear              — wipe device store
//    config activeScan  — toggle active/passive scan (stops + restarts scan)
//    gatt   mac,addrType — connect + enumerate GATT services/chars (~8 s)
//
//  ESP32-S3 = BLE 5.0 ONLY. No Bluetooth Classic. Hardware limit.
//  AUTHORIZED TESTING ONLY.
// ===========================================================================
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <NimBLEDevice.h>
#include "config.h"

// ---------------------------------------------------------------------------
//  Device store
// ---------------------------------------------------------------------------
struct BLEEntry {
  char     mac[18]     = {0};   // "AA:BB:CC:DD:EE:FF"
  char     name[33]    = {0};
  int8_t   rssiBest    = -128;
  int8_t   rssiLast    = -128;
  uint16_t hits        = 0;
  char     addrType[8] = {0};   // "public" / "random"
  char     vendor[24]  = {0};
  char     services[80]= {0};   // comma-sep UUID shorts, e.g. "180D,180F"
  char     mfgId[6]    = {0};   // company ID hex, e.g. "004C" (Apple)
  uint32_t firstMs     = 0;
  bool     uploaded    = false;
  bool     used        = false;
};

static BLEEntry g_devs[MAX_BLE_DEVS];
static int      g_devN      = 0;
static uint32_t g_newCount  = 0;
static bool     g_scanning  = true;
static bool     g_activeScan = DEFAULT_ACTIVE_SCAN;

// Mutex protecting the device store — written from NimBLE task (core 0),
// read from main loop (core 1).
static SemaphoreHandle_t g_storeMtx = nullptr;

// C2 link state (epoch + monotonic ack, per the /ingest protocol)
static uint32_t g_linkEpoch = 0;
static uint32_t g_lastCmdId = 0;
static uint32_t g_bootMs    = 0;

// Pending GATT job (filled by applyCommands, consumed by main loop)
struct GattJob { bool pending; char mac[18]; uint8_t addrType; };
static GattJob g_gattJob = {false, {0}, 0};

// GATT result to include in the next POST (cleared after one send)
static String g_gattResult = "";
static bool   g_gattResultReady = false;

// ---------------------------------------------------------------------------
//  Vendor OUI hint (public addresses only; random addresses are flagged)
// ---------------------------------------------------------------------------
static void vendorHint(const char* macStr, bool isRandom, char* out, size_t n) {
  if (isRandom) { strncpy(out, "Random", n - 1); out[n - 1] = 0; return; }
  unsigned b0 = 0, b1 = 0, b2 = 0;
  sscanf(macStr, "%02x:%02x:%02x", &b0, &b1, &b2);
  uint32_t oui = (b0 << 16) | (b1 << 8) | b2;
  struct { uint32_t oui; const char* name; } tbl[] = {
    {0x001A11,"Google"},   {0x3C5AB4,"Google"},
    {0x001BDC,"Apple"},    {0x000A95,"Apple"},    {0xD0817A,"Apple"},
    {0xAC1729,"Apple"},    {0x7C04D0,"Apple"},
    {0xB827EB,"Raspberry Pi"}, {0xDCA632,"Raspberry Pi"},
    {0x001BD2,"Samsung"},  {0xF4F5DB,"Samsung"},
    {0x00156D,"Ubiquiti"}, {0x0025CA,"Cisco"},
    {0x00004C,"Tile"},
  };
  for (auto& t : tbl)
    if (t.oui == oui) { strncpy(out, t.name, n - 1); out[n - 1] = 0; return; }
  out[0] = 0;
}

// ---------------------------------------------------------------------------
//  Device store access
// ---------------------------------------------------------------------------
static void storeLock()   { xSemaphoreTake(g_storeMtx, portMAX_DELAY); }
static void storeUnlock() { xSemaphoreGive(g_storeMtx); }

// Returns index of existing entry with this MAC, or -1 if not found.
// Caller must hold storeLock.
static int findDev(const char* mac) {
  for (int i = 0; i < g_devN; i++)
    if (g_devs[i].used && !strcasecmp(g_devs[i].mac, mac)) return i;
  return -1;
}

// Adds a new slot or returns -1 if the store is full. Caller holds storeLock.
static int addDev(const char* mac) {
  if (g_devN >= MAX_BLE_DEVS) return -1;
  int idx = g_devN++;
  memset(&g_devs[idx], 0, sizeof(BLEEntry));
  g_devs[idx].used     = true;
  g_devs[idx].rssiBest = -128;
  strncpy(g_devs[idx].mac, mac, sizeof(g_devs[idx].mac) - 1);
  return idx;
}

static void clearStore() {
  storeLock();
  for (int i = 0; i < g_devN; i++) memset(&g_devs[i], 0, sizeof(BLEEntry));
  g_devN     = 0;
  g_newCount = 0;
  storeUnlock();
}

// ---------------------------------------------------------------------------
//  NimBLE v2.x scan callback  (runs on core 0, NimBLE host task)
// ---------------------------------------------------------------------------
class ScanCB : public NimBLEScanCallbacks {
public:
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (!g_scanning) return;

    // Normalise MAC to uppercase "AA:BB:CC:DD:EE:FF"
    std::string rawMac = d->getAddress().toString();
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             (uint8_t)rawMac[0], (uint8_t)rawMac[3], (uint8_t)rawMac[6],
             (uint8_t)rawMac[9], (uint8_t)rawMac[12],(uint8_t)rawMac[15]);
    // Parse hex from string instead — rawMac is "aa:bb:cc:dd:ee:ff"
    unsigned a,b,c,dd,m4,f;
    if (sscanf(rawMac.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
               &a,&b,&c,&dd,&m4,&f) == 6) {
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",a,b,c,dd,m4,f);
    }

    int8_t rssi = (int8_t) d->getRSSI();
    bool   isRandom = (d->getAddress().getType() != BLE_ADDR_PUBLIC);

    storeLock();
    int idx = findDev(mac);
    bool isNew = (idx < 0);
    if (isNew) {
      idx = addDev(mac);
      if (idx < 0) { storeUnlock(); return; }   // store full
      g_newCount++;
      g_devs[idx].firstMs = millis();
      strncpy(g_devs[idx].addrType, isRandom ? "random" : "public",
              sizeof(g_devs[idx].addrType) - 1);
      vendorHint(mac, isRandom, g_devs[idx].vendor, sizeof(g_devs[idx].vendor));
    }

    BLEEntry& e = g_devs[idx];
    e.rssiLast = rssi;
    if (rssi > e.rssiBest) e.rssiBest = rssi;
    e.hits++;

    // Name (prefer longer / non-empty)
    if (d->haveName()) {
      std::string nm = d->getName();
      if (nm.size() > strlen(e.name))
        strncpy(e.name, nm.c_str(), sizeof(e.name) - 1);
    }

    // Advertised service UUIDs (comma-separated, capped)
    if (isNew) {
      size_t uuidCnt = d->getServiceUUIDCount();
      size_t written = 0;
      for (size_t i = 0; i < uuidCnt && written + 6 < sizeof(e.services); i++) {
        if (i > 0) { e.services[written++] = ','; }
        std::string us = d->getServiceUUID(i).toString();
        // Trim to short form if standard 128-bit UUID (128-bit = 36 chars)
        // Short UUID is 4 hex chars, long is 36.
        const char* us_c = us.c_str();
        size_t ul = strlen(us_c);
        size_t remain = sizeof(e.services) - written - 1;
        size_t copy   = ul < remain ? ul : remain;
        memcpy(e.services + written, us_c, copy);
        written += copy;
        e.services[written] = 0;
      }
    }

    // Manufacturer company ID (first 2 bytes of mfg data, little-endian)
    if (isNew && d->haveManufacturerData()) {
      std::string mfg = d->getManufacturerData();
      if (mfg.size() >= 2) {
        // bytes 0 and 1 are the company ID (little-endian)
        snprintf(e.mfgId, sizeof(e.mfgId), "%02X%02X",
                 (uint8_t)mfg[1], (uint8_t)mfg[0]);   // big-endian display
      }
    }
    storeUnlock();
  }

  // Restart continuous scan when it ends (it ends only if a duration was set;
  // with duration=0 it runs forever, but handle the callback anyway).
  void onScanEnd(const NimBLEScanResults& /*results*/, int /*reason*/) override {
    if (g_scanning) {
      NimBLEDevice::getScan()->start(0, false);
    }
  }
};

static ScanCB g_scanCB;

// ---------------------------------------------------------------------------
//  Scan control
// ---------------------------------------------------------------------------
static NimBLEScan* pScan = nullptr;

static void startScan() {
  if (!pScan) return;
  pScan->setActiveScan(g_activeScan);
  pScan->setInterval(SCAN_INTERVAL);
  pScan->setWindow(SCAN_WINDOW);
  pScan->setMaxResults(0);          // callback-only, no internal result list
  if (!pScan->isScanning())
    pScan->start(0, false);         // 0 = scan forever, false = non-blocking
}

static void stopScan() {
  if (pScan && pScan->isScanning()) pScan->stop();
}

static void restartScan() {
  stopScan();
  delay(50);
  startScan();
}

// ---------------------------------------------------------------------------
//  GATT enumeration (authorized testing — reads service/char UUIDs only)
// ---------------------------------------------------------------------------
static String doGatt(const char* macStr, uint8_t addrType) {
  // Stop BLE scan while we connect (can't scan + connect simultaneously)
  stopScan();
  delay(100);

  String result = "";
  NimBLEAddress addr(macStr, addrType);
  NimBLEClient* pClient = NimBLEDevice::createClient();
  if (!pClient) { startScan(); return "{\"err\":\"createClient failed\"}"; }

  pClient->setConnectionParams(12, 12, 0, 200);

  if (!pClient->connect(addr)) {
    NimBLEDevice::deleteClient(pClient);
    startScan();
    return "{\"err\":\"connect failed\"}";
  }

  // Enumerate services and characteristics
  JsonDocument doc;
  doc["mac"]      = macStr;
  doc["addrType"] = addrType;
  JsonArray svcs = doc["services"].to<JsonArray>();

  // getServices(true) refreshes from peer; returns a const reference in NimBLE v2.x
  const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
  for (NimBLERemoteService* svc : services) {
    JsonObject so = svcs.add<JsonObject>();
    so["uuid"] = svc->getUUID().toString().c_str();
    JsonArray chars = so["chars"].to<JsonArray>();

    // getCharacteristics(true) also returns a const reference in NimBLE v2.x
    const std::vector<NimBLERemoteCharacteristic*>& chrs = svc->getCharacteristics(true);
    for (NimBLERemoteCharacteristic* ch : chrs) {
      JsonObject co = chars.add<JsonObject>();
      co["uuid"] = ch->getUUID().toString().c_str();

      // NimBLE v2.x removed getProperties(); derive from individual capability flags.
      // Bit positions follow the BLE spec (GATT Characteristic Properties).
      uint8_t props = 0;
      if (ch->canBroadcast())        props |= 0x01;
      if (ch->canRead())             props |= 0x02;
      if (ch->canWriteNoResponse())  props |= 0x04;
      if (ch->canWrite())            props |= 0x08;
      if (ch->canNotify())           props |= 0x10;
      if (ch->canIndicate())         props |= 0x20;
      co["props"] = props;

      // Read value only if readable (best-effort; skip on error)
      if (ch->canRead()) {
        NimBLEAttValue val = ch->readValue();
        if (val.size() > 0 && val.size() <= 32) {
          String hex = "";
          for (size_t vi = 0; vi < val.size(); vi++) {
            char hb[3]; snprintf(hb, sizeof(hb), "%02X", (uint8_t)val[vi]);
            hex += hb;
          }
          co["val"] = hex.c_str();
        }
      }
    }
  }

  pClient->disconnect();
  delay(50);
  NimBLEDevice::deleteClient(pClient);

  serializeJson(doc, result);
  startScan();
  return result;
}

// ---------------------------------------------------------------------------
//  Command dispatch (applied after a successful POST)
// ---------------------------------------------------------------------------
static void applyCommands(JsonArrayConst cmds) {
  for (JsonObjectConst c : cmds) {
    uint32_t id = c["id"] | 0;
    if (id <= g_lastCmdId) continue;

    const char* cmd = c["cmd"] | "";
    bool hasOn = c["on"].is<int>();
    int  on    = hasOn ? (int)c["on"] : -1;

    if (!strcmp(cmd, "scan")) {
      bool newState = hasOn ? (on != 0) : !g_scanning;
      if (newState != g_scanning) {
        g_scanning = newState;
        if (g_scanning) startScan();
        else            stopScan();
      }
    } else if (!strcmp(cmd, "clear")) {
      clearStore();
    } else if (!strcmp(cmd, "config")) {
      // config activeScan:1/0
      bool want = c["activeScan"].is<int>() ? (int)c["activeScan"] != 0 : g_activeScan;
      if (want != g_activeScan) {
        g_activeScan = want;
        if (g_scanning) restartScan();   // mode change requires restart
      }
    } else if (!strcmp(cmd, "gatt")) {
      // gatt mac:"aa:bb:..", addrType:0|1
      // Queue it; the main loop will run it (needs ~8 s, not safe in-line here)
      if (!g_gattJob.pending && c["mac"].is<const char*>()) {
        strncpy(g_gattJob.mac, c["mac"] | "", sizeof(g_gattJob.mac) - 1);
        g_gattJob.addrType = c["addrType"] | 0;
        g_gattJob.pending  = true;
      }
    }
    g_lastCmdId = id;
  }
}

// ---------------------------------------------------------------------------
//  WiFi management
// ---------------------------------------------------------------------------
static bool ensureWiFi() {
  if (WiFi.status() == WL_CONNECTED) return true;
  WiFi.mode(WIFI_STA);
  WiFi.begin(C2_SSID, C2_PASSWORD);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < WIFI_CONNECT_MS)
    delay(100);
  if (WiFi.status() == WL_CONNECTED)
    Serial.printf("[BD] WiFi connected  ip=%s\n", WiFi.localIP().toString().c_str());
  else
    Serial.println("[BD] WiFi connect timeout");
  return WiFi.status() == WL_CONNECTED;
}

// ---------------------------------------------------------------------------
//  Report cycle: build JSON snapshot and POST to C2
// ---------------------------------------------------------------------------
static void reportToC2() {
  if (!ensureWiFi()) return;

  JsonDocument doc;
  doc["source"]    = SRC_NAME;
  doc["ver"]       = FW_VERSION;
  doc["linkEpoch"] = g_linkEpoch;
  doc["lastCmdId"] = g_lastCmdId;

  // Status
  JsonObject st = doc["status"].to<JsonObject>();
  storeLock();
  int  totalDevs = g_devN;
  uint32_t newDev  = g_newCount;
  storeUnlock();
  st["scanning"]   = g_scanning ? 1 : 0;
  st["devices"]    = totalDevs;
  st["newDevices"] = newDev;
  st["uptime"]     = (millis() - g_bootMs) / 1000;
  st["heap"]       = ESP.getFreeHeap();
  st["psram"]      = ESP.getFreePsram();
  st["activeScan"] = g_activeScan ? 1 : 0;

  // Attach GATT result if one is ready
  if (g_gattResultReady && g_gattResult.length() > 0) {
    JsonDocument gr;
    if (!deserializeJson(gr, g_gattResult)) doc["gattResult"] = gr.as<JsonObject>();
    g_gattResult = "";
    g_gattResultReady = false;
  }

  // Device batch: up to UPLINK_BATCH_MAX unsent entries (FIFO order)
  storeLock();
  JsonArray devArr = doc["devices"].to<JsonArray>();
  int sent = 0;
  for (int i = 0; i < g_devN && sent < UPLINK_BATCH_MAX; i++) {
    if (g_devs[i].uploaded || !g_devs[i].used) continue;
    BLEEntry& e = g_devs[i];
    JsonObject d = devArr.add<JsonObject>();
    d["mac"]      = e.mac;
    if (e.name[0])     d["name"]     = e.name;
    if (e.addrType[0]) d["addrType"] = e.addrType;
    if (e.vendor[0])   d["vendor"]   = e.vendor;
    if (e.services[0]) d["services"] = e.services;
    if (e.mfgId[0])    d["mfgId"]    = e.mfgId;
    d["rssiBest"] = e.rssiBest;
    d["count"]    = e.hits;
    d["first"]    = e.firstMs / 1000;
    sent++;
  }
  doc["count"] = sent;
  storeUnlock();

  String body;
  serializeJson(doc, body);

  // POST
  HTTPClient http;
  WiFiClient client;
  String url = String("http://") + C2_HOST + C2_INGEST_PATH;
  if (!http.begin(client, url)) return;
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);

  if (code == 200) {
    String resp = http.getString();
    JsonDocument rd;
    if (!deserializeJson(rd, resp)) {
      // Epoch / ack
      uint32_t newEpoch = rd["epoch"] | 0;
      if (newEpoch && newEpoch != g_linkEpoch) {
        g_linkEpoch  = newEpoch;
        g_lastCmdId  = 0;           // remote rebooted; reset ack counter
      }
      // Mark uploaded only if POST was acked
      storeLock();
      int marked = 0;
      for (int i = 0; i < g_devN && marked < sent; i++) {
        if (!g_devs[i].uploaded && g_devs[i].used) {
          g_devs[i].uploaded = true;
          marked++;
        }
      }
      // Reset newCount by counting actual unsent
      uint32_t remaining = 0;
      for (int i = 0; i < g_devN; i++) if (!g_devs[i].uploaded) remaining++;
      g_newCount = remaining;
      storeUnlock();

      applyCommands(rd["commands"].as<JsonArrayConst>());
    }
  }
  http.end();
}

// ---------------------------------------------------------------------------
//  Setup
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.printf("\nESP32-BlueDriver node booting  ver=%s\n", FW_VERSION);
  g_bootMs = millis();

  g_storeMtx = xSemaphoreCreateMutex();

  // NimBLE — init before WiFi so the coexistence stack is ready
  NimBLEDevice::init("");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);   // max RX sensitivity for scanning

  pScan = NimBLEDevice::getScan();
  pScan->setScanCallbacks(&g_scanCB, true);  // true = wantDuplicates (for RSSI)
  startScan();

  // WiFi (coexistence arbiter handles sharing with BLE automatically)
  WiFi.persistent(false);
  ensureWiFi();

  Serial.printf("[BD] BLE scan started (%s)  WiFi=%s\n",
                g_activeScan ? "active" : "passive",
                WiFi.isConnected() ? "UP" : "pending");
}

// ---------------------------------------------------------------------------
//  Loop  (runs on core 1; NimBLE host task runs on core 0)
// ---------------------------------------------------------------------------
void loop() {
  static uint32_t tReport = 0;
  static uint32_t tHb     = 0;

  // ---- Periodic report ---------------------------------------------------
  if (millis() - tReport >= REPORT_INTERVAL_MS) {
    tReport = millis();
    reportToC2();
  }

  // ---- Pending GATT job --------------------------------------------------
  if (g_gattJob.pending) {
    g_gattJob.pending = false;
    Serial.printf("[BD] GATT enum -> %s (type %u)\n", g_gattJob.mac, g_gattJob.addrType);
    String res = doGatt(g_gattJob.mac, g_gattJob.addrType);
    Serial.printf("[BD] GATT result: %s\n", res.c_str());
    g_gattResult      = res;
    g_gattResultReady = true;
    // Result ships in the very next reportToC2()
    tReport = 0;   // force an immediate report cycle
  }

  // ---- Heartbeat ---------------------------------------------------------
  if (millis() - tHb >= 3000) {
    tHb = millis();
    storeLock();
    int n = g_devN; uint32_t nw = g_newCount;
    storeUnlock();
    Serial.printf("[BD] scan=%d active=%d devs=%d new=%lu heap=%u psram=%u\n",
                  g_scanning, g_activeScan, n, (unsigned long)nw,
                  (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getFreePsram());
  }

  delay(20);
}
