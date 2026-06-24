// ===========================================================================
//  ESP32-WarDriver node  —  main.cpp   (ESP32-S3-DevKitC-1 N16R8)
//
//  WiFi survey via active scan + NEO-6M GPS + WigleWifi CSV logging to LittleFS
//  + defensive rogue-AP / surveillance-camera flagging. Joins the C2 SoftAP and
//  POSTs newly-seen networks (with a GPS stamp) to /ingest on a timer.
//
//  Scan-only: at the 802.11 layer this transmits nothing beyond the standard
//  probe requests that any active WiFi scan emits. No deauth, no injection.
//
//  AUTHORIZED TESTING ONLY.
// ===========================================================================
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <TinyGPSPlus.h>
#include "config.h"

// ---------------------------------------------------------------------------
//  Inventory
// ---------------------------------------------------------------------------
struct ApEntry {
  char     bssid[18] = {0};
  char     ssid[33]  = {0};
  uint8_t  ch        = 0;
  char     enc[10]   = {0};
  int8_t   rssiBest  = -128;
  char     vendor[24]= {0};
  char     flag[20]  = {0};   // "FLOCK CAMERA" / "" ; rogue label
  double   lat = 0, lon = 0;
  bool     hasGps    = false;
  char     firstSeen[20] = {0};
  bool     uploaded  = false;
  bool     logged    = false;
  bool     used      = false;
};
static ApEntry g_aps[MAX_APS];
static int     g_apN = 0;

// ---------------------------------------------------------------------------
//  Status LED (onboard WS2812). neopixelWrite() ships with the Arduino-ESP32
//  core — no extra library dependency.
// ---------------------------------------------------------------------------
static inline void setLed(uint8_t r, uint8_t g, uint8_t b) {
  if (!STATUS_LED_ENABLED) return;
  neopixelWrite(STATUS_LED_PIN,
                (uint16_t)r * LED_BRIGHTNESS / 255,
                (uint16_t)g * LED_BRIGHTNESS / 255,
                (uint16_t)b * LED_BRIGHTNESS / 255);
}

// ---------------------------------------------------------------------------
//  GPS
// ---------------------------------------------------------------------------
static TinyGPSPlus gps;
static HardwareSerial GPSserial(1);

struct GpsSnap { bool valid=false; double lat=0, lon=0; int sats=0; bool timeValid=false;
                 int yr=0,mo=0,dy=0,hh=0,mm=0,ss=0; };
static GpsSnap g_gps;

static void pumpGps() {
  while (GPSserial.available()) gps.encode(GPSserial.read());
  g_gps.valid = gps.location.isValid() && gps.location.age() < 5000;
  if (g_gps.valid) { g_gps.lat = gps.location.lat(); g_gps.lon = gps.location.lng(); }
  g_gps.sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
  if (gps.date.isValid() && gps.time.isValid()) {
    g_gps.timeValid = true;
    g_gps.yr = gps.date.year(); g_gps.mo = gps.date.month(); g_gps.dy = gps.date.day();
    g_gps.hh = gps.time.hour(); g_gps.mm = gps.time.minute(); g_gps.ss = gps.time.second();
  }
}
static void gpsStamp(char* out, size_t n) {
  if (g_gps.timeValid)
    snprintf(out, n, "%04d-%02d-%02d %02d:%02d:%02d",
             g_gps.yr, g_gps.mo, g_gps.dy, g_gps.hh, g_gps.mm, g_gps.ss);
  else out[0] = 0;
}

// ---------------------------------------------------------------------------
//  Helpers: encryption, vendor, threat heuristics
// ---------------------------------------------------------------------------
static const char* encStr(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/3";
    default:                        return "UNK";
  }
}

// Minimal vendor hint: locally-administered (randomized) MACs flagged; a couple
// of well-known OUIs included as examples. Extend the table as needed.
static void vendorHint(const uint8_t* bssid, char* out, size_t n) {
  if (bssid[0] & 0x02) { strncpy(out, "Randomized/Local", n-1); out[n-1]=0; return; }
  uint32_t oui = (bssid[0]<<16) | (bssid[1]<<8) | bssid[2];
  struct { uint32_t oui; const char* name; } tbl[] = {
    {0x001A11, "Google"}, {0x3C5AB4, "Google"}, {0xB827EB, "Raspberry Pi"},
    {0xDC2C6E, "Routerboard"}, {0x00156D, "Ubiquiti"},
  };
  for (auto& t : tbl) if (t.oui == oui) { strncpy(out, t.name, n-1); out[n-1]=0; return; }
  out[0] = 0;
}

// Defensive surveillance-camera / rogue flag. These are HEURISTICS to tune for
// your area — community ALPR-detection projects key off SSID/OUI patterns.
// Returns a label or "".
static const char* threatFlag(const char* ssid, const char* enc) {
  static const char* flockPatterns[] = { "Penguin", "FLOCK", "Flock" };
  if (ssid && *ssid)
    for (auto pat : flockPatterns)
      if (strstr(ssid, pat)) return "FLOCK CAMERA";
  return "";
}

// ---------------------------------------------------------------------------
//  CSV logging (WigleWifi-1.4)
// ---------------------------------------------------------------------------
static bool g_fsOk = false;
static void ensureLogHeader() {
  if (!g_fsOk) return;
  if (LittleFS.exists(WIFI_LOG_PATH)) {
    File f = LittleFS.open(WIFI_LOG_PATH, "r");
    bool empty = (f.size() == 0); f.close();
    if (!empty) return;
  }
  File f = LittleFS.open(WIFI_LOG_PATH, "w");
  if (!f) return;
  f.println("WigleWifi-1.4,appRelease=1.0.0,model=ESP32-S3,release=1.0.0,"
            "device=ESP32-WarDriver,display=,board=esp32-s3-devkitc-1,brand=Espressif");
  f.println("MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,"
            "CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type");
  f.close();
}
static int chanToFreq(int ch) { return (ch >= 1 && ch <= 13) ? 2407 + ch * 5 : (ch == 14 ? 2484 : 0); }
// RFC-4180 CSV field: quote when the value contains a comma, quote or newline,
// doubling any embedded quotes. Prevents an SSID with a comma from shifting
// every downstream column (corrupting the WigleWifi export).
static void csvQuote(const char* s, char* out, size_t n) {
  bool needQuote = false;
  for (const char* p = s; *p; p++) if (*p==',' || *p=='"' || *p=='\n' || *p=='\r') { needQuote = true; break; }
  if (!needQuote) { strncpy(out, s, n-1); out[n-1] = 0; return; }
  size_t w = 0;
  if (w < n-1) out[w++] = '"';
  for (const char* p = s; *p && w < n-2; p++) {
    if (*p=='"' && w < n-3) out[w++] = '"';   // escape by doubling
    out[w++] = *p;
  }
  if (w < n-1) out[w++] = '"';
  out[w] = 0;
}
static void logRow(const ApEntry& e) {
  if (!g_fsOk || !LOG_TO_FLASH) return;
  File f = LittleFS.open(WIFI_LOG_PATH, "a");
  if (!f) return;
  if (f.size() > LOG_MAX_BYTES) { f.close(); return; }   // stop growing
  char ssidQ[68];
  csvQuote(e.ssid, ssidQ, sizeof(ssidQ));
  f.printf("%s,%s,[%s],%s,%d,%d,%d,%.6f,%.6f,0,%s,WIFI\n",
           e.bssid, ssidQ, e.enc, e.firstSeen, e.ch, chanToFreq(e.ch),
           e.rssiBest, e.lat, e.lon, e.hasGps ? "5" : "0");
  f.close();
}

// ---------------------------------------------------------------------------
//  Scan -> store
// ---------------------------------------------------------------------------
static volatile bool g_scanning = true;
static uint32_t g_bootMs = 0;
static uint32_t g_newCount = 0;

// Self-healing state (declared early: doScan() uses them). Track the last
// successful C2 report and consecutive scan failures so the loop watchdog can
// reset the radio (or reboot) if the shared WiFi stack wedges.
static uint32_t g_lastReportOkMs = 0;
static uint32_t g_scanFails      = 0;
static uint32_t g_lastResetMs    = 0;
static void resetRadio();        // defined below

static int findOrAdd(const char* bssid) {
  for (int i = 0; i < g_apN; i++) if (!strcasecmp(g_aps[i].bssid, bssid)) return i;
  if (g_apN >= MAX_APS) return -1;
  memset(&g_aps[g_apN], 0, sizeof(ApEntry));
  g_aps[g_apN].used = true; g_aps[g_apN].rssiBest = -128;
  return g_apN++;
}

static void doScan() {
  if (!g_scanning) return;
  int n = WiFi.scanNetworks(false, true);   // sync, include hidden
  pumpGps();
  if (n < 0) {                              // WIFI_SCAN_FAILED / RUNNING
    if (++g_scanFails >= SCAN_FAIL_LIMIT) resetRadio();
    return;
  }
  g_scanFails = 0;
  for (int i = 0; i < n; i++) {
    uint8_t* raw = WiFi.BSSID(i);
    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             raw[0],raw[1],raw[2],raw[3],raw[4],raw[5]);
    int idx = findOrAdd(bssid);
    if (idx < 0) continue;
    ApEntry& e = g_aps[idx];
    bool isNew = (e.bssid[0] == 0);
    if (isNew) {
      strncpy(e.bssid, bssid, sizeof(e.bssid)-1);
      String s = WiFi.SSID(i);
      strncpy(e.ssid, s.c_str(), sizeof(e.ssid)-1);
      strncpy(e.enc, encStr(WiFi.encryptionType(i)), sizeof(e.enc)-1);
      vendorHint(raw, e.vendor, sizeof(e.vendor));
      const char* fl = threatFlag(e.ssid, e.enc);
      strncpy(e.flag, fl, sizeof(e.flag)-1);
      e.lat = g_gps.lat; e.lon = g_gps.lon; e.hasGps = g_gps.valid;
      gpsStamp(e.firstSeen, sizeof(e.firstSeen));
      g_newCount++;
    }
    e.ch = WiFi.channel(i);
    int r = WiFi.RSSI(i);
    if (r > e.rssiBest) { e.rssiBest = r;
      if (g_gps.valid) { e.lat = g_gps.lat; e.lon = g_gps.lon; e.hasGps = true; } }
    // Defer the CSV row until we have a GPS-stamped position, so the WigleWifi
    // export doesn't fill with worthless 0,0 coordinates before the first fix.
    if (!e.logged && e.hasGps) { logRow(e); e.logged = true; }
  }
  WiFi.scanDelete();
}

// ---------------------------------------------------------------------------
//  Report to C2
// ---------------------------------------------------------------------------
static uint32_t g_linkEpoch = 0, g_lastCmdId = 0;

// Fully reset the WiFi stack — recovers a wedged radio (scans returning -1/-2
// or the C2 association stuck) without a full reboot.
static void resetRadio() {
  Serial.println("[WD] resetting WiFi radio (watchdog)");
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(200);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setAutoReconnect(true);
  g_lastResetMs   = millis();
  g_scanFails     = 0;
}

static void clearStore() {
  for (int i = 0; i < g_apN; i++) g_aps[i].used = false;
  g_apN = 0; g_newCount = 0;
}
static void applyCommands(JsonArrayConst cmds) {
  for (JsonObjectConst c : cmds) {
    uint32_t id = c["id"] | 0; if (id <= g_lastCmdId) continue;
    const char* cmd = c["cmd"] | ""; bool hasOn = c["on"].is<int>(); int on = hasOn ? (int)c["on"] : -1;
    if      (!strcmp(cmd, "scan"))  g_scanning = hasOn ? (on != 0) : !g_scanning;
    else if (!strcmp(cmd, "clear")) clearStore();
    g_lastCmdId = id;
  }
}

static bool ensureC2() {
  if (WiFi.status() == WL_CONNECTED) return true;
  WiFi.mode(WIFI_STA);
  WiFi.begin(C2_SSID, C2_PASSWORD);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < WIFI_CONNECT_MS) delay(100);
  return WiFi.status() == WL_CONNECTED;
}

static void reportToC2() {
  if (!ensureC2()) return;

  JsonDocument doc;
  doc["source"]=SRC_NAME; doc["ver"]=FW_VERSION;
  doc["linkEpoch"]=g_linkEpoch; doc["lastCmdId"]=g_lastCmdId;

  JsonObject st = doc["status"].to<JsonObject>();
  st["scanning"]    = g_scanning ? 1 : 0;
  st["networks"]    = g_apN;
  st["newNetworks"] = g_newCount;
  st["uptime"]      = (millis() - g_bootMs) / 1000;
  st["heap"]        = ESP.getFreeHeap();
  st["psram"]       = ESP.getFreePsram();

  JsonObject g = doc["gps"].to<JsonObject>();
  g["valid"]=g_gps.valid?1:0; g["sats"]=g_gps.sats; g["lat"]=g_gps.lat; g["lon"]=g_gps.lon;

  JsonArray devs = doc["devices"].to<JsonArray>();
  int sent = 0;
  for (int i = 0; i < g_apN && sent < UPLINK_BATCH_MAX; i++) {
    if (g_aps[i].uploaded) continue;
    ApEntry& e = g_aps[i];
    JsonObject d = devs.add<JsonObject>();
    d["mac"]=e.bssid; d["ssid"]=e.ssid; d["channel"]=e.ch; d["enc"]=e.enc;
    d["rssi"]=e.rssiBest; d["vendor"]=e.vendor;
    if (e.flag[0]) d["threat"]=e.flag;
    d["lat"]=e.lat; d["lon"]=e.lon;
    sent++;
  }
  doc["count"] = sent;

  String body; serializeJson(doc, body);
  HTTPClient http; WiFiClient client;
  String url = String("http://") + C2_HOST + C2_INGEST_PATH;
  if (http.begin(client, url)) {
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    if (code == 200) {
      g_lastReportOkMs = millis();          // feed the connectivity watchdog
      // mark the batch uploaded
      int marked = 0;
      for (int i = 0; i < g_apN && marked < sent; i++)
        if (!g_aps[i].uploaded) { g_aps[i].uploaded = true; marked++; }
      String resp = http.getString();
      JsonDocument rd;
      if (!deserializeJson(rd, resp)) {
        uint32_t ne = rd["epoch"] | 0;
        if (ne && ne != g_linkEpoch) {
          g_linkEpoch = ne; g_lastCmdId = 0;
          // C2 (re)booted: re-sync our whole inventory so its store — and the
          // CSV export — holds every network we've found, not just future ones.
          for (int i = 0; i < g_apN; i++) g_aps[i].uploaded = false;
        }
        applyCommands(rd["commands"].as<JsonArrayConst>());
      }
    }
    http.end();
  }
}

// ---------------------------------------------------------------------------
//  Setup / loop
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\nESP32-WarDriver node booting (scan + GPS + log)...");
  g_bootMs = millis();
  setLed(0, 0, 16);                            // boot: dim blue

  g_fsOk = LittleFS.begin(true);
  if (g_fsOk) ensureLogHeader();
  else Serial.println("[WD] LittleFS mount failed (logging disabled)");

  if (GPS_ENABLED) GPSserial.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);            // disable modem power-save: keeps the C2 link
                                   // stable and stops scans/commands stalling
  WiFi.setAutoReconnect(true);
  g_lastReportOkMs = millis();     // grace period before the watchdog can fire
  ensureC2();
}

void loop() {
  static uint32_t tScan = 0, tReport = 0;
  pumpGps();

  if (millis() - tScan >= SCAN_INTERVAL_MS) { tScan = millis(); doScan(); }
  if (millis() - tReport >= REPORT_INTERVAL_MS) {
    tReport = millis();
    setLed(0, 0, 48);                          // blue: associating + POSTing
    reportToC2();
  }

  // ---- connectivity watchdog: recover a wedged radio, reboot as last resort
  uint32_t sinceOk = millis() - g_lastReportOkMs;
  if (sinceOk > WIFI_REBOOT_MS) {
    Serial.println("[WD] no C2 contact too long — rebooting");
    delay(50); ESP.restart();
  } else if (sinceOk > WIFI_WATCHDOG_MS && millis() - g_lastResetMs > WIFI_WATCHDOG_MS) {
    resetRadio();
  }

  // idle status colour between report bursts
  if (!g_scanning)        setLed(8, 4, 0);     // amber: scan paused
  else if (g_gps.valid)   setLed(0, 48, 0);     // green: scanning with GPS fix
  else                    setLed(0, 24, 24);    // cyan: scanning, no fix yet

  static uint32_t hb = 0;
  if (millis() - hb > 2000) {
    hb = millis();
    Serial.printf("[WD] scan=%d aps=%d new=%lu gps=%d(%d sats) heap=%u\n",
      g_scanning, g_apN, (unsigned long)g_newCount, g_gps.valid, g_gps.sats,
      (unsigned)ESP.getFreeHeap());
  }
  delay(20);
}
