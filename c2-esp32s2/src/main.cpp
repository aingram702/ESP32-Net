// ===========================================================================
//  ESP32-Net C2 coordinator  —  main.cpp   (ESP32-S2 / Flipper WiFi module)
//
//  Hosts the SoftAP the three S3 scan nodes join, ingests their JSON over
//  POST /ingest, keeps a capped in-RAM inventory, serves the unified dashboard
//  and a /api/data feed, and relays operator control commands back to nodes.
//
//  Wire protocol (POST /ingest, application/json):
//    { "source":"ESP32-WarDriver"|"ESP32-WarSniffer"|"ESP32-BlueDriver",
//      "ver":"1.0.0", "linkEpoch":<n>, "lastCmdId":<n>,
//      "status":{...}, "gps":{...}, "count":N, "devices":[...]/"aps":[...]/"alerts":[...] }
//  Response:
//    { "ok":1, "epoch":<nonce>, "commands":[ {"id":<n>,"cmd":"scan","on":0}, ... ] }
//
//  AUTHORIZED TESTING ONLY. Passive reconnaissance + WIDS aggregation.
// ===========================================================================
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include "config.h"
#include "web_ui.h"

// ---------------------------------------------------------------------------
//  Capped in-RAM inventory (fixed buffers to bound heap on the S2)
// ---------------------------------------------------------------------------
struct WiFiAP {
  char     mac[18]   = {0};
  char     ssid[33]  = {0};
  uint8_t  ch        = 0;
  char     enc[10]   = {0};
  int8_t   rssi      = -128;
  char     vendor[24]= {0};
  char     flag[20]  = {0};   // threat label, e.g. "FLOCK CAMERA"; "" if none
  double   lat = 0, lon = 0;  // GPS stamp from the WarDriver (best-RSSI fix)
  bool     hasGps    = false;
  uint32_t seenMs    = 0;     // C2 millis() of last update
};
struct BLEDev {
  char     mac[18]   = {0};
  char     name[33]  = {0};
  char     type[8]   = {0};   // public / random
  char     vendor[24]= {0};
  int8_t   rssi      = -128;
  uint16_t hits      = 0;
  char     services[40]={0};
  char     mfgId[6]  = {0};   // company ID hex, e.g. "004C" (Apple)
  uint32_t seenMs    = 0;
};
struct SniffAP {
  char     bssid[18] = {0};
  char     ssid[33]  = {0};
  uint8_t  ch        = 0;
  int8_t   rssi      = -128;
  uint16_t clients   = 0;
  uint32_t seenMs    = 0;
};
struct Alert {
  char     type[16]  = {0};
  char     bssid[18] = {0};
  char     detail[40]= {0};
  uint32_t tMs       = 0;
};
struct Probe {                      // directed probe-request SSID (client PNL)
  char     ssid[33]  = {0};
  uint16_t hits      = 0;
  uint32_t seenMs    = 0;
};

static WiFiAP  g_wifi[MAX_WIFI_APS];   static int g_wifiN  = 0;
static BLEDev  g_ble [MAX_BLE_DEVS];   static int g_bleN   = 0;
static SniffAP g_sap [MAX_SNIFF_APS];  static int g_sapN   = 0;
static Alert   g_alt [MAX_ALERTS];     static int g_altN   = 0;   // ring
static Probe   g_prb [MAX_PROBES];     static int g_prbN   = 0;

// WarSniffer aggregate counters / state (last reported snapshot)
struct SniffFrames { uint32_t total,mgmt,ctrl,data,beacon,probe,deauth,eapol; };
static SniffFrames g_frames = {0};
static uint8_t  g_sniffCh   = 0;
static uint32_t g_sniffDrop = 0;

// WarDriver last GPS snapshot
struct GpsSnap { bool valid=false; double lat=0, lon=0; int sats=0; };
static GpsSnap g_gps;

// Last GATT enumeration result reported by the BlueDriver (raw JSON, capped).
// Surfaced on the dashboard's BlueDriver tab; cleared on a BlueDriver "clear".
static char     g_gattJson[MAX_GATT_BYTES] = {0};
static uint32_t g_gattMs = 0;

// Live capture ring: recent 802.11 frames reported by the WarSniffer. Served
// incrementally to the dashboard's Wireshark-style view via /api/packets.
struct CapPkt {
  uint32_t seq;          // monotonic id (dashboard fetches "since" the last seq)
  uint32_t tMs;          // C2 arrival time
  uint8_t  ch;
  int8_t   rssi;
  uint16_t len;          // length on air
  uint8_t  caplen;       // bytes actually stored
  uint8_t  data[PKT_SNAPLEN];
};
static CapPkt   g_pkt[PKT_RING];
static int      g_pktHead = 0, g_pktCount = 0;
static uint32_t g_pktSeq  = 0;

// Malicious-device / surveillance watchlist. Edited from the dashboard, pushed
// to the WarSniffer (version handshake), and persisted to LittleFS.
struct WatchEnt { char mac[18]; char label[24]; };   // mac "AA:BB:CC" (OUI) or full
static WatchEnt g_watch[MAX_WATCH];
static int      g_watchN   = 0;
static uint32_t g_watchVer = 1;          // bumped on every edit
static uint32_t g_wsWatchSeen = 0;       // watchVer the WarSniffer last reported
static bool     g_fsOk     = false;

// ---------------------------------------------------------------------------
//  Per-node link state + outbound command queue (epoch + monotonic ids)
// ---------------------------------------------------------------------------
// on=-2 => "on" field omitted from the wire reply.
// arg/arg2 carry string/int operands (currently the GATT target mac + addrType),
// emitted only when arg[0] != 0 so other commands stay compact.
struct Command { uint32_t id; char cmd[12]; int on; char arg[20]; int arg2; };
struct NodeLink {
  bool     ever      = false;
  uint32_t lastSeen  = 0;
  uint32_t uptime    = 0;
  uint32_t heap      = 0;
  uint32_t psram     = 0;
  char     detail[48]= {0};
  // command delivery
  uint32_t epoch     = 0;          // per-node boot nonce (set at C2 boot)
  uint32_t nextId    = 1;
  Command  q[MAX_CMDS_PER_NODE];
  int      qN        = 0;
};
static NodeLink L_wd, L_ws, L_bd;

static NodeLink* linkFor(const char* src) {
  if (!strcmp(src, SRC_WARDRIVER))  return &L_wd;
  if (!strcmp(src, SRC_WARSNIFFER)) return &L_ws;
  if (!strcmp(src, SRC_BLUEDRIVER)) return &L_bd;
  return nullptr;
}

static void enqueueCmd(NodeLink* L, const char* cmd, int on,
                       const char* arg = nullptr, int arg2 = 0) {
  if (!L) return;
  if (L->qN >= MAX_CMDS_PER_NODE) {           // drop oldest
    memmove(&L->q[0], &L->q[1], sizeof(Command) * (MAX_CMDS_PER_NODE - 1));
    L->qN = MAX_CMDS_PER_NODE - 1;
  }
  Command& c = L->q[L->qN++];
  c.id = L->nextId++;
  strncpy(c.cmd, cmd, sizeof(c.cmd) - 1); c.cmd[sizeof(c.cmd)-1] = 0;
  c.on = on;
  if (arg) { strncpy(c.arg, arg, sizeof(c.arg) - 1); c.arg[sizeof(c.arg)-1] = 0; }
  else     c.arg[0] = 0;
  c.arg2 = arg2;
}

// prune commands the node has acked (id <= lastCmdId), but only if its
// linkEpoch matches our current epoch (guards against stale post-reboot acks)
static void pruneAcked(NodeLink* L, uint32_t linkEpoch, uint32_t lastCmdId) {
  if (!L || linkEpoch != L->epoch) return;
  int w = 0;
  for (int i = 0; i < L->qN; i++)
    if (L->q[i].id > lastCmdId) L->q[w++] = L->q[i];
  L->qN = w;
}

// ---------------------------------------------------------------------------
//  Store upsert helpers (dedupe by MAC/BSSID; evict nothing, just cap)
// ---------------------------------------------------------------------------
static void cpy(char* dst, size_t n, const char* src) {
  if (!src) { dst[0] = 0; return; }
  strncpy(dst, src, n - 1); dst[n - 1] = 0;
}

// Pick the slot with the oldest seenMs (LRU victim) once a store is full.
template <typename T>
static int oldestSlot(const T* arr, int n) {
  int v = 0;
  for (int i = 1; i < n; i++) if (arr[i].seenMs < arr[v].seenMs) v = i;
  return v;
}

static void upsertWiFi(JsonObjectConst o) {
  const char* mac = o["mac"] | o["bssid"] | "";
  if (!*mac) return;
  int idx = -1;
  for (int i = 0; i < g_wifiN; i++) if (!strcasecmp(g_wifi[i].mac, mac)) { idx = i; break; }
  if (idx < 0) {
    idx = (g_wifiN < MAX_WIFI_APS) ? g_wifiN++ : oldestSlot(g_wifi, g_wifiN);
    g_wifi[idx] = WiFiAP();          // reset reused slot (avoids stale GPS/flag)
  }
  WiFiAP& a = g_wifi[idx];
  cpy(a.mac, sizeof(a.mac), mac);
  cpy(a.ssid, sizeof(a.ssid), o["ssid"] | "");
  a.ch   = o["ch"]  | o["channel"] | 0;
  cpy(a.enc, sizeof(a.enc), o["enc"] | o["encryption"] | "");
  a.rssi = o["rssi"] | (int)-128;
  cpy(a.vendor, sizeof(a.vendor), o["vendor"] | "");
  cpy(a.flag, sizeof(a.flag), o["threat"] | o["flag"] | "");
  double lat = o["lat"] | 0.0, lon = o["lon"] | 0.0;
  if (lat != 0.0 || lon != 0.0) { a.lat = lat; a.lon = lon; a.hasGps = true; }
  a.seenMs = millis();
}

static void upsertBLE(JsonObjectConst o) {
  const char* mac = o["mac"] | o["address"] | "";
  if (!*mac) return;
  int idx = -1;
  for (int i = 0; i < g_bleN; i++) if (!strcasecmp(g_ble[i].mac, mac)) { idx = i; break; }
  if (idx < 0) {
    idx = (g_bleN < MAX_BLE_DEVS) ? g_bleN++ : oldestSlot(g_ble, g_bleN);
    g_ble[idx] = BLEDev();           // reset reused slot (avoids stale hits)
  }
  BLEDev& d = g_ble[idx];
  cpy(d.mac, sizeof(d.mac), mac);
  cpy(d.name, sizeof(d.name), o["name"] | "");
  cpy(d.type, sizeof(d.type), o["addrType"] | o["type"] | "");
  cpy(d.vendor, sizeof(d.vendor), o["vendor"] | "");
  d.rssi = o["rssiBest"] | o["rssi"] | (int)-128;
  d.hits = o["count"] | (int)(d.hits + 1);
  cpy(d.services, sizeof(d.services), o["services"] | "");
  cpy(d.mfgId, sizeof(d.mfgId), o["mfgId"] | "");
  d.seenMs = millis();
}

static void upsertSniffAP(JsonObjectConst o) {
  const char* b = o["bssid"] | o["mac"] | "";
  if (!*b) return;
  int idx = -1;
  for (int i = 0; i < g_sapN; i++) if (!strcasecmp(g_sap[i].bssid, b)) { idx = i; break; }
  if (idx < 0) idx = (g_sapN < MAX_SNIFF_APS) ? g_sapN++ : oldestSlot(g_sap, g_sapN);
  SniffAP& a = g_sap[idx];
  cpy(a.bssid, sizeof(a.bssid), b);
  cpy(a.ssid, sizeof(a.ssid), o["ssid"] | "");
  a.ch      = o["ch"] | o["channel"] | 0;
  a.rssi    = o["rssi"] | (int)-128;
  a.clients = o["clients"] | (int)0;
  a.seenMs  = millis();
}

static void pushAlert(JsonObjectConst o) {
  Alert& a = g_alt[g_altN % MAX_ALERTS]; g_altN++;
  cpy(a.type, sizeof(a.type), o["type"] | "");
  cpy(a.bssid, sizeof(a.bssid), o["bssid"] | "");
  cpy(a.detail, sizeof(a.detail), o["detail"] | "");
  a.tMs = millis();
}

static void upsertProbe(JsonObjectConst o) {
  const char* ssid = o["ssid"] | "";
  if (!*ssid) return;
  int idx = -1;
  for (int i = 0; i < g_prbN; i++) if (!strcmp(g_prb[i].ssid, ssid)) { idx = i; break; }
  if (idx < 0) {
    idx = (g_prbN < MAX_PROBES) ? g_prbN++ : oldestSlot(g_prb, g_prbN);
    g_prb[idx] = Probe();            // reset reused slot (avoids stale hits)
  }
  Probe& p = g_prb[idx];
  cpy(p.ssid, sizeof(p.ssid), ssid);
  p.hits   = o["hits"] | (int)(p.hits + 1);
  p.seenMs = millis();
}

// Mirror the operator's per-node "clear" on the C2's own aggregate store, so a
// CLEAR button empties the dashboard immediately instead of showing stale data
// that the (now-empty) node will never re-report.
static void clearMirror(const char* target) {
  if (!strcmp(target, "wardriver"))  { g_wifiN = 0; g_gps = GpsSnap(); }
  else if (!strcmp(target, "bluedriver")) { g_bleN = 0; g_gattJson[0] = 0; g_gattMs = 0; }
  else if (!strcmp(target, "warsniffer")) {
    g_sapN = 0; g_altN = 0; g_prbN = 0; g_frames = SniffFrames{0}; g_sniffDrop = 0;
    g_pktHead = 0; g_pktCount = 0;     // drop buffered capture (seq stays monotonic)
  }
}

// ---------------------------------------------------------------------------
//  Live capture ring + hex helpers
// ---------------------------------------------------------------------------
static uint8_t hexNib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}
static uint8_t hexToBytes(const char* hex, uint8_t* out, uint8_t maxn) {
  uint8_t n = 0;
  while (hex[0] && hex[1] && n < maxn) { out[n++] = (hexNib(hex[0]) << 4) | hexNib(hex[1]); hex += 2; }
  return n;
}
static void pushPkt(uint8_t ch, int8_t rssi, uint16_t len, const uint8_t* data, uint8_t caplen) {
  int slot;
  if (g_pktCount < PKT_RING) { slot = (g_pktHead + g_pktCount) % PKT_RING; g_pktCount++; }
  else { slot = g_pktHead; g_pktHead = (g_pktHead + 1) % PKT_RING; }   // overwrite oldest
  CapPkt& c = g_pkt[slot];
  c.seq = ++g_pktSeq; c.tMs = millis(); c.ch = ch; c.rssi = rssi; c.len = len;
  c.caplen = caplen > PKT_SNAPLEN ? PKT_SNAPLEN : caplen;
  memcpy(c.data, data, c.caplen);
}

// ---------------------------------------------------------------------------
//  Watchlist (MAC/OUI) — edited from the dashboard, pushed to the WarSniffer,
//  persisted to LittleFS.
// ---------------------------------------------------------------------------
// Validate + upper-case a MAC ("AA:BB:CC" OUI or full 6-octet MAC).
static bool watchNorm(const char* in, char* out, size_t n) {
  unsigned b[6];
  if (sscanf(in, "%02x:%02x:%02x:%02x:%02x:%02x",
             &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6) {
    snprintf(out, n, "%02X:%02X:%02X:%02X:%02X:%02X", b[0],b[1],b[2],b[3],b[4],b[5]);
    return true;
  }
  if (sscanf(in, "%02x:%02x:%02x", &b[0],&b[1],&b[2]) == 3) {
    snprintf(out, n, "%02X:%02X:%02X", b[0],b[1],b[2]);
    return true;
  }
  return false;
}
// Copy a label, stripping CSV/JSON-breaking and control characters. Used on
// both add (operator input) and load (file on flash) — the label is later
// emitted raw inside JSON, so this keeps every consumer well-formed.
static void labelCopy(char* dst, size_t n, const char* src) {
  size_t j = 0;
  for (const char* p = src ? src : ""; *p && j < n - 1; p++)
    if (*p != ',' && *p != '\n' && *p != '\r' && *p != '"' && *p != '\\' && (uint8_t)*p >= 0x20)
      dst[j++] = *p;
  dst[j] = 0;
}
static void watchSave() {
  if (!g_fsOk) return;
  File f = LittleFS.open(WATCH_PATH, "w");
  if (!f) return;
  for (int i = 0; i < g_watchN; i++) f.printf("%s,%s\n", g_watch[i].mac, g_watch[i].label);
  f.close();
}
static bool watchAdd(const char* mac, const char* label) {
  char norm[18];
  if (!watchNorm(mac, norm, sizeof(norm))) return false;
  for (int i = 0; i < g_watchN; i++) if (!strcasecmp(g_watch[i].mac, norm)) return false;  // dup
  if (g_watchN >= MAX_WATCH) return false;
  WatchEnt& w = g_watch[g_watchN++];
  strncpy(w.mac, norm, sizeof(w.mac)-1); w.mac[sizeof(w.mac)-1] = 0;
  labelCopy(w.label, sizeof(w.label), label);
  g_watchVer++;
  return true;
}
static bool watchDel(const char* mac) {
  char norm[18];
  if (!watchNorm(mac, norm, sizeof(norm))) return false;
  for (int i = 0; i < g_watchN; i++) if (!strcasecmp(g_watch[i].mac, norm)) {
    for (int k = i; k < g_watchN - 1; k++) g_watch[k] = g_watch[k+1];
    g_watchN--; g_watchVer++;
    return true;
  }
  return false;
}
static void watchLoad() {
  if (!g_fsOk) return;
  File f = LittleFS.open(WATCH_PATH, "r");
  if (!f) return;
  g_watchN = 0;
  while (f.available() && g_watchN < MAX_WATCH) {
    String line = f.readStringUntil('\n'); line.trim();
    if (!line.length()) continue;
    int c = line.indexOf(',');
    String mac = (c < 0) ? line : line.substring(0, c);
    String lbl = (c < 0) ? String("") : line.substring(c + 1);
    char norm[18];
    if (!watchNorm(mac.c_str(), norm, sizeof(norm))) continue;
    WatchEnt& w = g_watch[g_watchN++];
    strncpy(w.mac, norm, sizeof(w.mac)-1); w.mac[sizeof(w.mac)-1] = 0;
    labelCopy(w.label, sizeof(w.label), lbl.c_str());
  }
  f.close();
}
static void watchSeedDefaults() {
  // Starter entries (camera/surveillance vendor OUIs). These are examples to
  // tune for your area — add/remove from the dashboard. Matching is by OUI.
  watchAdd("AC:CC:8E", "Axis camera");
  watchAdd("00:40:8C", "Axis camera");
  watchAdd("00:80:F0", "Panasonic cam?");
}

// ---------------------------------------------------------------------------
//  HTTP server
// ---------------------------------------------------------------------------
static AsyncWebServer server(80);

// Per-request body accumulator (AsyncWebServer streams the body in chunks).
struct BodyBuf { String data; };

static void buildIngestReply(NodeLink* L, String& out) {
  JsonDocument doc;
  doc["ok"]    = 1;
  doc["epoch"] = L ? L->epoch : 0;
  JsonArray cmds = doc["commands"].to<JsonArray>();
  if (L) for (int i = 0; i < L->qN; i++) {
    JsonObject c = cmds.add<JsonObject>();
    c["id"]  = L->q[i].id;
    c["cmd"] = L->q[i].cmd;
    if (L->q[i].on != -2) c["on"] = L->q[i].on;
    if (L->q[i].arg[0]) { c["mac"] = L->q[i].arg; c["addrType"] = L->q[i].arg2; }
  }
  // Push the malicious-device watchlist to the WarSniffer; send the full list
  // only when its version is stale (it echoes watchVer in each request).
  if (L == &L_ws) {
    doc["watchVer"] = g_watchVer;
    if (g_wsWatchSeen != g_watchVer) {
      JsonArray w = doc["watch"].to<JsonArray>();
      for (int i = 0; i < g_watchN; i++) {
        JsonObject e = w.add<JsonObject>();
        e["mac"] = g_watch[i].mac; e["label"] = g_watch[i].label;
      }
    }
  }
  serializeJson(doc, out);
}

static void handleIngestBody(AsyncWebServerRequest* req) {
  BodyBuf* bb = (BodyBuf*) req->_tempObject;
  if (!bb) { req->send(400, "application/json", "{\"ok\":0,\"err\":\"no body\"}"); return; }

  JsonDocument doc;
  DeserializationError e = deserializeJson(doc, bb->data);
  delete bb; req->_tempObject = nullptr;
  if (e) { req->send(400, "application/json", "{\"ok\":0,\"err\":\"bad json\"}"); return; }

  const char* src = doc["source"] | "";
  NodeLink* L = linkFor(src);
  if (!L) { req->send(404, "application/json", "{\"ok\":0,\"err\":\"unknown source\"}"); return; }

  // link bookkeeping
  pruneAcked(L, doc["linkEpoch"] | 0, doc["lastCmdId"] | 0);
  L->ever     = true;
  L->lastSeen = millis();
  JsonObjectConst st = doc["status"];
  if (!st.isNull()) {
    L->uptime = st["uptime"] | 0;
    L->heap   = st["heap"]   | 0;
    L->psram  = st["psram"]  | 0;
  }

  // node-specific payloads
  if (L == &L_wd) {
    JsonObjectConst g = doc["gps"];
    if (!g.isNull()) { g_gps.valid = (g["valid"] | 0) != 0;
      g_gps.lat = g["lat"] | 0.0; g_gps.lon = g["lon"] | 0.0; g_gps.sats = g["sats"] | 0; }
    for (JsonObjectConst o : doc["devices"].as<JsonArrayConst>()) upsertWiFi(o);
    snprintf(L->detail, sizeof(L->detail), "%u APs / scan:%d",
             (unsigned)g_wifiN, (int)(st["scanning"] | 0));
  } else if (L == &L_bd) {
    for (JsonObjectConst o : doc["devices"].as<JsonArrayConst>()) upsertBLE(o);
    JsonObjectConst gr = doc["gattResult"];
    if (!gr.isNull()) {
      size_t w = serializeJson(gr, g_gattJson, sizeof(g_gattJson));
      if (w == 0 || w >= sizeof(g_gattJson)) g_gattJson[0] = 0;  // dropped if too big
      else g_gattMs = millis();
    }
    snprintf(L->detail, sizeof(L->detail), "%u dev / active:%d",
             (unsigned)g_bleN, (int)(st["activeScan"] | 0));
  } else if (L == &L_ws) {
    JsonObjectConst f = st["frames"];
    if (!f.isNull()) {
      g_frames.total = f["total"]|0; g_frames.mgmt=f["mgmt"]|0; g_frames.ctrl=f["ctrl"]|0;
      g_frames.data=f["data"]|0; g_frames.beacon=f["beacon"]|0; g_frames.probe=f["probe"]|0;
      g_frames.deauth=f["deauth"]|0; g_frames.eapol=f["eapol"]|0;
    }
    g_sniffCh   = st["channel"] | 0;
    g_sniffDrop = st["dropped"] | 0;
    g_wsWatchSeen = doc["watchVer"] | 0;        // for the watchlist push handshake
    for (JsonObjectConst o : doc["aps"].as<JsonArrayConst>())    upsertSniffAP(o);
    for (JsonObjectConst o : doc["alerts"].as<JsonArrayConst>()) pushAlert(o);
    for (JsonObjectConst o : doc["probes"].as<JsonArrayConst>()) upsertProbe(o);
    for (JsonObjectConst o : doc["packets"].as<JsonArrayConst>()) {
      uint8_t buf[PKT_SNAPLEN];
      uint8_t cap = hexToBytes(o["data"] | "", buf, PKT_SNAPLEN);
      pushPkt(o["ch"] | 0, o["rssi"] | (int)-128, o["len"] | 0, buf, cap);
    }
    snprintf(L->detail, sizeof(L->detail), "ch%u / %u frames",
             (unsigned)g_sniffCh, (unsigned)g_frames.total);
  }

  String out; buildIngestReply(L, out);
  req->send(200, "application/json", out);
}

// /api/cmd : browser -> queue a control command for a node
static void handleCmdBody(AsyncWebServerRequest* req) {
  BodyBuf* bb = (BodyBuf*) req->_tempObject;
  if (!bb) { req->send(400, "text/plain", "no body"); return; }
  JsonDocument doc;
  DeserializationError e = deserializeJson(doc, bb->data);
  delete bb; req->_tempObject = nullptr;
  if (e) { req->send(400, "text/plain", "bad json"); return; }

  const char* target = doc["target"] | "";
  const char* cmd    = doc["cmd"]    | "";
  int on             = doc["on"].is<int>() ? (int)doc["on"] : -2;

  NodeLink* L = nullptr;
  if (!strcmp(target, "wardriver"))  L = &L_wd;
  else if (!strcmp(target, "warsniffer")) L = &L_ws;
  else if (!strcmp(target, "bluedriver")) L = &L_bd;
  if (!L || !*cmd) { req->send(400, "text/plain", "bad target/cmd"); return; }

  if (!strcmp(cmd, "gatt")) {                        // gatt carries mac + addrType
    const char* mac = doc["mac"] | "";
    if (!*mac) { req->send(400, "text/plain", "gatt needs mac"); return; }
    enqueueCmd(L, cmd, on, mac, doc["addrType"] | 0);
  } else {
    enqueueCmd(L, cmd, on);
  }
  if (!strcmp(cmd, "clear")) clearMirror(target);   // keep the dashboard in sync
  req->send(200, "application/json", "{\"ok\":1}");
}

// ---------------------------------------------------------------------------
//  CSV export — pull collected inventory off the C2 for offline reporting.
//  GET /api/export/wifi | /api/export/ble | /api/export/sniff
// ---------------------------------------------------------------------------
// RFC-4180 CSV field with CSV-injection hardening. Values here come from
// untrusted RF (SSIDs, device names): quote anything with a comma/quote/newline
// and double embedded quotes, AND neutralise spreadsheet formula injection by
// prefixing a leading =,+,-,@,TAB,CR with an apostrophe.
static void csvField(AsyncResponseStream* rs, const char* s) {
  if (!s) s = "";
  char c0 = s[0];
  bool danger = (c0=='=' || c0=='+' || c0=='-' || c0=='@' || c0=='\t' || c0=='\r');
  bool quote = danger;
  for (const char* p = s; *p && !quote; p++)
    if (*p==',' || *p=='"' || *p=='\n' || *p=='\r') quote = true;
  if (!quote) { rs->print(s); return; }
  rs->print('"');
  if (danger) rs->print('\'');
  for (const char* p = s; *p; p++) { if (*p=='"') rs->print('"'); rs->print(*p); }
  rs->print('"');
}

static int wifiChanToFreq(int ch) {
  return (ch >= 1 && ch <= 13) ? 2407 + ch * 5 : (ch == 14 ? 2484 : 0);
}

static void handleExportWiFi(AsyncWebServerRequest* req) {
  AsyncResponseStream* rs = req->beginResponseStream("text/csv");
  rs->addHeader("Content-Disposition", "attachment; filename=wifi.csv");
  rs->print("BSSID,SSID,Channel,Frequency,Encryption,RSSI,Latitude,Longitude,Vendor,Flag,AgeSec\n");
  uint32_t now = millis();
  for (int i = 0; i < g_wifiN; i++) {
    csvField(rs, g_wifi[i].mac);  rs->print(',');
    csvField(rs, g_wifi[i].ssid); rs->print(',');
    rs->printf("%u,%d,", (unsigned)g_wifi[i].ch, wifiChanToFreq(g_wifi[i].ch));
    csvField(rs, g_wifi[i].enc);  rs->print(',');
    rs->printf("%d,", (int)g_wifi[i].rssi);
    if (g_wifi[i].hasGps) rs->printf("%.6f,%.6f,", g_wifi[i].lat, g_wifi[i].lon);
    else                  rs->print(",,");
    csvField(rs, g_wifi[i].vendor); rs->print(',');
    csvField(rs, g_wifi[i].flag);   rs->print(',');
    rs->printf("%u\n", (unsigned)((now - g_wifi[i].seenMs) / 1000));
  }
  req->send(rs);
}

static void handleExportBLE(AsyncWebServerRequest* req) {
  AsyncResponseStream* rs = req->beginResponseStream("text/csv");
  rs->addHeader("Content-Disposition", "attachment; filename=ble.csv");
  rs->print("Address,Name,AddrType,Vendor,MfgId,RSSI,Hits,Services,AgeSec\n");
  uint32_t now = millis();
  for (int i = 0; i < g_bleN; i++) {
    csvField(rs, g_ble[i].mac);  rs->print(',');
    csvField(rs, g_ble[i].name); rs->print(',');
    csvField(rs, g_ble[i].type); rs->print(',');
    csvField(rs, g_ble[i].vendor); rs->print(',');
    csvField(rs, g_ble[i].mfgId);  rs->print(',');
    rs->printf("%d,%u,", (int)g_ble[i].rssi, (unsigned)g_ble[i].hits);
    csvField(rs, g_ble[i].services); rs->print(',');
    rs->printf("%u\n", (unsigned)((now - g_ble[i].seenMs) / 1000));
  }
  req->send(rs);
}

static void handleExportSniff(AsyncWebServerRequest* req) {
  AsyncResponseStream* rs = req->beginResponseStream("text/csv");
  rs->addHeader("Content-Disposition", "attachment; filename=sniff.csv");
  rs->print("BSSID,SSID,Channel,RSSI,Clients,AgeSec\n");
  uint32_t now = millis();
  for (int i = 0; i < g_sapN; i++) {
    csvField(rs, g_sap[i].bssid); rs->print(',');
    csvField(rs, g_sap[i].ssid);  rs->print(',');
    rs->printf("%u,%d,%u,", (unsigned)g_sap[i].ch, (int)g_sap[i].rssi, (unsigned)g_sap[i].clients);
    rs->printf("%u\n", (unsigned)((now - g_sap[i].seenMs) / 1000));
  }
  req->send(rs);
}

// /api/packets?since=<seq> : incremental live-capture feed for the dashboard's
// Wireshark-style view. Streamed by hand to avoid a large JsonDocument on the S2.
static void handlePackets(AsyncWebServerRequest* req) {
  uint32_t since = 0;
  if (req->hasParam("since")) since = strtoul(req->getParam("since")->value().c_str(), nullptr, 10);
  AsyncResponseStream* rs = req->beginResponseStream("application/json");
  rs->print("{\"packets\":[");
  bool first = true;
  for (int k = 0; k < g_pktCount; k++) {
    int i = (g_pktHead + k) % PKT_RING;
    if (g_pkt[i].seq <= since) continue;
    if (!first) rs->print(','); first = false;
    rs->printf("{\"seq\":%u,\"t\":%u,\"ch\":%u,\"rssi\":%d,\"len\":%u,\"data\":\"",
               (unsigned)g_pkt[i].seq, (unsigned)g_pkt[i].tMs, (unsigned)g_pkt[i].ch,
               (int)g_pkt[i].rssi, (unsigned)g_pkt[i].len);
    for (int j = 0; j < g_pkt[i].caplen; j++) rs->printf("%02x", g_pkt[i].data[j]);
    rs->print("\"}");
  }
  rs->printf("],\"last\":%u}", (unsigned)g_pktSeq);
  req->send(rs);
}

// /api/watch : GET the watchlist; POST {op:add|del|clear, mac, label} to edit it.
static void handleWatchGet(AsyncWebServerRequest* req) {
  AsyncResponseStream* rs = req->beginResponseStream("application/json");
  rs->printf("{\"ver\":%u,\"watch\":[", (unsigned)g_watchVer);
  for (int i = 0; i < g_watchN; i++) {
    if (i) rs->print(',');
    rs->print("{\"mac\":\""); rs->print(g_watch[i].mac);
    rs->print("\",\"label\":\""); rs->print(g_watch[i].label); rs->print("\"}");
  }
  rs->print("]}");
  req->send(rs);
}
static void handleWatchBody(AsyncWebServerRequest* req) {
  BodyBuf* bb = (BodyBuf*) req->_tempObject;
  if (!bb) { req->send(400, "text/plain", "no body"); return; }
  JsonDocument doc;
  DeserializationError e = deserializeJson(doc, bb->data);
  delete bb; req->_tempObject = nullptr;
  if (e) { req->send(400, "text/plain", "bad json"); return; }
  const char* op = doc["op"] | "";
  bool ok = false;
  if      (!strcmp(op, "add"))   ok = watchAdd(doc["mac"] | "", doc["label"] | "");
  else if (!strcmp(op, "del"))   ok = watchDel(doc["mac"] | "");
  else if (!strcmp(op, "clear")) { g_watchN = 0; g_watchVer++; ok = true; }
  if (ok) watchSave();
  req->send(ok ? 200 : 400, "application/json", ok ? "{\"ok\":1}" : "{\"ok\":0}");
}

// /api/data : full snapshot for the dashboard
static void handleData(AsyncWebServerRequest* req) {
  JsonDocument doc;
  doc["uptime"]    = millis() / 1000;
  doc["apClients"] = WiFi.softAPgetStationNum();

  uint32_t now = millis();
  JsonObject nodes = doc["nodes"].to<JsonObject>();
  auto addNode = [&](const char* key, NodeLink& L) {
    JsonObject n = nodes[key].to<JsonObject>();
    bool online = L.ever && (now - L.lastSeen) < NODE_TIMEOUT_MS;
    n["online"]     = online;
    n["lastSeenMs"] = L.ever ? (now - L.lastSeen) : (uint32_t)0;
    n["uptime"]     = L.uptime;
    n["heap"]       = L.heap;
    n["detail"]     = L.detail;
  };
  addNode("wardriver", L_wd);
  addNode("warsniffer", L_ws);
  addNode("bluedriver", L_bd);

  // WARDRIVER
  JsonObject wd = doc["wardriver"].to<JsonObject>();
  JsonObject gp = wd["gps"].to<JsonObject>();
  gp["valid"] = g_gps.valid; gp["lat"] = g_gps.lat; gp["lon"] = g_gps.lon; gp["sats"] = g_gps.sats;
  JsonArray waps = wd["aps"].to<JsonArray>();
  for (int i = 0; i < g_wifiN; i++) {
    JsonObject a = waps.add<JsonObject>();
    a["mac"]=g_wifi[i].mac; a["ssid"]=g_wifi[i].ssid; a["ch"]=g_wifi[i].ch;
    a["enc"]=g_wifi[i].enc; a["rssi"]=g_wifi[i].rssi; a["vendor"]=g_wifi[i].vendor;
    if (g_wifi[i].flag[0]) a["flag"]=g_wifi[i].flag;
    a["seenMs"]= now - g_wifi[i].seenMs;
  }

  // WARSNIFFER
  JsonObject ws = doc["warsniffer"].to<JsonObject>();
  ws["channel"] = g_sniffCh; ws["dropped"] = g_sniffDrop;
  JsonObject fr = ws["frames"].to<JsonObject>();
  fr["total"]=g_frames.total; fr["mgmt"]=g_frames.mgmt; fr["ctrl"]=g_frames.ctrl;
  fr["data"]=g_frames.data; fr["beacon"]=g_frames.beacon; fr["probe"]=g_frames.probe;
  fr["deauth"]=g_frames.deauth; fr["eapol"]=g_frames.eapol;
  JsonArray saps = ws["aps"].to<JsonArray>();
  for (int i = 0; i < g_sapN; i++) {
    JsonObject a = saps.add<JsonObject>();
    a["bssid"]=g_sap[i].bssid; a["ssid"]=g_sap[i].ssid; a["ch"]=g_sap[i].ch;
    a["rssi"]=g_sap[i].rssi; a["clients"]=g_sap[i].clients;
  }
  JsonArray al = ws["alerts"].to<JsonArray>();
  int total = g_altN < MAX_ALERTS ? g_altN : MAX_ALERTS;
  for (int k = 0; k < total; k++) {                 // newest first
    int i = (g_altN - 1 - k + MAX_ALERTS) % MAX_ALERTS;
    JsonObject a = al.add<JsonObject>();
    a["type"]=g_alt[i].type; a["bssid"]=g_alt[i].bssid;
    a["detail"]=g_alt[i].detail; a["ageMs"]= now - g_alt[i].tMs;
  }
  JsonArray pb = ws["probes"].to<JsonArray>();
  for (int i = 0; i < g_prbN; i++) {
    JsonObject p = pb.add<JsonObject>();
    p["ssid"]=g_prb[i].ssid; p["hits"]=g_prb[i].hits; p["seenMs"]= now - g_prb[i].seenMs;
  }

  // BLUEDRIVER
  JsonObject bd = doc["bluedriver"].to<JsonObject>();
  JsonArray bdv = bd["devs"].to<JsonArray>();
  for (int i = 0; i < g_bleN; i++) {
    JsonObject d = bdv.add<JsonObject>();
    d["mac"]=g_ble[i].mac; d["name"]=g_ble[i].name; d["type"]=g_ble[i].type;
    d["vendor"]=g_ble[i].vendor; d["rssi"]=g_ble[i].rssi; d["hits"]=g_ble[i].hits;
    d["services"]=g_ble[i].services;
    if (g_ble[i].mfgId[0]) d["mfgId"]=g_ble[i].mfgId;
  }
  if (g_gattJson[0]) {
    JsonDocument gd;                          // nest the captured GATT result
    if (!deserializeJson(gd, g_gattJson)) {
      bd["gatt"] = gd.as<JsonObject>();
      bd["gattAgeMs"] = now - g_gattMs;
    }
  }

  AsyncResponseStream* rs = req->beginResponseStream("application/json");
  serializeJson(doc, *rs);
  req->send(rs);
}

// generic chunked-body collector shared by /ingest and /api/cmd
static void bodyCollector(AsyncWebServerRequest* req, uint8_t* data,
                          size_t len, size_t index, size_t total) {
  if (total > MAX_BODY_BYTES) return;          // ignore oversized
  if (index == 0) {
    if (req->_tempObject) { delete (BodyBuf*) req->_tempObject; }
    BodyBuf* bb = new BodyBuf();
    bb->data.reserve(total ? total + 1 : 256);
    req->_tempObject = bb;
  }
  BodyBuf* bb = (BodyBuf*) req->_tempObject;
  if (bb) bb->data.concat((const char*) data, len);
}

// ---------------------------------------------------------------------------
//  Setup / loop
// ---------------------------------------------------------------------------
static void startAP() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL, 0, AP_MAX_CLIENTS);
  delay(100);
  Serial.printf("[C2] SoftAP \"%s\"  ip=%s  ch=%d\n",
                AP_SSID, WiFi.softAPIP().toString().c_str(), AP_CHANNEL);
}

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.printf("\n%s v%s booting...\n", FW_NAME, FW_VERSION);

  // assign each node link a random non-zero boot epoch
  randomSeed((uint32_t) esp_random());
  L_wd.epoch = (esp_random() | 1);
  L_ws.epoch = (esp_random() | 1);
  L_bd.epoch = (esp_random() | 1);

  // Mount LittleFS and load the persisted watchlist (seed defaults if empty).
  g_fsOk = LittleFS.begin(true);
  if (g_fsOk) {
    watchLoad();
    if (g_watchN == 0) { watchSeedDefaults(); watchSave(); }
  } else {
    Serial.println("[C2] LittleFS mount failed — watchlist not persisted");
    watchSeedDefaults();
  }

  startAP();

  if (MDNS.begin(MDNS_HOST)) {
    MDNS.addService("http", "tcp", 80);
    Serial.printf("[C2] mDNS responder up: http://%s.local/\n", MDNS_HOST);
  }

  server.on("/", HTTP_GET, [](AsyncWebServerRequest* r) {
    AsyncWebServerResponse* resp = r->beginResponse_P(200, "text/html", INDEX_HTML);
    resp->addHeader("Cache-Control", "no-store");
    r->send(resp);
  });
  server.on("/api/data", HTTP_GET, handleData);
  server.on("/api/packets", HTTP_GET, handlePackets);
  server.on("/api/watch", HTTP_GET, handleWatchGet);
  server.on("/api/export/wifi",  HTTP_GET, handleExportWiFi);
  server.on("/api/export/ble",   HTTP_GET, handleExportBLE);
  server.on("/api/export/sniff", HTTP_GET, handleExportSniff);
  server.on(INGEST_PATH, HTTP_POST, handleIngestBody, nullptr, bodyCollector);
  server.on("/api/cmd", HTTP_POST, handleCmdBody, nullptr, bodyCollector);
  server.on("/api/watch", HTTP_POST, handleWatchBody, nullptr, bodyCollector);

  server.onNotFound([](AsyncWebServerRequest* r) {
    // captive-portal style: bounce everything to the dashboard
    r->redirect("/");
  });

  server.begin();
  Serial.println("[C2] HTTP server up. Browse http://192.168.4.1/");
}

void loop() {
  // Everything runs in the AsyncTCP task; nothing required here.
  // Periodic heartbeat to serial for field debugging.
  static uint32_t t = 0;
  if (millis() - t > 5000) {
    t = millis();
    Serial.printf("[C2] clients=%d  wifi=%d ble=%d sap=%d  heap=%u\n",
                  WiFi.softAPgetStationNum(), g_wifiN, g_bleN, g_sapN,
                  (unsigned) ESP.getFreeHeap());
  }
  delay(20);
}
