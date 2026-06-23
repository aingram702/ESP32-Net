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
  if (idx < 0) idx = (g_wifiN < MAX_WIFI_APS) ? g_wifiN++ : oldestSlot(g_wifi, g_wifiN);
  WiFiAP& a = g_wifi[idx];
  cpy(a.mac, sizeof(a.mac), mac);
  cpy(a.ssid, sizeof(a.ssid), o["ssid"] | "");
  a.ch   = o["ch"]  | o["channel"] | 0;
  cpy(a.enc, sizeof(a.enc), o["enc"] | o["encryption"] | "");
  a.rssi = o["rssi"] | (int)-128;
  cpy(a.vendor, sizeof(a.vendor), o["vendor"] | "");
  cpy(a.flag, sizeof(a.flag), o["threat"] | o["flag"] | "");
  a.seenMs = millis();
}

static void upsertBLE(JsonObjectConst o) {
  const char* mac = o["mac"] | o["address"] | "";
  if (!*mac) return;
  int idx = -1;
  for (int i = 0; i < g_bleN; i++) if (!strcasecmp(g_ble[i].mac, mac)) { idx = i; break; }
  if (idx < 0) idx = (g_bleN < MAX_BLE_DEVS) ? g_bleN++ : oldestSlot(g_ble, g_bleN);
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
  if (idx < 0) idx = (g_prbN < MAX_PROBES) ? g_prbN++ : oldestSlot(g_prb, g_prbN);
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
  }
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
    for (JsonObjectConst o : doc["aps"].as<JsonArrayConst>())    upsertSniffAP(o);
    for (JsonObjectConst o : doc["alerts"].as<JsonArrayConst>()) pushAlert(o);
    for (JsonObjectConst o : doc["probes"].as<JsonArrayConst>()) upsertProbe(o);
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
// RFC-4180 minimal CSV field: quote if it contains a comma, quote or newline,
// and double any embedded quotes.
static void csvField(AsyncResponseStream* rs, const char* s) {
  if (!s) s = "";
  bool quote = false;
  for (const char* p = s; *p; p++) if (*p==',' || *p=='"' || *p=='\n' || *p=='\r') { quote = true; break; }
  if (!quote) { rs->print(s); return; }
  rs->print('"');
  for (const char* p = s; *p; p++) { if (*p=='"') rs->print('"'); rs->print(*p); }
  rs->print('"');
}

static void handleExportWiFi(AsyncWebServerRequest* req) {
  AsyncResponseStream* rs = req->beginResponseStream("text/csv");
  rs->addHeader("Content-Disposition", "attachment; filename=wifi.csv");
  rs->print("BSSID,SSID,Channel,Encryption,RSSI,Vendor,Flag,AgeSec\n");
  uint32_t now = millis();
  for (int i = 0; i < g_wifiN; i++) {
    csvField(rs, g_wifi[i].mac);  rs->print(',');
    csvField(rs, g_wifi[i].ssid); rs->print(',');
    rs->printf("%u,", (unsigned)g_wifi[i].ch);
    csvField(rs, g_wifi[i].enc);  rs->print(',');
    rs->printf("%d,", (int)g_wifi[i].rssi);
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
  server.on("/api/export/wifi",  HTTP_GET, handleExportWiFi);
  server.on("/api/export/ble",   HTTP_GET, handleExportBLE);
  server.on("/api/export/sniff", HTTP_GET, handleExportSniff);
  server.on(INGEST_PATH, HTTP_POST, handleIngestBody, nullptr, bodyCollector);
  server.on("/api/cmd", HTTP_POST, handleCmdBody, nullptr, bodyCollector);

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
