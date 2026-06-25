// ===========================================================================
//  ESP32-WarSniffer node  —  main.cpp   (ESP32-S3-DevKitC-1 N16R8)
//
//  PASSIVE 802.11 monitor + lightweight WIDS. It channel-hops in promiscuous
//  mode, tallies frame types, maintains an AP/STA inventory, and raises
//  defensive detections (deauth flood / evil-twin / beacon flood). It then
//  interleaves: stop sniffing -> associate to the C2 SoftAP -> POST a metadata
//  snapshot to /ingest -> resume sniffing.
//
//  By design this node TRANSMITS NOTHING on the monitored band (no deauth, no
//  injection, no rogue AP) and stores NO packet payloads or handshakes — only
//  frame counters, AP/STA metadata, and WIDS alerts leave the device.
//
//  AUTHORIZED TESTING ONLY.
// ===========================================================================
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include "config.h"

// ---------------------------------------------------------------------------
//  Inventory + counters (written from the promiscuous callback)
// ---------------------------------------------------------------------------
struct ApInfo {
  uint8_t  bssid[6] = {0};
  char     ssid[33] = {0};
  uint8_t  ch       = 0;
  int8_t   rssiBest = -128;
  int8_t   rssiLast = -128;
  uint16_t clients  = 0;
  uint32_t lastMs   = 0;
  bool     used     = false;
};
struct StaInfo { uint8_t mac[6]; int apIdx; bool used; };
struct AlertRec { char type[16]; uint8_t bssid[6]; char detail[40]; uint32_t tMs; };
// Directed probe-request SSIDs — a client's preferred-network list (PNL). Purely
// passive: these are SSIDs nearby devices actively broadcast that they remember.
struct ProbeReq { char ssid[33]; uint16_t hits; uint32_t lastMs; bool used; };

// Live packet capture: a small per-window buffer of raw frame prefixes shipped
// to the C2 for the Wireshark-style dashboard view.
struct CapPkt { uint8_t ch; int8_t rssi; uint16_t len; uint8_t caplen; uint8_t data[CAP_SNAPLEN]; };
// Watchlist: MAC/OUI entries (len 3 = OUI match, 6 = full-MAC match) pushed from
// the C2 so we can flag known malicious / surveillance devices on sight.
struct WatchEnt { uint8_t mac[6]; uint8_t len; char label[24]; };
struct WatchHit { uint8_t mac[6]; };

static ApInfo   g_aps[MAX_APS];
static StaInfo  g_stas[MAX_STAS]; static int g_staN = 0;
static AlertRec g_alerts[MAX_ALERTS]; static int g_alertHead = 0, g_alertCnt = 0;
static ProbeReq g_probes[MAX_PROBES]; static int g_probeN = 0;
static CapPkt   g_cap[CAP_RING];      static int g_capN = 0;     // buffered this window
static WatchEnt g_watch[MAX_WATCH];   static int g_watchN = 0;
static WatchHit g_whits[MAX_WATCH_HITS]; static int g_whitN = 0;
static uint32_t g_watchVer = 0;       // version of the watchlist we hold

static volatile uint32_t cTotal=0,cMgmt=0,cCtrl=0,cData=0,
                         cBeacon=0,cProbe=0,cDeauth=0,cEapol=0,cDropped=0;

static portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;

// WIDS sliding-window accumulators
static uint32_t widsWinStart = 0;
static uint32_t deauthInWin  = 0;
static uint32_t ssidsInWin   = 0;

// runtime state
static volatile bool g_capturing = true;
static bool     g_hop       = true;
static uint8_t  g_channel   = CHANNEL_MIN;
static uint32_t g_bootMs    = 0;
static uint32_t g_lastReportOkMs = 0;   // for the reboot watchdog

// C2 link bookkeeping (epoch + command ack)
static uint32_t g_linkEpoch = 0;
static uint32_t g_lastCmdId = 0;

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------
static inline bool macEq(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}
static void macStr(const uint8_t* m, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}

// Record a directed probe-request SSID (caller holds g_mux). Bounded inventory:
// dedupe by SSID, drop silently once full.
static void noteProbe(const char* ssid) {
  if (!ssid || !*ssid) return;                 // ignore wildcard/broadcast probes
  for (int i = 0; i < g_probeN; i++)
    if (!strcmp(g_probes[i].ssid, ssid)) {
      if (g_probes[i].hits < 0xFFFF) g_probes[i].hits++;
      g_probes[i].lastMs = millis();
      return;
    }
  if (g_probeN >= MAX_PROBES) return;
  ProbeReq& p = g_probes[g_probeN++];
  strncpy(p.ssid, ssid, sizeof(p.ssid)-1); p.ssid[sizeof(p.ssid)-1]=0;
  p.hits = 1; p.lastMs = millis(); p.used = true;
}

// ---------------------------------------------------------------------------
//  Status LED (onboard WS2812 on the DevKitC-1). neopixelWrite() is built into
//  the Arduino-ESP32 core — no extra library dependency.
// ---------------------------------------------------------------------------
static inline void setLed(uint8_t r, uint8_t g, uint8_t b) {
  if (!STATUS_LED_ENABLED) return;
  neopixelWrite(STATUS_LED_PIN,
                (uint16_t)r * LED_BRIGHTNESS / 255,
                (uint16_t)g * LED_BRIGHTNESS / 255,
                (uint16_t)b * LED_BRIGHTNESS / 255);
}

static int findOrAddAp(const uint8_t* bssid) {
  int free = -1;
  for (int i = 0; i < MAX_APS; i++) {
    if (g_aps[i].used && macEq(g_aps[i].bssid, bssid)) return i;
    if (!g_aps[i].used && free < 0) free = i;
  }
  if (free < 0) return -1;
  memset(&g_aps[free], 0, sizeof(ApInfo));
  memcpy(g_aps[free].bssid, bssid, 6);
  g_aps[free].used = true;
  g_aps[free].rssiBest = -128;
  return free;
}

// count a unique client MAC against an AP (capped, best-effort)
static void noteClient(const uint8_t* sta, int apIdx) {
  if (apIdx < 0) return;
  for (int i = 0; i < g_staN; i++)
    if (g_stas[i].used && macEq(g_stas[i].mac, sta)) {
      if (g_stas[i].apIdx != apIdx) g_stas[i].apIdx = apIdx;
      return;
    }
  if (g_staN >= MAX_STAS) return;
  memcpy(g_stas[g_staN].mac, sta, 6);
  g_stas[g_staN].apIdx = apIdx;
  g_stas[g_staN].used  = true;
  g_staN++;
  if (g_aps[apIdx].clients < 0xFFFF) g_aps[apIdx].clients++;
}

static void addAlert(const char* type, const uint8_t* bssid, const char* detail) {
  int slot = (g_alertHead + g_alertCnt) % MAX_ALERTS;
  AlertRec& r = g_alerts[slot];
  strncpy(r.type, type, sizeof(r.type)-1); r.type[sizeof(r.type)-1]=0;
  if (bssid) memcpy(r.bssid, bssid, 6); else memset(r.bssid, 0, 6);
  strncpy(r.detail, detail, sizeof(r.detail)-1); r.detail[sizeof(r.detail)-1]=0;
  r.tMs = millis();
  if (g_alertCnt < MAX_ALERTS) g_alertCnt++;
  else g_alertHead = (g_alertHead + 1) % MAX_ALERTS;   // overwrite oldest
}

// Return the watchlist label for a MAC (OUI or full match), or nullptr.
// Caller holds g_mux.
static const char* watchMatch(const uint8_t* mac) {
  for (int i = 0; i < g_watchN; i++) {
    uint8_t n = g_watch[i].len ? g_watch[i].len : 6;
    if (memcmp(g_watch[i].mac, mac, n) == 0) return g_watch[i].label;
  }
  return nullptr;
}
// Raise a WATCHLIST alert the first time a matching MAC is seen (dedupe so a
// chatty device doesn't flood the alert log). Caller holds g_mux.
static void noteWatch(const uint8_t* mac) {
  if (g_watchN == 0) return;
  const char* label = watchMatch(mac);
  if (!label) return;
  for (int i = 0; i < g_whitN; i++) if (macEq(g_whits[i].mac, mac)) return;  // already alerted
  if (g_whitN < MAX_WATCH_HITS) { memcpy(g_whits[g_whitN].mac, mac, 6); g_whitN++; }
  char det[40]; snprintf(det, sizeof(det), "%.31s", label);
  addAlert("WATCHLIST", mac, det);
}

// Buffer a raw frame prefix for the live capture view. Time-gated so the buffer
// spreads across the sniff window (multiple channels) instead of filling from
// the first burst. Caller holds g_mux.
static uint32_t g_lastCapMs = 0;
static void capturePkt(const uint8_t* p, int len, uint8_t ch, int8_t rssi) {
  if (g_capN >= CAP_RING) return;                 // window buffer full; ship first
  uint32_t now = millis();
  if (g_capN > 0 && now - g_lastCapMs < CAP_INTERVAL_MS) return;
  g_lastCapMs = now;
  CapPkt& c = g_cap[g_capN++];
  c.ch = ch; c.rssi = rssi; c.len = (uint16_t)len;
  uint8_t cap = len < CAP_SNAPLEN ? (uint8_t)len : CAP_SNAPLEN;
  c.caplen = cap;
  memcpy(c.data, p, cap);
}

// ---------------------------------------------------------------------------
//  Promiscuous RX callback  (runs in the WiFi task — keep it short)
// ---------------------------------------------------------------------------
static void IRAM_ATTR sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_capturing) return;
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*) buf;
  const uint8_t* p = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) { portENTER_CRITICAL_ISR(&g_mux); cDropped++; portEXIT_CRITICAL_ISR(&g_mux); return; }

  uint16_t fc       = p[0] | (p[1] << 8);
  uint8_t  ftype    = (fc >> 2) & 0x3;
  uint8_t  fsubtype = (fc >> 4) & 0xF;
  int8_t   rssi     = pkt->rx_ctrl.rssi;
  uint8_t  ch       = pkt->rx_ctrl.channel;

  const uint8_t* addr1 = p + 4;     // RA / DA
  const uint8_t* addr2 = (len >= 16) ? p + 10 : nullptr;   // TA / SA
  const uint8_t* addr3 = (len >= 22) ? p + 16 : nullptr;   // BSSID (infra)

  portENTER_CRITICAL_ISR(&g_mux);
  cTotal++;
  switch (ftype) {
    case 0: cMgmt++; break;
    case 1: cCtrl++; break;
    case 2: cData++; break;
    default: break;
  }

  if (ftype == 0) {                 // management
    if (fsubtype == 8) {            // beacon
      cBeacon++; ssidsInWin++;
      if (addr2) {
        int ai = findOrAddAp(addr2);
        if (ai >= 0) {
          g_aps[ai].ch = ch; g_aps[ai].rssiLast = rssi;
          if (rssi > g_aps[ai].rssiBest) g_aps[ai].rssiBest = rssi;
          g_aps[ai].lastMs = millis();
          // SSID from tagged params: header(24)+ts(8)+interval(2)+caps(2)=36
          if (len > 38 && p[36] == 0x00) {
            uint8_t sl = p[37];
            if (sl > 0 && sl <= 32 && 38 + sl <= len) {
              // evil-twin check: same SSID, different BSSID, big RSSI delta
              char tmp[33]; memcpy(tmp, p + 38, sl); tmp[sl] = 0;
              for (int j = 0; j < MAX_APS; j++) {
                if (j == ai || !g_aps[j].used) continue;
                if (!strcmp(g_aps[j].ssid, tmp) && !macEq(g_aps[j].bssid, addr2)) {
                  int d = (int)g_aps[j].rssiBest - (int)rssi;
                  if (d < 0) d = -d;
                  if (d >= EVIL_TWIN_RSSI_DELTA) {
                    char det[40]; snprintf(det, sizeof(det), "dup SSID '%s' dRSSI=%d", tmp, d);
                    addAlert("EVIL-TWIN", addr2, det);
                  }
                }
              }
              memcpy(g_aps[ai].ssid, p + 38, sl); g_aps[ai].ssid[sl] = 0;
            }
          }
        }
      }
    } else if (fsubtype == 5) {     // probe response -> also names an AP
      cBeacon++; if (addr2) { int ai = findOrAddAp(addr2);
        if (ai >= 0) { g_aps[ai].ch = ch; g_aps[ai].rssiLast = rssi; g_aps[ai].lastMs = millis(); } }
    } else if (fsubtype == 4) {     // probe request (from a STA)
      cProbe++;
      // SSID is the first tagged param: header(24) -> [id=0][len][ssid...]
      if (len > 26 && p[24] == 0x00) {
        uint8_t sl = p[25];
        if (sl > 0 && sl <= 32 && 26 + sl <= len) {
          char tmp[33]; memcpy(tmp, p + 26, sl); tmp[sl] = 0;
          noteProbe(tmp);
        }
      }
    } else if (fsubtype == 12 || fsubtype == 10) {  // deauth / disassoc
      cDeauth++; deauthInWin++;
      if (deauthInWin == DEAUTH_THRESHOLD && addr2) {
        char det[40]; snprintf(det, sizeof(det), "%lu deauth/disassoc <1s", (unsigned long)deauthInWin);
        addAlert("DEAUTH-FLOOD", addr2, det);
      }
    }
  } else if (ftype == 2) {          // data
    bool toDs   = fc & 0x0100;
    bool fromDs = fc & 0x0200;
    // associate client<->AP for client counts
    if (addr3) {
      int ai = findOrAddAp(addr3);  // addr3 is BSSID for to/from-DS data
      if (ai >= 0) {
        const uint8_t* sta = nullptr;
        if (toDs && !fromDs && addr2) sta = addr2;        // STA -> AP
        else if (!toDs && fromDs && addr1) sta = addr1;   // AP -> STA
        if (sta) noteClient(sta, ai);
        g_aps[ai].rssiLast = rssi; g_aps[ai].lastMs = millis();
      }
    }
    // EAPOL visibility (count only; never stored). LLC/SNAP ethertype 0x888E.
    int hdr = 24; if (fc & 0x0080) hdr += 2;             // QoS data adds 2
    if (len >= hdr + 8) {
      const uint8_t* llc = p + hdr;
      if (llc[0]==0xAA && llc[1]==0xAA && llc[6]==0x88 && llc[7]==0x8E) cEapol++;
    }
  }

  // Watchlist: flag known malicious / surveillance MACs (transmitter + BSSID).
  if (g_watchN) {
    if (addr2) noteWatch(addr2);
    if (addr3 && (!addr2 || !macEq(addr3, addr2))) noteWatch(addr3);
  }
  // Buffer this frame for the live Wireshark-style capture view.
  capturePkt(p, len, ch, rssi);

  portEXIT_CRITICAL_ISR(&g_mux);
}

// ---------------------------------------------------------------------------
//  Capture control
// ---------------------------------------------------------------------------
static void startSniffer() {
  // STA mode (not NULL) gives a reliably-started driver for promiscuous mode —
  // with NULL mode the driver can be stopped and promiscuous silently captures
  // nothing. We never associate here, so the STA just parks on the set channel.
  WiFi.disconnect(true, false);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  delay(10);                       // let the mode change settle before promiscuous
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffCb);
  esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
  widsWinStart = millis(); deauthInWin = 0; ssidsInWin = 0;
}
static void stopSniffer() {
  esp_wifi_set_promiscuous(false);
}

static void widsTick() {
  uint32_t now = millis();
  if (now - widsWinStart >= DEAUTH_WINDOW_MS) {
    portENTER_CRITICAL(&g_mux);
    if (ssidsInWin >= BEACON_FLOOD_THRESHOLD) {
      char det[40]; snprintf(det, sizeof(det), "%lu unique SSIDs <1s", (unsigned long)ssidsInWin);
      addAlert("BEACON-FLOOD", nullptr, det);
    }
    deauthInWin = 0; ssidsInWin = 0; widsWinStart = now;
    portEXIT_CRITICAL(&g_mux);
  }
}

static void clearStore() {
  portENTER_CRITICAL(&g_mux);
  for (int i = 0; i < MAX_APS; i++) g_aps[i].used = false;
  g_staN = 0;
  for (int i = 0; i < MAX_STAS; i++) g_stas[i].used = false;
  g_alertHead = g_alertCnt = 0;
  g_probeN = 0;
  g_capN = 0;
  g_whitN = 0;            // forget watchlist hits so they can re-alert
  cTotal=cMgmt=cCtrl=cData=cBeacon=cProbe=cDeauth=cEapol=cDropped=0;
  portEXIT_CRITICAL(&g_mux);
}

// ---------------------------------------------------------------------------
//  Report cycle: associate to C2, POST snapshot, apply returned commands
// ---------------------------------------------------------------------------
static void applyCommands(JsonArrayConst cmds) {
  for (JsonObjectConst c : cmds) {
    uint32_t id = c["id"] | 0;
    if (id <= g_lastCmdId) continue;
    const char* cmd = c["cmd"] | "";
    bool hasOn = c["on"].is<int>();
    int  on    = hasOn ? (int)c["on"] : -1;
    Serial.printf("[WS] cmd #%lu %s on=%d\n", (unsigned long)id, cmd, on);
    if      (!strcmp(cmd, "scan"))  g_capturing = hasOn ? (on != 0) : !g_capturing;
    else if (!strcmp(cmd, "hop"))   g_hop       = hasOn ? (on != 0) : !g_hop;
    else if (!strcmp(cmd, "clear")) clearStore();
    else if (!strcmp(cmd, "config")) { if (hasOn && on >= CHANNEL_MIN && on <= CHANNEL_MAX) g_channel = on; }
    g_lastCmdId = id;
  }
}

// Replace the in-RAM watchlist with one pushed from the C2. Safe to mutate
// without the lock: the promiscuous sniffer (the only other reader) is stopped
// during the report cycle in which this runs.
static void applyWatchlist(JsonArrayConst arr, uint32_t ver) {
  g_watchN = 0;
  for (JsonObjectConst e : arr) {
    if (g_watchN >= MAX_WATCH) break;
    const char* mac = e["mac"] | "";
    unsigned b[6] = {0}; uint8_t len = 0;
    int got = sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                     &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    if (got == 3)      len = 3;          // OUI prefix
    else if (got == 6) len = 6;          // full MAC
    else continue;
    WatchEnt& w = g_watch[g_watchN++];
    for (int i = 0; i < 6; i++) w.mac[i] = (uint8_t)b[i];
    w.len = len;
    strncpy(w.label, e["label"] | "", sizeof(w.label)-1); w.label[sizeof(w.label)-1]=0;
  }
  g_watchVer = ver;
  g_whitN = 0;                            // re-evaluate hits against the new list
}

static void hexAppend(String& s, const uint8_t* d, int n) {
  static const char* H = "0123456789abcdef";
  for (int i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 0xF]; }
}

static void reportToC2() {
  stopSniffer();

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(C2_SSID, C2_PASSWORD);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < WIFI_CONNECT_MS) delay(100);
  if (WiFi.status() != WL_CONNECTED) { startSniffer(); return; }

  // snapshot under lock
  JsonDocument doc;
  doc["source"]    = SRC_NAME;
  doc["ver"]       = FW_VERSION;
  doc["linkEpoch"] = g_linkEpoch;
  doc["lastCmdId"] = g_lastCmdId;
  doc["watchVer"]  = g_watchVer;        // C2 re-pushes the watchlist if stale

  JsonObject st = doc["status"].to<JsonObject>();
  st["capturing"] = g_capturing ? 1 : 0;
  st["channel"]   = g_channel;
  st["hopping"]   = g_hop ? 1 : 0;
  st["uptime"]    = (millis() - g_bootMs) / 1000;
  st["heap"]      = ESP.getFreeHeap();
  st["psram"]     = ESP.getFreePsram();
  st["dropped"]   = cDropped;
  JsonObject fr = st["frames"].to<JsonObject>();

  portENTER_CRITICAL(&g_mux);
  fr["total"]=cTotal; fr["mgmt"]=cMgmt; fr["ctrl"]=cCtrl; fr["data"]=cData;
  fr["beacon"]=cBeacon; fr["probe"]=cProbe; fr["deauth"]=cDeauth; fr["eapol"]=cEapol;

  // strongest APs first (simple selection, capped at UPLINK_AP_MAX)
  JsonArray aps = doc["aps"].to<JsonArray>();
  bool taken[MAX_APS] = {false};
  for (int n = 0; n < UPLINK_AP_MAX; n++) {
    int best = -1; int bestR = -200;
    for (int i = 0; i < MAX_APS; i++)
      if (g_aps[i].used && !taken[i] && g_aps[i].rssiBest > bestR) { bestR = g_aps[i].rssiBest; best = i; }
    if (best < 0) break;
    taken[best] = true;
    char mac[18]; macStr(g_aps[best].bssid, mac);
    JsonObject a = aps.add<JsonObject>();
    a["bssid"]=mac; a["ssid"]=g_aps[best].ssid; a["ch"]=g_aps[best].ch;
    a["rssi"]=g_aps[best].rssiBest; a["clients"]=g_aps[best].clients;
  }
  // recent alerts (newest first)
  JsonArray al = doc["alerts"].to<JsonArray>();
  int emitted = 0;
  for (int k = 0; k < g_alertCnt && emitted < UPLINK_ALERT_MAX; k++, emitted++) {
    int idx = (g_alertHead + g_alertCnt - 1 - k) % MAX_ALERTS;
    char mac[18]; macStr(g_alerts[idx].bssid, mac);
    JsonObject a = al.add<JsonObject>();
    a["type"]=g_alerts[idx].type; a["bssid"]=mac; a["detail"]=g_alerts[idx].detail;
  }
  // probed SSIDs (client PNLs) — most-recently-seen first, capped
  JsonArray pr = doc["probes"].to<JsonArray>();
  bool pTaken[MAX_PROBES] = {false};
  for (int n = 0; n < UPLINK_PROBE_MAX; n++) {
    int best = -1; uint32_t bestT = 0;
    for (int i = 0; i < g_probeN; i++)
      if (g_probes[i].used && !pTaken[i] && (best < 0 || g_probes[i].lastMs >= bestT))
        { bestT = g_probes[i].lastMs; best = i; }
    if (best < 0) break;
    pTaken[best] = true;
    JsonObject po = pr.add<JsonObject>();
    po["ssid"] = g_probes[best].ssid; po["hits"] = g_probes[best].hits;
  }
  doc["count"] = aps.size();
  portEXIT_CRITICAL(&g_mux);

  // Live capture frames (no lock needed: the sniffer is stopped during report).
  JsonArray pk = doc["packets"].to<JsonArray>();
  int npk = g_capN < UPLINK_PKT_MAX ? g_capN : UPLINK_PKT_MAX;
  for (int i = 0; i < npk; i++) {
    JsonObject o = pk.add<JsonObject>();
    o["ch"] = g_cap[i].ch; o["rssi"] = g_cap[i].rssi; o["len"] = g_cap[i].len;
    String hx; hexAppend(hx, g_cap[i].data, g_cap[i].caplen);
    o["data"] = hx;
  }
  g_capN = 0;                          // window buffer drained

  String body; serializeJson(doc, body);

  HTTPClient http; WiFiClient client;
  String url = String("http://") + C2_HOST + C2_INGEST_PATH;
  if (http.begin(client, url)) {
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    if (code == 200) {
      g_lastReportOkMs = millis();          // feed the reboot watchdog
      String resp = http.getString();
      JsonDocument rd;
      if (!deserializeJson(rd, resp)) {
        uint32_t newEpoch = rd["epoch"] | 0;
        if (newEpoch && newEpoch != g_linkEpoch) { g_linkEpoch = newEpoch; g_lastCmdId = 0; }
        applyCommands(rd["commands"].as<JsonArrayConst>());
        // Watchlist push: the C2 includes the full list only when ours is stale.
        if (rd["watch"].is<JsonArrayConst>())
          applyWatchlist(rd["watch"].as<JsonArrayConst>(), rd["watchVer"] | 0);
      }
    }
    http.end();
  }

  WiFi.disconnect(true, false);
  startSniffer();
}

// ---------------------------------------------------------------------------
//  Setup / loop
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\nESP32-WarSniffer node booting (passive monitor + WIDS)...");
  g_bootMs = millis();
  g_lastReportOkMs = millis();      // grace period before the watchdog can fire
  setLed(0, 0, 16);                 // boot: dim blue
  WiFi.persistent(false);
  startSniffer();
}

void loop() {
  // ---- SNIFF phase ----
  uint32_t phaseStart = millis();
  uint32_t lastHop = millis();
  // green while sniffing, red if a WIDS alert fired in the last few seconds
  bool recentAlert = g_alertCnt > 0 &&
                     (millis() - g_alerts[(g_alertHead + g_alertCnt - 1) % MAX_ALERTS].tMs) < 4000;
  if (!g_capturing)      setLed(8, 4, 0);     // dim amber: capture stopped
  else if (recentAlert)  setLed(64, 0, 0);    // red: recent WIDS alert
  else                   setLed(0, 48, 0);     // green: actively sniffing
  while (millis() - phaseStart < SNIFF_WINDOW_MS) {
    if (g_capturing && g_hop && millis() - lastHop >= HOP_INTERVAL_MS) {
      g_channel++; if (g_channel > CHANNEL_MAX) g_channel = CHANNEL_MIN;
      esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
      lastHop = millis();
    }
    widsTick();
    delay(5);
  }
  // ---- REPORT phase ----
  setLed(0, 0, 48);                            // blue: associating + POSTing
  reportToC2();

  // reboot watchdog: if the C2 has been unreachable far too long, the WiFi/
  // promiscuous stack may be wedged — restart clean.
  if (millis() - g_lastReportOkMs > WIFI_WATCHDOG_MS) {
    Serial.println("[WS] no C2 contact too long — rebooting");
    delay(50); ESP.restart();
  }

  static uint32_t hb = 0;
  if (millis() - hb > 1000) {
    hb = millis();
    Serial.printf("[WS] cap=%d ch=%d total=%lu beacon=%lu deauth=%lu eapol=%lu aps=%d heap=%u\n",
      g_capturing, g_channel, (unsigned long)cTotal, (unsigned long)cBeacon,
      (unsigned long)cDeauth, (unsigned long)cEapol,
      []{int n=0;for(int i=0;i<MAX_APS;i++)if(g_aps[i].used)n++;return n;}(),
      (unsigned)ESP.getFreeHeap());
  }
}
