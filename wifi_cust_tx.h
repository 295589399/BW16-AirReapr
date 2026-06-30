#ifndef WIFI_CUST_TX
#define WIFI_CUST_TX

#include <Arduino.h>

// Type definitions
typedef uint8_t __u8;

// Required constant definitions
#define WLAN0_NAME "wlan0"

// Packed and 4-byte aligned to reduce copy/access misalignment overhead

// Deauthentication frame structure
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xC0;      // Frame control field, set to deauthentication type
  uint16_t duration = 0xFFFF;         // Duration field
  uint8_t destination[6];             // Destination MAC address
  uint8_t source[6];                  // Source MAC address
  uint8_t access_point[6];            // Access point MAC address
  const uint16_t sequence_number = 0;  // Sequence number
  uint16_t reason = 0x06;             // Deauthentication reason code
} DeauthFrame;

// Protected management frame structure with 802.11w support
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xC0;      // Frame control field, set to deauthentication type
  uint16_t duration = 0xFFFF;         // Duration field
  uint8_t destination[6];             // Destination MAC address
  uint8_t source[6];                  // Source MAC address
  uint8_t access_point[6];            // Access point MAC address
  const uint16_t sequence_number = 0;  // Sequence number
  uint16_t reason = 0x06;             // Deauthentication reason code
  uint8_t mic[16];                    // Message Integrity Code
  uint8_t key_replay_counter[8];      // Key replay counter
} ProtectedDeauthFrame;

// Beacon frame structure
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x80;      // Frame control field, set to beacon type
  uint16_t duration = 0;              // Duration field
  uint8_t destination[6];             // Destination MAC address
  uint8_t source[6];                  // Source MAC address
  uint8_t access_point[6];            // Access point MAC address
  const uint16_t sequence_number = 0;  // Sequence number
  const uint64_t timestamp = 0;       // Timestamp
  uint16_t beacon_interval = 0x64;    // Beacon interval
  uint16_t ap_capabilities = 0x21;    // AP capability information
  const uint8_t ssid_tag = 0;         // SSID tag
  uint8_t ssid_length = 0;            // SSID length
  uint8_t ssid[255];                  // SSID content
} BeaconFrame;

// Probe response frame (minimal usable fields, IE layout similar to Beacon)
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x50;      // Type/Subtype: Probe Response
  uint16_t duration = 0;              // Duration
  uint8_t destination[6];             // Destination MAC (broadcast/any)
  uint8_t source[6];                  // Source MAC (spoofed AP)
  uint8_t access_point[6];            // BSSID (same as source MAC)
  const uint16_t sequence_number = 0; // Sequence number
  const uint64_t timestamp = 0;       // Timestamp
  uint16_t beacon_interval = 0x64;    // Interval
  uint16_t ap_capabilities = 0x21;    // Capabilities
  const uint8_t ssid_tag = 0;         // SSID tag
  uint8_t ssid_length = 0;            // SSID length
  uint8_t ssid[255];                  // SSID content
} ProbeRespFrame;

// 802.11 Authentication request frame (Open System) minimal fields
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xB0;      // Type/Subtype: Authentication
  uint16_t duration = 0;
  uint8_t destination[6];             // BSSID / access point
  uint8_t source[6];                  // STA MAC (spoofed)
  uint8_t bssid[6];                   // BSSID
  const uint16_t sequence_number = 0;
  uint16_t auth_algorithm = 0x0000;   // Open System
  uint16_t auth_sequence = 0x0001;    // Seq 1: authentication request
  uint16_t status_code = 0x0000;      // Keep 0
} AuthReqFrame;

// 802.11 Association request frame (minimal usable fields, fixed capability + SSID IE + supported rates IE optional)
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x0000 | (0x0 << 2) | (0x0 << 4); // Placeholder, filled by SDK later or kept as 0
  uint16_t duration = 0;
  uint8_t destination[6];             // BSSID
  uint8_t source[6];                  // STA MAC
  uint8_t bssid[6];                   // BSSID
  const uint16_t sequence_number = 0;
  uint16_t capability = 0x0431;       // Common basic capability set
  uint16_t listen_interval = 0x000A;  // 10 TU
  // IE: SSID
  const uint8_t ssid_tag = 0x00;
  uint8_t ssid_length = 0;
  uint8_t ssid[32];
} AssocReqFrame;

// ★ SDK internal struct offsets — hardcoded, dependent on the specific Realtek SDK version
//   When upgrading SDK, verify these offsets are still valid
#define RTK_WLAN_INFO_PTR_OFFSET    0x10   // rltk_wlan_info + offset → triple indirection dereference
#define RTK_MGTXMITFRAME_OFFSET     0xAE0  // ptr + offset → alloc_mgtxmitframe parameter
#define RTK_FRAME_DATA_AREA_OFFSET  0x80   // frame_control + offset → frame data area pointer
#define RTK_FRAME_DATA_PAYLOAD_OFF  0x28   // data area + offset → actual payload start
#define RTK_FRAME_LEN_FIELD1_OFFSET 0x14   // frame_control + offset → frame length field 1
#define RTK_FRAME_LEN_FIELD2_OFFSET 0x18   // frame_control + offset → frame length field 2
#define RTK_FRAME_ATTRIB_OFFSET     8      // frame_control + offset → update_mgntframe_attrib parameter
#define RTK_FRAME_DATA_AREA_SIZE    0x68   // Total data area size (memset zero range)
#define RTK_FRAME_MAX_PAYLOAD       0x40   // Available payload size = 0x68 - 0x28 (hard limit; exceeding causes stack/heap corruption)

// Import required C functions from the closed-source library
// Note: function definitions may not be 100% accurate as type info is lost during compilation
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

// External function declarations - removed conflicting declarations, use SDK versions

// Function declarations
void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);
// Build beacon frame only without sending, returns frame length for upper layer to reuse buffer for burst transmission
size_t wifi_build_beacon_frame(void* src_mac, void* dst_mac, const char *ssid, BeaconFrame &out);

// Build/send probe response, reusable for upper layer burst transmissions
size_t wifi_build_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid, ProbeRespFrame &out);
void wifi_tx_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid);

// New: protected management frame functions with 802.11w support
void wifi_tx_protected_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason, const uint8_t* mic, const uint8_t* replay_counter);
bool wifi_generate_pmf_mic(const uint8_t* frame, size_t frame_len, const uint8_t* key, uint8_t* mic);
bool wifi_attempt_pmf_attack(const uint8_t* bssid, const uint8_t* client_mac, uint8_t channel);

// New: build and send authentication/association requests
size_t wifi_build_auth_req(void* sta_mac, void* bssid, AuthReqFrame &out);
void wifi_tx_auth_req(void* sta_mac, void* bssid);
size_t wifi_build_assoc_req(void* sta_mac, void* bssid, const char* ssid, AssocReqFrame &out);
void wifi_tx_assoc_req(void* sta_mac, void* bssid, const char* ssid);

// Compat: broadcast deauth/disassociation (lightweight STA wake-up for learning/triggering reconnection)
void wifi_tx_broadcast_deauth(void* bssid, uint16_t reason, int burstCount, int interDelayUs);
void wifi_tx_broadcast_disassoc(void* bssid, uint16_t reason, int burstCount, int interDelayUs);



#endif
