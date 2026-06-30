#include "wifi_cust_tx.h"

/*
 * Send a raw 802.11 frame of the specified length
 * The frame must be valid and have sequence number 0 (will be set automatically)
 * FCS is automatically appended, do not include it in the length
 * @param frame Pointer to the raw frame
 * @param size Frame size
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  // ★ Safety check: payload must not exceed available data area space (otherwise stack/heap corruption → unrecoverable crash)
  if (length > RTK_FRAME_MAX_PAYLOAD) {
    Serial.print("[TX] Frame length exceeds limit: ");
    Serial.print(length);
    Serial.print(" > ");
    Serial.println(RTK_FRAME_MAX_PAYLOAD);
    return;
  }

  void *ptr = (void *)**(uint32_t **)((uint8_t*)rltk_wlan_info + RTK_WLAN_INFO_PTR_OFFSET);
  void *frame_control = alloc_mgtxmitframe((uint8_t*)ptr + RTK_MGTXMITFRAME_OFFSET);

  if (frame_control != 0) {
    // Update frame attributes
    update_mgntframe_attrib(ptr, (uint8_t*)frame_control + RTK_FRAME_ATTRIB_OFFSET);
    // Clear frame control data area
    memset((void *)*(uint32_t *)((uint8_t*)frame_control + RTK_FRAME_DATA_AREA_OFFSET), 0, RTK_FRAME_DATA_AREA_SIZE);
    // Get frame data pointer and copy data
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)((uint8_t*)frame_control + RTK_FRAME_DATA_AREA_OFFSET) + RTK_FRAME_DATA_PAYLOAD_OFF;
    memcpy(frame_data, frame, length);
    // Set frame length
    *(uint32_t *)((uint8_t*)frame_control + RTK_FRAME_LEN_FIELD1_OFFSET) = length;
    *(uint32_t *)((uint8_t*)frame_control + RTK_FRAME_LEN_FIELD2_OFFSET) = length;
    // Send frame
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * Send an 802.11 deauthentication frame on the current channel
 * @param src_mac Byte array containing sender MAC address, must be 6 bytes
 * @param dst_mac Byte array containing target MAC address, or use FF:FF:FF:FF:FF:FF for broadcast
 * @param reason Reason code conforming to 802.11 specification (optional)
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  // Set source MAC address
  memcpy(&frame.source, src_mac, 6);
  // Set access point MAC address
  memcpy(&frame.access_point, src_mac, 6);
  // Set destination MAC address
  memcpy(&frame.destination, dst_mac, 6);
  // Set deauthentication reason
  frame.reason = reason;
  // Send frame
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * Send a basic 802.11 beacon frame on the current channel
 * @param src_mac Byte array containing sender MAC address, must be 6 bytes
 * @param dst_mac Byte array containing target MAC address, or use FF:FF:FF:FF:FF:FF for broadcast
 * @param ssid Null-terminated char array representing the SSID
*/
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  // Set source MAC address
  memcpy(&frame.source, src_mac, 6);
  // Set access point MAC address
  memcpy(&frame.access_point, src_mac, 6);
  // Set destination MAC address
  memcpy(&frame.destination, dst_mac, 6);
  // Copy SSID and calculate length (with bounds check to prevent out-of-bounds stack corruption)
  int max_ssid = RTK_FRAME_MAX_PAYLOAD - 38;
  for (int i = 0; i < max_ssid && i < 254 && ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  // Send frame (size = base 38 bytes + SSID length)
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

size_t wifi_build_beacon_frame(void* src_mac, void* dst_mac, const char *ssid, BeaconFrame &out) {
  // Pre-build beacon frame buffer for reuse
  memcpy(&out.source, src_mac, 6);
  memcpy(&out.access_point, src_mac, 6);
  memcpy(&out.destination, dst_mac, 6);
  out.ssid_length = 0;
  int max_ssid = RTK_FRAME_MAX_PAYLOAD - 38;
  for (int i = 0; i < max_ssid && i < 254 && ssid[i] != '\0'; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  return 38 + out.ssid_length;
}

void wifi_tx_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid) {
  ProbeRespFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.ssid_length = 0;
  int max_ssid = RTK_FRAME_MAX_PAYLOAD - 38;
  for (int i = 0; i < max_ssid && i < 254 && ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

size_t wifi_build_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid, ProbeRespFrame &out) {
  memcpy(&out.source, src_mac, 6);
  memcpy(&out.access_point, src_mac, 6);
  memcpy(&out.destination, dst_mac, 6);
  out.ssid_length = 0;
  const int maxSSID = RTK_FRAME_MAX_PAYLOAD - 38;
  for (int i = 0; i < maxSSID && ssid[i] != '\0'; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  return 38 + out.ssid_length;
}

size_t wifi_build_auth_req(void* sta_mac, void* bssid, AuthReqFrame &out) {
  memcpy(&out.source, sta_mac, 6);
  memcpy(&out.destination, bssid, 6);
  memcpy(&out.bssid, bssid, 6);
  out.auth_algorithm = 0x0000; // Open System
  out.auth_sequence = 0x0001;
  out.status_code = 0x0000;
  return sizeof(AuthReqFrame);
}

void wifi_tx_auth_req(void* sta_mac, void* bssid) {
  AuthReqFrame frame;
  size_t len = wifi_build_auth_req(sta_mac, bssid, frame);
  wifi_tx_raw_frame(&frame, len);
}

size_t wifi_build_assoc_req(void* sta_mac, void* bssid, const char* ssid, AssocReqFrame &out) {
  memcpy(&out.source, sta_mac, 6);
  memcpy(&out.destination, bssid, 6);
  memcpy(&out.bssid, bssid, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid && ssid[i] != '\0' && i < 32; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  // Fixed capabilities and listen interval are already set in the struct
  // Assoc request frame length = 24-byte MAC header (approximated by struct prefix) + fixed fields (4) + IE (2+len)
  // Struct is laid out linearly, so return the effective occupied length directly
  return sizeof(AssocReqFrame) - (32 - out.ssid_length);
}

void wifi_tx_assoc_req(void* sta_mac, void* bssid, const char* ssid) {
  AssocReqFrame frame;
  size_t len = wifi_build_assoc_req(sta_mac, bssid, ssid, frame);
  wifi_tx_raw_frame(&frame, len);
}


void wifi_tx_broadcast_deauth(void* bssid, uint16_t reason, int burstCount, int interDelayUs) {
  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, broadcast, 6);
  frame.reason = reason;
  for (int i = 0; i < burstCount; i++) {
    wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
    if (interDelayUs > 0) delayMicroseconds(interDelayUs);
  }
}

typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xA0;      // Disassociation
  uint16_t duration = 0x0000;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t bssid[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x0008;           // Disassoc due to inactivity by default
} DisassocFrame;

void wifi_tx_broadcast_disassoc(void* bssid, uint16_t reason, int burstCount, int interDelayUs) {
  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  DisassocFrame frame = {};
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.bssid, bssid, 6);
  memcpy(&frame.destination, broadcast, 6);
  frame.reason = reason;
  for (int i = 0; i < burstCount; i++) {
    wifi_tx_raw_frame(&frame, sizeof(DisassocFrame));
    if (interDelayUs > 0) delayMicroseconds(interDelayUs);
  }
}

