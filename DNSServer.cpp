#include "DNSServer.h"

static DNSServer* dnsServerInstance = NULL;

DNSServer::DNSServer() {
    _resolvedIP[0] = 192;
    _resolvedIP[1] = 168;
    _resolvedIP[2] = 1;
    _resolvedIP[3] = 1;
    _dns_server_pcb = NULL;
}

// ★ Destructor: ensure global singleton pointer is cleared to prevent lwIP async callbacks from accessing the destroyed object
DNSServer::~DNSServer() {
    stop();
}

void DNSServer::setResolvedIP(uint8_t ip0, uint8_t ip1, uint8_t ip2, uint8_t ip3) {
    _resolvedIP[0] = ip0;
    _resolvedIP[1] = ip1;
    _resolvedIP[2] = ip2;
    _resolvedIP[3] = ip3;
}

bool DNSServer::requestIncludesOnlyOneQuestion(DNSHeader &dnsHeader) {
    // ★ Only check QCount: modern device DNS queries carry EDNS0 OPT records (ARCount>0)
    //   Must ignore ARCount, otherwise DNS returns SERVFAIL → device falls back to cellular DNS → captive portal won't pop up
    return ntohs(dnsHeader.QDCount) == 1 && dnsHeader.ANCount == 0 && dnsHeader.NSCount == 0;
}

void DNSServer::begin() {
    dnsServerInstance = this;
    
    // ★ Safely remove all existing DNS PCBs (including AmebaD built-in dhcps DNS server)
    //   Must use while+next pattern to avoid use-after-free
    int removed = 0;
    struct udp_pcb *pcb = udp_pcbs;
    while (pcb != NULL) {
        struct udp_pcb *next = pcb->next;
        if (pcb->local_port == DNS_SERVER_PORT) {
            Serial.print("Found existing DNS server PCB (");
            Serial.print((uint32_t)pcb, HEX);
            Serial.println("), removing it");
            udp_remove(pcb);
            removed++;
        }
        pcb = next;
    }
    if (removed > 0) {
        Serial.print("Removed "); Serial.print(removed);
        Serial.println(" existing DNS PCB(s), waiting for cleanup...");
        delay(100);  // ★ Wait for lwIP to finish async release
    }

    _dns_server_pcb = udp_new();
    if (!_dns_server_pcb) {
        Serial.println("ERROR: udp_new() failed for DNS server!");
        dnsServerInstance = NULL;
        return;
    }
    Serial.println("Created new DNS server PCB");
    
    // ★ Verify bind result — if built-in DNS PCB is not fully released, bind will fail
    err_t err = udp_bind(_dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT);
    if (err != ERR_OK) {
        Serial.print("ERROR: udp_bind() failed with err=");
        Serial.println(err);
        Serial.println("Port 53 may still be occupied by built-in DNS server!");
        // ★ Retry: traverse again and force remove
        pcb = udp_pcbs;
        while (pcb != NULL) {
            struct udp_pcb *next = pcb->next;
            if (pcb->local_port == DNS_SERVER_PORT) {
                Serial.println("Force-removing leftover DNS PCB");
                udp_remove(pcb);
            }
            pcb = next;
        }
        delay(100);
        err = udp_bind(_dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT);
        if (err != ERR_OK) {
            Serial.println("FATAL: DNS server bind RETRY also failed!");
            udp_remove(_dns_server_pcb);
            _dns_server_pcb = NULL;
            dnsServerInstance = NULL;
            return;
        }
    }
    
    udp_recv(_dns_server_pcb, (udp_recv_fn)packetHandler, NULL);
    Serial.println("DNS server bound to port 53 - OK");
}

void DNSServer::stop() {
    if (_dns_server_pcb) {
        udp_remove(_dns_server_pcb);
        _dns_server_pcb = NULL;
        dnsServerInstance = NULL;
        Serial.println("DNS server stopped and PCB removed");
    }
}

void DNSServer::packetHandler(void *arg, struct udp_pcb *udp_pcb, struct pbuf *udp_packet_buffer, struct ip_addr *sender_addr, uint16_t sender_port) {
    (void)arg;
    
    if (!dnsServerInstance || !udp_packet_buffer || udp_packet_buffer->len < DNS_HEADER_SIZE) {
        if (udp_packet_buffer) pbuf_free(udp_packet_buffer);
        return;
    }

    DNSHeader dnsHeader;
    DNSQuestion dnsQuestion;
    
    memcpy(&dnsHeader, udp_packet_buffer->payload, DNS_HEADER_SIZE);

    if (dnsServerInstance->requestIncludesOnlyOneQuestion(dnsHeader)) {
        if (udp_packet_buffer->len <= DNS_HEADER_SIZE) {
            pbuf_free(udp_packet_buffer);
            return;
        }
        
        uint16_t offset = DNS_HEADER_SIZE;
        uint16_t nameLength = 0;
        // ★ DNS name field limit: RFC 1035 specifies max 255 bytes; treat exceeding packets as malformed and discard
        while (offset < udp_packet_buffer->len
               && ((uint8_t*)udp_packet_buffer->payload)[offset] != 0
               && nameLength < 255) {
            nameLength++;
            offset++;
        }
        if (nameLength >= 255) {
            // Name too long or not terminated, discard
            pbuf_free(udp_packet_buffer);
            return;
        }
        
        if (offset >= udp_packet_buffer->len - 4) {
            pbuf_free(udp_packet_buffer);
            return;
        }
        
        offset++;
        nameLength++;
        
        dnsQuestion.QName = (uint8_t *)udp_packet_buffer->payload + DNS_HEADER_SIZE;
        dnsQuestion.QNameLength = nameLength;
        int sizeUrl = static_cast<int>(nameLength);

        struct dns_hdr *hdr = (struct dns_hdr *)udp_packet_buffer->payload;
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dns_hdr) + sizeUrl + 20, PBUF_RAM);

        if (p) {
            struct dns_hdr *rsp_hdr = (struct dns_hdr *)p->payload;
            rsp_hdr->id = hdr->id;
            rsp_hdr->flags1 = 0x85;
            rsp_hdr->flags2 = 0x80;
            rsp_hdr->numquestions = PP_HTONS(1);
            rsp_hdr->numanswers = PP_HTONS(1);
            rsp_hdr->numauthrr = PP_HTONS(0);
            rsp_hdr->numextrarr = PP_HTONS(0);

            uint8_t *responsePtr = (uint8_t *)rsp_hdr + sizeof(struct dns_hdr);
            memcpy(responsePtr, dnsQuestion.QName, sizeUrl);
            responsePtr += sizeUrl;
            
            *(uint16_t *)responsePtr = PP_HTONS(1);
            *(uint16_t *)(responsePtr + 2) = PP_HTONS(1);
            responsePtr[4] = 0xc0;
            responsePtr[5] = 0x0c;
            *(uint16_t *)(responsePtr + 6) = PP_HTONS(1);
            *(uint16_t *)(responsePtr + 8) = PP_HTONS(1);
            *(uint32_t *)(responsePtr + 10) = PP_HTONL(60);
            *(uint16_t *)(responsePtr + 14) = PP_HTONS(4);
            memcpy(responsePtr + 16, dnsServerInstance->_resolvedIP, 4);

            udp_sendto(udp_pcb, p, sender_addr, sender_port);
            pbuf_free(p);
        }
    } else {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, udp_packet_buffer->len, PBUF_RAM);
        if (p) {
            memcpy(p->payload, udp_packet_buffer->payload, udp_packet_buffer->len);
            
            struct dns_hdr *dns_rsp = (struct dns_hdr *)p->payload;
            dns_rsp->flags1 |= 0x80;
            dns_rsp->flags2 = 0x05;
            
            udp_sendto(udp_pcb, p, sender_addr, sender_port);
            pbuf_free(p);
        }
    }

    pbuf_free(udp_packet_buffer);
}





