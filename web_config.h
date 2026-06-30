#ifndef WEB_CONFIG_H
#define WEB_CONFIG_H

// Web UI configuration
#define WEB_UI_SSID "BW16-AirReapr"        // AP SSID name
#define WEB_UI_PASSWORD "1234567890"     // AP password (at least 8 characters)
#define WEB_UI_CHANNEL 1                 // AP channel
#define WEB_UI_MAX_CONNECTIONS 4         // Maximum connections
#define WEB_SERVER_PORT 80               // Web server port

// Web Test configuration (open SSID, no password)
#define WEB_TEST_SSID "BW16-WebTest"    // Test AP SSID name (no password)
#define WEB_TEST_CHANNEL 1               // Test AP channel

// Configuration notes:
// 1. SSID name: Network name displayed in the WiFi list
// 2. Password: Password required to connect to the AP
// 3. Channel: WiFi channel the AP operates on (1-13 for 2.4GHz, 36+ for 5GHz)
// 4. Max connections: Maximum number of devices that can connect simultaneously
// 5. Web server port: HTTP service port number

// Modify these values to customize your Web UI settings
// Note: Password must be at least 8 characters, otherwise AP cannot start

#endif
