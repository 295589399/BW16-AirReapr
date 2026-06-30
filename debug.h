#ifndef DEBUG_H
#define DEBUG_H

#include <Arduino.h>

// Forward declarations for types used in function signatures
// (Arduino IDE auto-generates prototypes before user code, so these must be visible early)
struct WiFiScanResult;

//#define DEBUG  // Debug mode toggle

// Set debug serial baud rate
#define DEBUG_BAUD 115200

#ifdef DEBUG
  // If DEBUG is defined, initialize serial communication
  #define DEBUG_SER_INIT() Serial.begin(DEBUG_BAUD);
  // If DEBUG is defined, output debug information
  #define DEBUG_SER_PRINT(...) Serial.print(__VA_ARGS__);
#else
  // If DEBUG is not defined, these macros do nothing
  #define DEBUG_SER_PRINT(...)
  #define DEBUG_SER_INIT()
#endif

#endif
