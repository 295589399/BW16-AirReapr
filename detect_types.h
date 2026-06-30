// Attack detection type definitions — standalone .h file, ensures types appear before auto-generated function prototypes during Arduino .ino preprocessing
#ifndef DETECT_TYPES_H
#define DETECT_TYPES_H

#include <WString.h>

enum ThreatLevel { THREAT_NONE = 0, THREAT_LOW, THREAT_MEDIUM, THREAT_HIGH };

struct DetectEntry {
  ThreatLevel level;
  String     description;
  String     detail;
  int        channel;
};

struct DetectStats {
  int totalAPs;
  int openAPs;
  int hiddenAPs;
  int ssidDupGroups;
  int maxChDensity;
  int maxChDensityCh;
  int weakEncryptAPs;
};

#endif
