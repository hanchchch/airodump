#include <cstdint>
#include <arpa/inet.h>
#include "scheme/mac.h"

#pragma pack(push, 1)
typedef struct FixedParam {
    uint64_t timestamp;
    uint16_t bc_int;
    uint16_t capa_info;
} fixed_param_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TaggedParam {
    uint8_t num;
    uint8_t len;
    char essid_start;    
} tagged_param_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct WirelessManagement {
    FixedParam fix;
    TaggedParam tag;
} wireless_management_t;
#pragma pack(pop)