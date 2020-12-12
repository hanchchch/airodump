#include <cstdint>
#include <arpa/inet.h>
#include "scheme/mac.h"

#pragma pack(push, 1)
typedef struct Beacon {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    Mac daddr; //broadcast
    Mac taddr;
    Mac bssid;
    uint16_t frag_seq;

    uint16_t seq_num();
    uint8_t frag_num();

    typedef enum {
        BEACON_FRAME = 0x8000
	} Type;
} beacon_t;
#pragma pack(pop)
