#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
typedef struct RadiotapHdr {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint64_t present;
    uint64_t mac_timestamp;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t ch_freq;
    uint16_t ch_flags;
    uint8_t ant_sig1;
    uint8_t zero;
    uint16_t rx_flags;
    uint8_t ant_sig2;
    uint8_t ant;
} radiotap_hdr_t;
#pragma pack(pop)
