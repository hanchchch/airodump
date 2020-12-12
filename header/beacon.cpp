#include "beacon.h"

uint16_t Beacon::seq_num() {
    return ((frag_seq) >> 4);
}

uint8_t Beacon::frag_num() {
    return ((frag_seq) && 0x000f);
}
