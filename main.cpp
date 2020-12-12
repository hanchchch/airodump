#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <libnet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

#include "main.h"

std::map<uint64_t, int> seq;

void usage() {
	puts("syntax : airodump <interface>");
	puts("sample : airodump mon0");
}

uint64_t to_ll(Mac m) {
    return (
        (uint64_t)m.mac_[0] 
        || (uint64_t)m.mac_[1] << 0x8
        || (uint64_t)m.mac_[2] << 0x10
        || (uint64_t)m.mac_[3] << 0x18
        || (uint64_t)m.mac_[4] << 0x20
        || (uint64_t)m.mac_[5] << 0x28
    );
}

void dump(char* buf, int size) {
    for (int i=0; i<size; i++) {
        if (i%16 == 0) puts("");
        printf("%02hhx ", buf[i]);
    }
    puts("");
}

bool is_beacon_frame(const u_char* packet) {
    radiotap_hdr_t* pk_radiotap_hdr = (radiotap_hdr_t*)packet;
    beacon_t* pk_beacon = (beacon_t*)(packet+pk_radiotap_hdr->len);
    if (ntohs(pk_beacon->type) != Beacon::Type::BEACON_FRAME) return false;
    
    return true;
}

bool find_seq(Mac bssid) {
    return seq.find(to_ll(bssid)) != seq.end();
}

void print_frame_info(const u_char* packet) {
    radiotap_hdr_t* pk_radiotap_hdr = (radiotap_hdr_t*)packet;
    beacon_t* pk_beacon = (beacon_t*)(packet+pk_radiotap_hdr->len);
    wireless_management_t* pk_wireman = (wireless_management_t*)((char*)pk_beacon+sizeof(Beacon));

    if (!find_seq(pk_beacon->bssid)) seq[to_ll(pk_beacon->bssid)] = pk_beacon->seq_num();

    int beacon = pk_beacon->seq_num() - seq[to_ll(pk_beacon->bssid)];

    printf("[ BSSID ] %s\n", std::string(pk_beacon->bssid).c_str());
    printf("[ Beacon ] %d\n", beacon);
    printf("[ ESSID ] ");
    for (int i=0; i<pk_wireman->tag.len; i++) printf("%c", *(&(pk_wireman->tag.essid_start)+i));
    printf("\n");

}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        if (is_beacon_frame(packet)) 
        print_frame_info(packet);
    }

    pcap_close(handle);
}
