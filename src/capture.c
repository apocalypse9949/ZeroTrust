#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "policy.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("[+] Packet captured: %d bytes\n", header->len);
    check_policy(packet, header->len);  
}

void start_packet_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(1);
    }

    printf("[*] Capturing on eth0...\n");
    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
}
