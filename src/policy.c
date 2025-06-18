#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "policy.h"

#define MAX_KNOWN_IPS 10
static char *known_ips[MAX_KNOWN_IPS];
static int num_known_ips = 0;

void check_policy(const u_char *packet, int len) {
    printf("[!] Analyzing packet... (len = %d)\n", len);

    struct ethhdr *eth_header = (struct ethhdr *)packet;

    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        struct iphdr *ip_header = (struct iphdr *)(packet + ETH_HLEN);

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

        printf("Source IP: %s, Destination IP: %s\n", src_ip, dst_ip);

        if (!is_known_ip(src_ip)) {
            log_event("ALERT", "Unknown source IP detected");
            block_ip(src_ip);
        }

        // Further analysis can be added here (e.g., port scan, protocol misuse)

    } else {
        log_event("INFO", "Non-IP packet captured");
    }
}

void block_ip(const char *ip) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iptables -A INPUT -s %s -j DROP", ip);
    printf("[!] Blocking IP: %s\n", ip);
    system(cmd);
}

void log_event(const char *event_type, const char *description);
void add_known_ip(const char *ip);
int is_known_ip(const char *ip);

void log_event(const char *event_type, const char *description) {
    FILE *log_file = fopen("zerotrust_log.json", "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    time_t rawtime;
    struct tm *info;
    char timestamp[80];

    time(&rawtime);
    info = localtime(&rawtime);
    strftime(timestamp, 80, "%Y-%m-%d %H:%M:%S", info);

    fprintf(log_file, "{\"timestamp\": \"%s\", \"event_type\": \"%s\", \"description\": \"%s\"}\n",
            timestamp, event_type, description);
    fclose(log_file);
}

void add_known_ip(const char *ip) {
    if (num_known_ips < MAX_KNOWN_IPS) {
        known_ips[num_known_ips] = strdup(ip);
        num_known_ips++;
        log_event("INFO", "Added new known IP");
    } else {
        log_event("WARNING", "Cannot add more known IPs, array is full.");
    }
}

int is_known_ip(const char *ip) {
    for (int i = 0; i < num_known_ips; i++) {
        if (strcmp(known_ips[i], ip) == 0) {
            return 1;
        }
    }
    return 0;
}
