#include <stdio.h>
#include "capture_windows.h"
#include "policy.h"

int main() {
    printf("[*] Starting ZeroTrustScope (Windows)...\n");
    start_packet_capture();
    return 0;
} 