#include <stdio.h>
#include "capture.h"
#include "policy.h"

int main() {
    printf("[*] Starting ZeroTrustScope...\n");
    start_packet_capture();
    return 0;
}
