#include <stdio.h>

__declspec(dllexport) void start_monitoring() {
    printf("[*] Stub: Starting packet monitoring (C library not compiled)\n");
}

__declspec(dllexport) void add_trusted_ip(const char *ip) {
    printf("[*] Stub: Adding trusted IP %s (C library not compiled)\n", ip);
}

__declspec(dllexport) void block_untrusted_ip(const char *ip) {
    printf("[*] Stub: Blocking untrusted IP %s (C library not compiled)\n", ip);
}
