#include <windows.h>

// Export functions for FFI - minimal version
__declspec(dllexport) void start_monitoring(void) {
    // Use Windows API instead of printf to avoid runtime dependencies
    OutputDebugStringA("[*] Starting packet monitoring via FFI (Windows DLL)...\n");
}

__declspec(dllexport) void add_trusted_ip(const char *ip) {
    OutputDebugStringA("[*] Adding trusted IP via FFI (Windows DLL)...\n");
}

__declspec(dllexport) void block_untrusted_ip(const char *ip) {
    OutputDebugStringA("[*] Blocking untrusted IP via FFI (Windows DLL)...\n");
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            OutputDebugStringA("[*] ZeroTrustScope DLL loaded\n");
            break;
        case DLL_PROCESS_DETACH:
            OutputDebugStringA("[*] ZeroTrustScope DLL unloaded\n");
            break;
    }
    return TRUE;
} 