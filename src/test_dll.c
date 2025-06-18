#include <stdio.h>

__declspec(dllexport) int test_function(void) {
    printf("Test function called!\n");
    return 42;
} 