// test_caps.c
#include <stdio.h>
#include <sys/reboot.h>
#include <errno.h>
#include <unistd.h>

int main() {
    printf("Testing capabilities...\n");
    
    // CAP_SYS_BOOTが必要な操作（reboot）
    printf("1. Attempting reboot (should fail)...\n");
    if (reboot(RB_AUTOBOOT) == -1) {
        printf("   ✓ Blocked (errno=%d): %s\n", errno, 
               errno == EPERM ? "Permission denied" : "Other error");
    } else {
        printf("   ✗ Succeeded (危険！)\n");
    }
    
    // CAP_CHOWNが必要な操作（許可されているはず）
    printf("2. Attempting chown (should succeed)...\n");
    if (chown("/tmp", 0, 0) == -1) {
        printf("   ✗ Failed: Permission denied\n");
    } else {
        printf("   ✓ Succeeded\n");
    }
    
    return 0;
}