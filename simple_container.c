#define _GNU_SOURCE // GNU拡張機能を有効化
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <seccomp.h>        // 追加
#include <errno.h>          // 追加

#define STACK_SIZE (1024 * 1024) // 1MBのスタック領域を確保

typedef struct {
    char *rootfs;
    char *command;
    char *hostname;
} container_config;

// Seccompフィルターを設定
int setup_seccomp() {
    scmp_filter_ctx ctx;
    
    // デフォルトで全て許可
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        perror("seccomp_init");
        return -1;
    }
    
    // 危険なシステムコールをブロック
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapon), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapoff), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(settimeofday), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(perf_event_open), 0);
    
    // フィルターを適用
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        return -1;
    }
    
    seccomp_release(ctx);
    printf("Seccomp filter loaded successfully\n");
    return 0;
}

// Capabilitiesを制限する関数
int drop_capabilities() {
    // 保持するCapabilitiesのリスト
    cap_value_t caps_to_keep[] = {
        CAP_CHOWN,
        CAP_DAC_OVERRIDE,
        CAP_FSETID, 
        CAP_FOWNER,
        CAP_SETGID,
        CAP_SETUID,
        CAP_NET_BIND_SERVICE,
        CAP_KILL,
    };

    int num_caps = sizeof(caps_to_keep) / sizeof(cap_value_t);

    cap_t caps = cap_init();
    if (caps == NULL) {
        perror("cap_init");
        return -1;
    }

    // 保持するcapabilitiesを設定
    if (cap_set_flag(caps, CAP_EFFECTIVE, num_caps, caps_to_keep, CAP_SET) == -1) {
        perror("cap_set_flag effective");
        cap_free(caps);
        return -1;
    }
    
    if (cap_set_flag(caps, CAP_PERMITTED, num_caps, caps_to_keep, CAP_SET) == -1) {
        perror("cap_set_flag permitted");
        cap_free(caps);
        return -1;
    }
    
    if (cap_set_flag(caps, CAP_INHERITABLE, num_caps, caps_to_keep, CAP_SET) == -1) {
        perror("cap_set_flag inheritable");
        cap_free(caps);
        return -1;
    }

    if (cap_set_proc(caps) == -1) {
        perror("cap_set_proc");
        cap_free(caps);
        return -1;
    }

    cap_free(caps);

    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    printf("Capabilities dropped successfully\n");
    return 0;
}

int setup_loopback() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0 ) {
        perror("SIOCGIFFLAGS");
        close(sock);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}
int child_func(void *arg) {
    container_config *config = (container_config *)arg;

    // 独立したホスト名を設定
    if (config->hostname != NULL) {
        if (sethostname(config->hostname, strlen(config->hostname)) == -1) {
            perror("sethostname");
            // 致命的ではないため続行
        }
    }

    // マウントの準備
    // MS_PRIVATEで、このnamespaceにおけるマウント操作が親namespaceに伝播しないようにする
    // MS_RECで、上記の設定をすべてのサブマウントに再帰的に適用する
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount-root");
        return 1;
    }

    // chrootを行う前に、指定されたディレクトリを自分自身にバインドマウントする
    if (mount(config->rootfs, config->rootfs, "bind", MS_BIND | MS_REC, NULL) == -1) {
        perror("mount-bind");
        return 1;
    }

    // chrootを実行し、ルートを変更
    if (chroot(config->rootfs) == -1) {
        perror("chroot");
        return 1;
    }

    // chdirで新しいルートに移動
    if (chdir("/") == -1) {
        perror("chdir");
        return 1;
    }

    // psコマンドを実行するために/procをマウント
    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        perror("mount /proc");
    }

    // loopback インターフェースを有効化
    if (setup_loopback() == -1) {
        fprintf(stderr, "Warning: failed to setup loopback interface\n");
    }

    // Capabilitiesを制限
    if (drop_capabilities() == -1) {
        fprintf(stderr, "Warning: failed to drop capabilities\n");
    }

    // Seccompフィルターを適用
    if (setup_seccomp() == -1) {
        fprintf(stderr, "Warning: failed to setup seccomp\n");
    }

    // 環境変数の設定
    char *env[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", NULL};

    // コマンドの実行
    char *args[] = {"/bin/sh", "-c", config->command, NULL};
    execve("/bin/sh", args, env); // 現在のプロセスを新しいプロセスで置き換える
    
    // execve()が成功すると、残りのコードは実行されない
    perror("execve");
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <rootfs_path> <commnad>\n", argv[0]);
        fprintf(stderr, "Example: %s ./rootfs \"ls -la /\"\n", argv[0]);
    }

    container_config config = {
        .rootfs = argv[1],
        .command = argv[2],
        .hostname = "my-container"
    };

    // スタック領域の確保
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 1;
    }

    // スタックは下から上に成長するため、スタックのスタート位置として最上位アドレスを渡す
    // CLONE_NEWPIDで、PID namespaceを作成
    // CLONE_NEWNSで、Mount namespaceを作成
    // SIGCHLDで、子プロセスの終了時にSIGCHLDシグナルを送る
    pid_t pid = clone(child_func, stack + STACK_SIZE, 
                        CLONE_NEWPID | 
                        CLONE_NEWNS | 
                        CLONE_NEWUTS |
                        CLONE_NEWNET | 
                        CLONE_NEWIPC | // Inter Process Comunication (IPC)を独立させることで、共有メモリへのアクセスを制限
                        SIGCHLD,
                        &config);
    
    if (pid == -1) {
        perror("clone");
        free(stack);
        return 1;
    }

    printf("Container started with PID: %d\n", pid);

    waitpid(pid, NULL, 0);

    free(stack);
    return 0;
}   