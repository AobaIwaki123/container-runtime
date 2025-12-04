#define _GNU_SOURCE
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
#include <seccomp.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>

#define STACK_SIZE (1024 * 1024)

typedef struct {
    long memory_limit;
    int cpu_percent;
} cgroup_config;

typedef struct {
    char *rootfs;
    char *command;
    char *hostname;
    cgroup_config cgroup;
} container_config;

int setup_cgroup(pid_t pid, const char *container_id, cgroup_config *config) {
    char path[512];
    FILE *f;
    
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", container_id);
    
    if (mkdir(path, 0755) == -1) {
        if (errno != EEXIST) {  // 既に存在する場合は無視
            perror("mkdir cgroup");
            return -1;
        }
    }
    
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs", container_id);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d\n", pid);
        fclose(f);
    } else {
        perror("write cgroup.procs");
        return -1;
    }
    
    return 0;
}

int set_memory_limit(const char *container_id, long bytes) {
    char path[512];
    FILE *f;
    
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/memory.max", container_id);
    
    f = fopen(path, "w");
    if (f == NULL) {
        perror("open memory.max");
        return -1;
    }
    
    fprintf(f, "%ld\n", bytes);
    fclose(f);
    
    return 0;
}

int set_cpu_limit(const char *container_id, int cpu_percent) {
    char path[512];
    FILE *f;
    
    long quota = cpu_percent * 1000;
    long period = 100000;
    
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cpu.max", container_id);
    
    f = fopen(path, "w");
    if (f == NULL) {
        perror("open cpu.max");
        return -1;
    }
    
    fprintf(f, "%ld %ld\n", quota, period);
    fclose(f);
    
    return 0;
}

int cleanup_cgroup(const char *container_id) {
    char path[512];
    
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", container_id);
    
    if (rmdir(path) == -1) {
        if (errno != ENOENT) {  // 存在しない場合は無視
            perror("rmdir cgroup");
            return -1;
        }
    }
    
    return 0;
}

int setup_seccomp() {
    scmp_filter_ctx ctx;
    
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        perror("seccomp_init");
        return -1;
    }
    
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
    
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        return -1;
    }
    
    seccomp_release(ctx);
    return 0;
}

int drop_capabilities() {
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

    if (cap_set_flag(caps, CAP_EFFECTIVE, num_caps, caps_to_keep, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_PERMITTED, num_caps, caps_to_keep, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_INHERITABLE, num_caps, caps_to_keep, CAP_SET) == -1) {
        perror("cap_set_flag");
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

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
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

    if (config->hostname != NULL) {
        if (sethostname(config->hostname, strlen(config->hostname)) == -1) {
            perror("sethostname");
        }
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount-root");
        return 1;
    }

    if (mount(config->rootfs, config->rootfs, "bind", MS_BIND | MS_REC, NULL) == -1) {
        perror("mount-bind");
        return 1;
    }

    if (chroot(config->rootfs) == -1) {
        perror("chroot");
        return 1;
    }

    if (chdir("/") == -1) {
        perror("chdir");
        return 1;
    }

    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        perror("mount /proc");
    }

    if (setup_loopback() == -1) {
        fprintf(stderr, "Warning: failed to setup loopback interface\n");
    }

    if (drop_capabilities() == -1) {
        fprintf(stderr, "Warning: failed to drop capabilities\n");
    }

    if (setup_seccomp() == -1) {
        fprintf(stderr, "Warning: failed to setup seccomp\n");
    }

    char *env[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", NULL};
    char *args[] = {"/bin/sh", "-c", config->command, NULL};
    execve("/bin/sh", args, env);
    
    perror("execve");
    return 1;
}

int main(int argc, char *argv[]) {
    long memory_mb = 0;       // 0 = unlimited
    int cpu_percent = 100;    // 100 = unlimited

    int opt;
    while ((opt = getopt(argc, argv, "m:c:")) != -1) {
        switch (opt) {
        case 'm':
            memory_mb = atol(optarg);
            break;
        case 'c':
            cpu_percent = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-m memory_mb] [-c cpu_percent] <rootfs> <command>\n", 
                    argv[0]);
            return 1;
        }
    }
    
    if (optind + 2 > argc) {
        fprintf(stderr, "Missing rootfs or command\n");
        return 1;
    }
    
    char *rootfs = argv[optind];
    char *command = argv[optind + 1];

    container_config config = {
        .rootfs = rootfs,       // ✅ 修正：getopt後の値を使用
        .command = command,     // ✅ 修正：getopt後の値を使用
        .hostname = "my-container",
        .cgroup = {
            .memory_limit = memory_mb * 1024 * 1024,
            .cpu_percent = cpu_percent
        }
    };

    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 1;
    }

    pid_t pid = clone(child_func, stack + STACK_SIZE, 
                      CLONE_NEWPID | 
                      CLONE_NEWNS | 
                      CLONE_NEWUTS |
                      CLONE_NEWNET | 
                      CLONE_NEWIPC |
                      SIGCHLD,
                      &config);
    
    if (pid == -1) {
        perror("clone");
        free(stack);
        return 1;
    }

    char container_id[64];
    snprintf(container_id, sizeof(container_id), "container_%d", pid);
    
    printf("Container started with PID: %d\n", pid);
    printf("Container ID: %s\n", container_id);

    // cgroupsを設定
    if (memory_mb > 0 || cpu_percent < 100) {
        if (setup_cgroup(pid, container_id, &config.cgroup) == 0) {
            if (memory_mb > 0) {
                set_memory_limit(container_id, config.cgroup.memory_limit);
                printf("Memory limit: %ldMB\n", memory_mb);
            }
            if (cpu_percent < 100) {
                set_cpu_limit(container_id, config.cgroup.cpu_percent);
                printf("CPU limit: %d%%\n", cpu_percent);
            }
        } else {
            fprintf(stderr, "Warning: Failed to setup cgroups\n");
        }
    }

    waitpid(pid, NULL, 0);

    // ✅ 追加：クリーンアップ
    if (memory_mb > 0 || cpu_percent < 100) {
        cleanup_cgroup(container_id);
    }

    free(stack);
    return 0;
}