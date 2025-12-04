#define _GNU_SOURCE // GNU拡張機能を有効化
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <string.h>

#define STACK_SIZE (1024 * 1024) // 1MBのスタック領域を確保

typedef struct {
    char *rootfs;
    char *command;
} container_config;

int child_func(void *arg) {
    container_config *config = (container_config *)arg;

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

    // 環境変数の設定
    char *env[] = {"PATH=/bin:/usr/bin", NULL};

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
        .command = argv[2]
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
                        CLONE_NEWPID | CLONE_NEWNS | SIGCHLD,
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