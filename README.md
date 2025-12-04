## Build

```sh
$ gcc -o bin/simple_container simple_container.c
```

## Examples

```sh
$ sudo ./bin/simple_container ~/container-test/rootfs "ls -la /"

# プロセスリストを見る（コンテナ内では限定的なPIDしか見えない）
$ sudo ./bin/simple_container ~/container-test/rootfs "ps aux"

# ホスト名を変更してみる（UTSネームスペース未使用なのでホストに影響する）
$ sudo ./bin/simple_container ~/container-test/rootfs "hostname"

# マウントポイントを確認
$ sudo ./bin/simple_container ~/container-test/rootfs "mount"
```