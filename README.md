# Work on host machine

## Install Package

```sh
$ sudo apt update
$ sudo apt install -y build-essential debootstrap
```

## Setup Root Filesystem

`~/container-test/rootfs`に完全なLinuxファイルシステムが作成される。

```sh
$ mkdir -p ~/container-test/rootfs
$ sudo debootstrap --variant=minbase focal ~/container-test/rootfs
```

実行後、以下のようなディレクトリ構造が作成される。

```sh
$ pwd
/home/aoba/container-test/rootfs

$ ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

### debootstrapとは

ルートファイルシステムをゼロから構築するためのツール

### --variantオプション

- `minbase` - 最小限のパッケージのみ（最も軽量、約50-100MB）
- `buildd` - ビルド環境用
- 指定なし（デフォルト） - 標準的なパッケージセット（やや大きい）

### focalとは

Ubuntuのコードネーム（バージョン名）を指定

- `focal` = Ubuntu 20.04 LTS
- `jammy` = Ubuntu 22.04 LTS
- `noble` = Ubuntu 24.04 LTS
- `bookworm` = Debian 12
- `bullseye` = Debian 11

# Build

```sh
$ gcc -o bin/simple_container simple_container.c
```

# Examples

```sh
$ sudo ./bin/simple_container ~/container-test/rootfs "ls -la /"

# プロセスリストを見る（コンテナ内では限定的なPIDしか見えない）
$ sudo ./bin/simple_container ~/container-test/rootfs "ps aux"

# ホスト名を変更してみる（UTSネームスペース未使用なのでホストに影響する）
$ sudo ./bin/simple_container ~/container-test/rootfs "hostname"

# マウントポイントを確認
$ sudo ./bin/simple_container ~/container-test/rootfs "mount"

# ネットワークを確認
$ sudo ./bin/simple_container ~/container-test/rootfs "cat /proc/net/dev"
```