# Check Cross-VM Transient Vulnerabilities (CCTV)

### A tool to assess the mitigation status of virtual machines against cross-core microarchitectural attacks

## Usage

```bash
$ python3 main.py
```

### Options

`--debug`: printing additional information and outputting even when an error is encountered

`--ignore-container`: ignores containerisation - only full virtualisation is considered

### Usage with nix on other distributions

```bash
$ nix-shell -p python3 util-linux systemd --pure -I \
  https://github.com/NixOS/nixpkgs/archive/4ecab3273592f27479a583fb6d975d4aba3486fe.tar.gz \
  --run "python3 main.py"  
```

## Installation (without nix)

```bash
# Arch
$ pacman -Syyu python util-linux systemd --noconfirm

# Debian / Ubuntu
$ apt update && apt install -y python3 util-linux systemd

# Alpine (no systemd available)
$ apk update && apk add python3 util-linux

# RHEL / Rocky / CentOS
$ dnf install python3 util-linux systemd -y

# OpenSUSE
$ zypper -n in python3 util-linux systemd

# Void Linux (no systemd available)
$ xbps-install -S python3 util-linux -y

# FreeBSD (no systemd available)
$ pkg install python3 lscpu 
```