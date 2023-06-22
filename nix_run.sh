#! /usr/bin/env nix-shell
#! nix-shell -i bash --pure
#! nix-shell -p python3 util-linux systemd
#! nix-shell -I https://github.com/NixOS/nixpkgs/archive/4ecab3273592f27479a583fb6d975d4aba3486fe.tar.gz

python3 main.py
