{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/4ecab3273592f27479a583fb6d975d4aba3486fe.tar.gz") {} }:

pkgs.mkShell {
    buildInputs = [
        pkgs.python310
        pkgs.util-linux
        pkgs.systemd
        # todo: remove, only for dev
        pkgs.fish
        pkgs.python310Packages.flake8
        pkgs.python310Packages.autopep8
        # pkgs.python310Packages.pytest
    ];

    shellHook = ''
        echo "Linting with flake8 ... "
        flake8 --exclude venv/ --max-line-lengt 150
    '';
    # shellHook = ''
    #     python3 main.py
    #     exit
    # '';
}
