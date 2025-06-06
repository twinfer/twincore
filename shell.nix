{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.gotools
    pkgs.gopls
    pkgs.golangci-lint
    pkgs.python3
    pkgs.python3Packages.pip
    pkgs.ripgrep
  ];


  shellHook = ''
    export TMPDIR=/tmp
    export PATH=$PATH:$(go env GOPATH)/bin
    go fmt ./...

  '';

}