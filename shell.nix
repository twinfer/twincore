{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.kaitai-struct-compiler
    pkgs.gotools
  ];
}