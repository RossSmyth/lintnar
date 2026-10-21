{
  system ? builtins.currentSystem or "x86_64-linux",
  inputs ? import ./npins { },
  pkgs ? import inputs.nixpkgs { inherit system; },
  cranar ? import ./. { inherit system inputs pkgs; },
}:
let
  inherit (pkgs) mkShell;
in
mkShell {
  inputsFrom = [
    cranar
  ];

  env.ZSTD_SYS_USE_PKG_CONFIG = true;

  packages = with pkgs; [
    clippy
    rust-analyzer
    rustfmt
  ];
}
