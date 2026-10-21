{
  system ? builtins.currentSystem or "x86_64-linux",
  inputs ? import ./npins { },
  pkgs ? import inputs.nixpkgs { inherit system; },
}:
let
  inherit (pkgs)
    rustPlatform
    lib
    pkg-config
    zstd
    ;
in
rustPlatform.buildRustPackage {
  pname = "cranar";
  version = "0.1.0";

  __strucutredAttrs = true;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    zstd
  ];

  env.ZSTD_SYS_USE_PKG_CONFIG = true;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    license = lib.licenses.blueOak100;
    mainProgram = "cranar";
  };
}
