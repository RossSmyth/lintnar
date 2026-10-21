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
    aws-lc
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
    aws-lc
  ];

  env = {
    ZSTD_SYS_USE_PKG_CONFIG = true;
    AWS_LC_SYS_USE_SYSTEM = true;
  };

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "harmonia-file-core-3.3.0" = "sha256-VjMsfiUZiujmUQvn+AtctXM0CQVmYyX4hFTHrsA3M7o=";
    };
  };

  meta = {
    license = lib.licenses.blueOak100;
    mainProgram = "cranar";
  };
}
