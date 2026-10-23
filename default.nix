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
    hyperscan
    xz
    ;
in
rustPlatform.buildRustPackage {
  pname = "lintnar";
  version = "0.1.0";

  __strucutredAttrs = true;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./test-data
    ];
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    zstd
    aws-lc
    hyperscan
    xz
  ];

  env = {
    CARGO_PROFILE_RELEASE_LTO = "thin";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = 1;
    ZSTD_SYS_USE_PKG_CONFIG = true;
    AWS_LC_SYS_USE_SYSTEM = true;
  };

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "harmonia-file-core-3.3.0" = "sha256-sJzjr2074ecIZQazleb1yTpbU2o+gYW6P5FYu9W2M0E=";
    };
  };

  meta = {
    license = lib.licenses.blueOak100;
    mainProgram = "cranar";
  };
}
