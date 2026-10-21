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
    ;
in
rustPlatform.buildRustPackage {
  pname = "cranar";
  version = "0.1.0";

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

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    license = lib.licenses.blueOak100;
    mainProgram = "cranar";
  };
}
