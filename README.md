# Lintnar

Lint NAR files or something. Reads them without loading the entire archives into memory at once, or placing them into the nix store. Then just scan them for whatever.

## Using

Pass store paths via stdin.

1. `curl curl -sfL https://channels.nixos.org/nixos-unstable/store-paths.xz | xz -d > store-paths.txt`
2. `cat store-paths.txt | lintnar`

Optionally wrap it in systemd-run.

## TODO

* Everything
