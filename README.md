# Lintnar

Lint NAR files or something. Reads them without loading the entire archives into memory at once, or placing them into the nix store. Then just scan them for whatever.

Works well. On my good computer it took 2 hours and 15 minutes to scan all NAR archives of a recent unstable. This is 820 (compressed) GiB over 217126 store paths.

## Using

Pass store paths via stdin.

- `curl curl -sfL https://channels.nixos.org/nixos-unstable/store-paths.xz | xz -d | lintnar`

How I use it:

- `systemd-run --user -p StandardInput=file:store-paths.txt result/bin/lintnar`

It will then run in the background. Take note of the service name, or set it in the above invocation. Once it is done:

- `journalctl --user -u run-p17883-i18215.service1`

You can use options like `-o cat` to use this in pipelines. I'm not sure if you can only filter to stdout somehow, as stderr has some notional logging that isn't json.

## TODO

* Better error handling (currently panics kill the current run without any output)
* Retry upon network failure (currently just silently skips the store path)
* Output to sqlite db (currently just jsonl which can be annoying to work with)
* Add nixpkgs attribute correlation to sqlite db (good to know)
