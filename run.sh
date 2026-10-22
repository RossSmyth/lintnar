#!/usr/bin/env bash
curl -sfL https://channels.nixos.org/nixos-unstable/store-paths.xz | xz -d | cargo run --
