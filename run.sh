#!/usr/bin/env -S bash -Eeuo pipefail
path="$(realpath test-paths.txt)"
suffix="$RANDOM"

unit_name="$(systemd-run --user -p "StandardInput=file:$path" --unit="lintnar-$suffix" result/bin/lintnar)"

echo "lintnar-$suffix.service" >> jobs.log
