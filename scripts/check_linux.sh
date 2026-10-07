#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker build --pull=false -t agentprof-btp:review2 .
docker run --rm --network none --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges \
  --memory 512m --pids-limit 128 --cpus 2 --entrypoint python \
  agentprof-btp:review2 -m benchmarks.linux_checks
