#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
image=agentprof-btp:review2
output=${1:-linux-$(date +%Y%m%d-%H%M%S)}
mkdir -p results
docker build --pull=false -t "$image" .
docker run --rm --network none --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges --memory 512m --pids-limit 128 --cpus 2 \
  "$image" doctor
# SYS_PTRACE is for the root controller's learning recorder, not worker code.
# No host project, credentials or Docker socket is mounted into the container.
docker run --rm --network none --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SYS_PTRACE --security-opt no-new-privileges --memory 512m \
  --pids-limit 128 --cpus 2 --mount "type=bind,source=$(pwd)/results,target=/results" \
  "$image" evaluate --output "/results/$output" --repeats 3
docker image inspect "$image" --format '{{.Id}}' > "results/$output/image-id.txt"
