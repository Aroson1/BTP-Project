#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output=${1:-comparison-$(date +%Y%m%d-%H%M%S)}
limit=${2:-30}
mkdir -p results
if [ ! -f vendor/progent/full/secagent/tool.py ]; then
  python3 scripts/fetch_progent.py
fi
docker build --pull=false -t agentprof-btp:review2 .
docker build --pull=false -f Dockerfile.comparison -t agentprof-btp:comparison .
docker run --rm --network none --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SYS_PTRACE \
  --security-opt no-new-privileges --memory 512m --pids-limit 128 --cpus 2 \
  --mount "type=bind,source=$(pwd)/results,target=/results" --entrypoint python \
  agentprof-btp:comparison -m benchmarks.large_evaluate --output "/results/$output" --limit "$limit"
docker image inspect agentprof-btp:comparison --format '{{.Id}}' > "results/$output/image-id.txt"
