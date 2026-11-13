#!/usr/bin/env bash
# The prototype's numbers, interleaved old and new, ROUNDS times: at 1,000/s (cgroup CPU, buffers), then per call (loop).
cd "$(dirname "$0")/../.."
C=coffre_thr_qx8qf2k5yv_rig
R=postgresql://coffre_owner:local-dev-only@127.0.0.1:56491/coffre; H=postgresql://coffre_vault_hot:local-hot-only@127.0.0.1:56491/coffre
old() { node --conditions=coffre:source packages/vault/scripts/bench-use.ts --owner $R --hot $H --container $C --rate ${RATE:-1000} --seconds ${SECS:-10} --pool 16 --json "$@" 2>&1 | tail -1 \
  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print('rate', d['form'], d['function'], 'cover' if d['cover'] else 'nocover', {k:d[k] for k in ['served','failed','rode','cpuMsPerUse','buffersPerUse','serverMsPerUse','p50','p99']})"; }
new() { node --conditions=coffre:source experiments/simple-use/bench-hot.ts --owner $R --hot $H --container $C --rate ${RATE:-1000} --seconds ${SECS:-10} --pool 16 "$@" 2>&1 | tail -1 | sed 's/^/rate /'; }
uptime
for i in $(seq ${ROUNDS:-3}); do
  echo "== round $i"; uptime
  old --form cached --cover --function use_credential_0082; old --form cached --cover --function use_credential; new --form ride
  old --form cached --function use_credential_0082; old --form cached --function use_credential; new --form hot
  old --form probing --cover --function use_credential_0082; old --form probing --cover --function use_credential; new --form moved
done
docker exec -i $C psql -q -U coffre_owner -d coffre < experiments/simple-use/loop.sql
C=$C ROUNDS=${ROUNDS:-3} ./experiments/simple-use/cpuloop.sh use_credential_0082 use_credential use_hot use_ride
uptime
