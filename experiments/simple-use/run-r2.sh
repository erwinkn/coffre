#!/usr/bin/env bash
# After review r1: the hot calls with the as_of row check (finding 1) and use_move (finding 5), interleaved with
# main's and #590's decided writes, 3 rounds at 1,000/s.
cd "$(dirname "$0")/../.."
C=coffre_thr_qx8qf2k5yv_rig
R=postgresql://coffre_owner:local-dev-only@127.0.0.1:56491/coffre; H=postgresql://coffre_vault_hot:local-hot-only@127.0.0.1:56491/coffre
new() { node --conditions=coffre:source experiments/simple-use/bench-hot.ts --owner $R --hot $H --container $C --rate ${RATE:-1000} --seconds ${SECS:-10} --pool 16 "$@" 2>&1 | tail -1 | sed 's/^/rate /'; }
for i in $(seq ${ROUNDS:-3}); do
  echo "== round $i"; uptime
  new --form write --function use_credential_0082; new --form write --function use_credential
  new --form hot; new --form ride; new --form moved; new --form move
done
