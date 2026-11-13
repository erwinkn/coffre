#!/usr/bin/env bash
# After review r2: use_move with R42's election (finding 1), log unmoved and moved, beside main's decided write
# and use_hot, 3 rounds at 1,000/s.
cd "$(dirname "$0")/../.."
C=coffre_thr_qx8qf2k5yv_rig
R=postgresql://coffre_owner:local-dev-only@127.0.0.1:56491/coffre; H=postgresql://coffre_vault_hot:local-hot-only@127.0.0.1:56491/coffre
new() { node --conditions=coffre:source experiments/simple-use/bench-hot.ts --owner $R --hot $H --container $C --rate ${RATE:-1000} --seconds ${SECS:-10} --pool 16 "$@" 2>&1 | tail -1 | sed 's/^/rate /'; }
for i in $(seq ${ROUNDS:-3}); do
  echo "== round $i"; uptime
  new --form write --function use_credential
  new --form hot; new --form moved; new --form move; new --form move-moved
done
