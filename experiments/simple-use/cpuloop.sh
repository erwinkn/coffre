#!/usr/bin/env bash
# Backend CPU per call (µs, /proc/<pid>/schedstat) of each function: N calls in one session each, ROUNDS times, interleaved.
C=${C:-coffre_thr_qx8qf2k5yv_rig}; N=${N:-3000}
for i in $(seq ${ROUNDS:-3}); do for fn in "$@"; do
  out=$(docker exec -i $C psql -qAt -U coffre_owner -d coffre <<SQL
SET plan_cache_mode = force_generic_plan;
SELECT pg_backend_pid() AS pid \gset
\setenv BPID :pid
SELECT bench_loop_w396('$fn', 100);
\! awk '{print \$1}' /proc/\$BPID/schedstat
SELECT bench_loop_w396('$fn', $N);
\! awk '{print \$1}' /proc/\$BPID/schedstat
SQL
)
  echo "$out" | python3 -c "import sys; t=sys.stdin.read().split(); l=[x for x in t if x.isdigit()]; print('loop', '$fn', t[-2] if len(t)>1 else '', round((int(l[-1])-int(l[-2]))/1000/$N,1), 'us cpu/call')"
done; done
