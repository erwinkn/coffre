# W209: Merkle checkpoints for 0.15's audit log

An experiment, DO NOT MERGE. The design, the numbers and the decisions are in
[`docs/design/merkle-checkpoints.md`](../../docs/design/merkle-checkpoints.md).
Everything here runs against a scratch Postgres of your own (never the shared
one on :55432):

```
node --test experiments/merkle/test/tree.test.ts                     # the tree against RFC 9162's recursion
W209_URL=postgresql://… node --test --test-concurrency=1 experiments/merkle/test/*.test.ts
node experiments/merkle/attacks.ts --url postgresql://…              # what a database writer can and cannot hide
node experiments/merkle/bench.ts --url … --fresh --rate 1000 --every 500 --witness local
node experiments/merkle/change-bench.ts --url … [--witness <url>]   # a change answering once sealed
node experiments/merkle/history.ts --url … --leaves 10000000         # R48: proofs on a large tree
node experiments/merkle/fill.ts --url … && node experiments/merkle/src/server.ts --url …
(cd experiments/merkle/go && go run . -key '<verifier key>')         # Go's sumdb code checks it all
scripts/formal-seal.sh --workers 8                                    # the TLA+ model
```

W212's comparison of tree shapes (one tree, split by retention class, per
day, per tick, chained, MMR), in `shapes/`; the numbers are in the doc's
"Tree shape, by numbers":

```
node --test experiments/merkle/shapes/shapes.test.ts                 # each shape against the RFC tree
node experiments/merkle/shapes/bench.ts --url … --shape split --start 31536000000 --ticks 600
node experiments/merkle/shapes/proofs.ts [--chain-year]               # proof sizes, verify and walk costs
node experiments/merkle/shapes/retain.ts --url …                      # after bench.ts's 10M runs
node experiments/merkle/shapes/midnight.ts --url …                    # stragglers at each `at`-day boundary
```
