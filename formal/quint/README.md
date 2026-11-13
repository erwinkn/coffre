# 0.16's models

Three [Quint](https://quint.sh) models of the design in
[docs/design/0.16.md](../../docs/design/0.16.md). No script runs them yet:
`pnpm formal` still checks 0.14's TLA+ models, and takes these over when
0.16's vault is built. Until then, run them from a folder with
`@informalsystems/quint` 0.33.1 installed, and a Java runtime for TLC.

- `change.qnt`: a change (read, decide, one write that compares every row it
  read), "always an Owner", and revocation against the vault's short memory.
  A row's MAC is a function of its content, so a row changed and changed back
  compares equal. `sound` passes, 24,627,382 distinct states. `noReadSet` and
  `stampLate` must fail. `packages/vault/test/replay-change.ts` replays its
  runs against the vault's change and its use on Postgres (its header says
  how).
- `log.qnt`: the log, the signer and its mirror of the access rows' MACs,
  against a database writer without the key. `logSound` passes, 74,424,831
  states, with one row, MACs 0 to 2, three entries and two moves by the
  writer. Nine modules, each with one protection off, must fail.
- `rotate.qnt`: a rotation of the vault's key, with a vault not yet replaced
  beside a new one, and a writer who holds the old key. `rotateSound` passes,
  12,294,943 distinct states, in about a minute. Five modules, each with one
  protection off, must fail: `noFence`, `underConfig`, `noDrain`,
  `retireAtOnce` (all on `quiet`) and `anyKey` (on `clean`).

```sh
# Sampled, in seconds
quint run log.qnt --main logSound --invariants quiet caught --max-samples 1000000 --max-steps 30
# Exhaustive, about five minutes on 8 cores
quint verify log.qnt --main logSound --invariant safe --backend tlc --tlc-config tlc.json
# A counterexample, readable
quint run log.qnt --main noChain --invariants caught --mbt --out-itf t.itf.json && node show.mjs t.itf.json
```
