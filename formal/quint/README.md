# 0.16's models

Two [Quint](https://quint.sh) models of the design in
[docs/design/0.16.md](../../docs/design/0.16.md). No script runs them yet:
`pnpm formal` still checks 0.14's TLA+ models, and takes these over when
0.16's vault is built. Until then, run them from a folder with
`@informalsystems/quint` 0.33.1 installed, and a Java runtime for TLC.

- `change.qnt`: a change (read, decide, one write that compares every row it
  read), "always an Owner", and revocation against the vault's short memory.
  `sound` passes, 25,966,984 states. `noReadSet` and `stampLate` must fail.
- `log.qnt`: the log, the signer and its mirror of the access rows' MACs,
  against a database writer without the key. `logSound` passes, 52,048,877
  states, with one row, MACs 0 to 2, three entries and two moves by the
  writer. Nine modules, each with one protection off, must fail.

```sh
# Sampled, in seconds
quint run log.qnt --main logSound --invariants quiet caught --max-samples 1000000 --max-steps 30
# Exhaustive, about five minutes on 8 cores
quint verify log.qnt --main logSound --invariant safe --backend tlc --tlc-config tlc.json
# A counterexample, readable
quint run log.qnt --main noChain --invariants caught --mbt --out-itf t.itf.json && node show.mjs t.itf.json
```
