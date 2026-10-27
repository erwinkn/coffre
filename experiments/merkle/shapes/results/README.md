# W212's raw results

What the doc's "Tree shape, by numbers" tables were read from, as the scripts printed them:

- `seal.jsonl`: `bench.ts`, every shape at 0, 10M, 86.4M and 31.5B leaves (600 ticks), and from empty to 10M (`storage-10M`, 20,000 ticks).
- `repeats.jsonl`: `bench.ts`, `one` and `split` interleaved, three times, from empty and from a year (review r1).
- `retain.json`, `dropday.json`: `retain.ts`, retention's deletes and reads, and a day's tiles dropped.
- `midnight.json`: `midnight.ts`, stragglers at 34 `at`-day boundaries and the whole log's WAL a tick.
- `proofs.json` (with every link of a year's chain walked), `proofs-r2.json` (after review r1: split's ticks, `day`'s composites and walk): `proofs.ts`.
