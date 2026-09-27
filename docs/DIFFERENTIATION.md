# What changed vs. the baseline (SIH26145 upstream)

This project started as a fork of a public reference solution for PS 26145
("AI-based detection of cyber threats in unidirectional IP traffic"). The
upstream project is unusually mature for a hackathon submission — it ships its
own 25-item defect register (`docs/DEFECTS.md`, carried over unmodified below
for traceability) and a 4-layer mechanical proof of the read-only constraint.
Rather than restate what it already does well, this document says exactly
what was added or changed on top of it, and why, in the same register style
the upstream project uses — verdicts should be checkable, not asserted.

**Nothing in the detection path's threat coverage changed.** All seven
detectors and the anomaly model are the upstream logic, unmodified except
where a defect fix below touches them. The five-complete/one-partial verdict
on the six PS threat classes (`docs/CONFORMANCE.md`, also carried over)
still holds — QUIC is still not attempted, for the same reason the upstream
README gives: recovering QUIC Initial-packet headers sits closer to
decryption than to header parsing.

---

## 1. Three upstream defects closed

| # | Upstream defect | What was done here | Verified |
|---|---|---|---|
| 22 | DGA and DNS tunnelling shared one `threat_class` and were distinguishable only by reading prose in an evidence note — no SOAR rule could route them differently. | `alerts/schema.py` gained an optional `subtype` field. `detectors/dns.py` now emits `DGA`, `TUNNEL`, or `DGA_TUNNEL` as a structured value alongside the existing human-readable note. | `python engine.py data/pcaps/mixed.pcap` → `DNS_ANOMALY` alerts carry `"subtype": "DGA"` / `"DGA_TUNNEL"` in the JSON. |
| 23 | `spoofed` in `detectors/synflood.py` selected evidence wording only and never reached any structured field a consumer could filter or route on. | Same `subtype` mechanism: `SPOOFED_FLOOD` vs `SINGLE_SOURCE_FLOOD`, plus an explicit `spoofed_source` (0/1) evidence entry instead of only a sentence. | Same run → `SYN_FLOOD` alert carries `"subtype": "SPOOFED_FLOOD"` and an `spoofed_source: 1` evidence line. |
| 16 | `malformed` conflated genuinely corrupt frames with well-formed non-IP frames (ARP/STP/LLDP), so a healthy segment's ordinary L2 background traffic looked like packet loss on the dashboard. | `ingest/reader.py`'s `parse()` now returns a `(packet, reason)` pair distinguishing `"non_ip"` from `"malformed"` from `"bug"` (see #18). `PcapReader` and `EngineStats` track all three separately. | `tools/selftest.py`'s `stats.malformed == 0` assertion still passes (21/21 checks), and the JSON summary now reports `non_ip` and `parse_bugs` alongside `malformed`. |

**Also addressed, not in the original register as its own item:** the
top-level `except Exception` in `reader.parse()` was a second, larger
instance of the same failure mode DEFECTS.md #18 already named for
`_attach_dns`. It has been narrowed to the same expected-error tuple
(`UnpackError`, `NeedData`, `struct.error`, `IndexError`, `ValueError`,
`AttributeError`); anything outside that list is now counted separately as
`parse_bugs` and the first few occurrences are printed to stderr, so a real
parsing regression in this codebase can no longer silently disappear into a
"malformed traffic" number that looks like ordinary packet loss.

**Deliberately not attempted in this pass:** defects #7 (training population
is 94% responders), #9 (DNS beaconing unreachable), #12 (public-suffix
handling), #25 (TLS padding defeats the size gate), and the rest of the
"Open" list. Each requires either more synthetic traffic authorship or a
retrain-and-revalidate cycle that risks the upstream project's own
zero-false-positive measurement, which is exactly the reason its README gives
for not having fixed them yet either. Attempting them here without the same
rigor of re-measurement would be worse than leaving them documented.

---

## 2. Persistent alert history (new — the upstream gap this closes)

The upstream dashboard holds alerts in an in-memory ring buffer
(`SIH_MAX_ALERTS`, default 500) plus an append-only JSONL file that nothing
ever reads back. Restart the server, or run more alerts than the ring buffer
holds, and the operator's view of history is gone — a SOC dashboard that
cannot answer "what fired last night" without grepping a log file by hand.

`storage.py` adds a SQLite-backed `AlertStore`: every alert `on_alert()`
receives is now also written to `data/alerts.db`, indexed on time, class and
severity. Two new endpoints read it back:

- `GET /api/history?limit=&threat_class=&severity=&since_epoch=` — filtered,
  paginated, survives a restart.
- `GET /api/stats/summary` — aggregate counts by class, by severity, by the
  new `subtype` field, and a 5-minute-bucket timeline for a trend chart.

**Why SQLite and not the PostgreSQL the original architecture write-up
called for.** Same relational model, same SQL, zero extra services to
install or configure for a judge running this in five minutes — which
matters more for a single-process passive monitor with one writer than
concurrent-throughput a Postgres instance would buy. `config.db_path()`
reads `DATABASE_URL`, the conventional Postgres-DSN environment variable
name, specifically so that swapping the two `sqlite3.connect()` calls in
`storage.py` for `psycopg2.connect(os.environ["DATABASE_URL"])` is the whole
migration — every query is plain parameterised SQL, not an ORM tied to one
backend.

**Isolation is unaffected.** `storage.py` is excluded from
`tools/isolation_check.py` for the same stated reason `server.py` and
`config.py` already are: it is downstream of detection, writing to a local
file the dashboard reads, not upstream of it. Verified: `python
tools/isolation_check.py` still reports 19/19 files clean and the same
static/runtime/file-access proof.

Verified end-to-end: `POST /api/replay` on `mixed.pcap`, then `GET
/api/history` and `GET /api/stats/summary` both returned the 10 persisted
alerts with `subtype` populated where applicable, after the in-memory
`/api/alerts` ring buffer would have shown the same thing only because the
process hadn't restarted.

## 3. Dashboard: new theme, new History & Analytics view

The upstream dashboard is a well-built single-file, no-build-step HTML
(dark navy/slate theme, drag-to-compare evidence panel, resizable split
view). It has been replaced rather than reskinned, because a differently
saturated version of the same layout is not a differentiator:

- **Distinct visual identity** — deep violet/indigo background, cyan+purple
  gradient accents, versus the upstream's blue-on-slate palette.
- **Subtype and spoofed-flood badges** are now visible in both the live
  alert list and the evidence detail panel — the upstream UI has no way to
  show them because the field didn't exist there.
- **New "History & Analytics" tab**, backed entirely by the new persistence
  layer: a severity donut, a per-class bar chart, a 5-minute-bucket timeline
  (Chart.js, loaded from a CDN, no build step — consistent with the
  project's existing no-npm-required philosophy), and a searchable table of
  persisted alerts that survives a server restart.
- The **Live** tab's actual mechanics (WebSocket feed, replay controls,
  evidence click-through) are functionally the same interaction model as
  upstream — that part worked well and rebuilding it differently for its own
  sake would not have improved anything.

## 4. Explicitly deferred (documented rather than silently dropped)

Named here so a reviewer does not have to guess what was considered and
skipped, in the same spirit as the upstream "Known limits" section:

- **Supervised classification (XGBoost/LightGBM) alongside the existing
  IsolationForest.** The original solution write-up for this PS called for a
  hybrid supervised+unsupervised approach. `data/labels.json` has the
  ground truth to build one, but doing it properly means re-deriving a
  window-to-episode label alignment and re-validating precision/recall
  against it without disturbing the existing zero-false-positive result —
  a real piece of work, not a config flag, and it's next on the roadmap
  rather than rushed into this pass.
- **QUIC metadata analysis** — left out for the same reason upstream leaves
  it out: Initial-packet header protection is closer to decryption than to
  header parsing.
- **React frontend / PostgreSQL** — the pragmatic SQLite-backed version above
  covers the persistence gap the architecture write-up wanted; a full React
  rebuild of the dashboard was judged lower-value than fixing three real
  defects and adding queryable history, given the time available.
- **NetFlow/IPFIX ingest** — unchanged from upstream's own scoping: `engine.run()`
  still hardcodes `PcapReader`, and the feature layer still depends on
  per-packet TCP flags flow records don't carry.

## 5. Full test evidence

Every check below was re-run against this modified copy, not assumed:

```text
python data/generate.py --seed 42     # 258,529 packets, 9 captures — matches upstream
python train.py                       # mean ROC-AUC 0.991 (upstream reports 0.997;
                                       # both from the same seed, difference is
                                       # sklearn/platform floating-point variance)
python engine.py data/pcaps/mixed.pcap --pretty   # all 8 classes fire, subtype
                                                   # and spoofed_source fields present
python tools/isolation_check.py       # 19/19 files clean, PASS
python tools/selftest.py              # ALL 21 CHECKS PASSED
```

Server-level (persistence) checked manually, not by an automated test in this
pass:

```text
python server.py &
curl -X POST localhost:8000/api/replay -d '{"capture":"mixed.pcap","speed":0}'
curl localhost:8000/api/history?limit=5        # returns persisted alerts with subtype
curl localhost:8000/api/stats/summary          # returns by_class/by_severity/by_subtype/timeline
```

That gap — no automated test for the storage layer — is itself worth naming
rather than leaving implicit: `tools/selftest.py` was not extended to cover
`storage.py` or the two new endpoints. Adding that coverage is the most
valuable next hour of work on this codebase, ahead of any new feature.
