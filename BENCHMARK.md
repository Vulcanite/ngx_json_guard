# Benchmarks

Fresh results, captured 2026-08-24 from commit `08851ee`. All numbers below
come from the runs in `artifacts/` described in [Reproducing](#reproducing);
nothing is carried over from earlier benchmark rounds.

This document measures three things, in order of isolation:

1. **Parser micro-throughput** — the standalone `src/json_guard_parser.c`
   with no NGINX involved.
2. **Per-request guard cost** — what `json_guard` adds to a request inside
   NGINX, measured with the module's own inspection timer
   (`json_guard_inspection_us`) and end-to-end request latency.
3. **End-to-end engine comparison** — NGINX baseline vs guard vs
   ModSecurity vs Coraza, with and without the guard in front, under a
   constrained 2 vCPU / 4 GiB WAF container.

This is a processing benchmark, not a WAF detection-rate benchmark.

---

## Environment

| Item | Value |
|---|---|
| Host CPU | AMD Ryzen 7 7840HS, 16 logical cores |
| Host kernel | 6.18.33.1-microsoft-standard-WSL2 (x86_64) |
| Host RAM | 11 GiB |
| Docker | 29.6.2, Compose v5.3.1 |
| Compiler (micro bench) | gcc 15.2.0, `-O2 -Wall -Wextra -Werror` |
| WAF container budget | 2 vCPU, 4 GiB RAM (cgroup v2 enforced) |

Pinned software versions (from `benchmark/native/versions.env`, SHA-256
pinned in each artifact's `config-sha256.txt`):

| Component | Version |
|---|---|
| NGINX | 1.26.2 |
| libmodsecurity | 3.0.13 |
| ModSecurity-nginx | 1.0.3 |
| OWASP CRS | 4.25.0 |
| Coraza | 3.7.0 (via coraza-caddy) |
| Caddy | 2.11.3 (xcaddy 0.4.5, Go 1.25.9) |

**Host caveat:** results were produced inside WSL2 on shared hardware. The
harness records host CPU steal and flags noisy suites; no suite in these
runs was flagged (`Steal % = 0`, `Noisy = False` throughout). Absolute
numbers will differ on other hosts — relative comparisons within a suite are
the meaningful output. Micro-benchmarks must be run on an idle host: the
same binary measured 1.5–1.7x slower while Docker builds were loading the
same machine.

## Methodology

- **Micro:** `make bench-micro` — parse passes over an in-memory buffer,
  64 KiB chunks, parser reset per pass, one untimed warmup pass, median of
  15 timed passes, `CLOCK_MONOTONIC`.
- **Engine comparison:** `make cross-waf-full` (`MODE=full`) — eight engine
  profiles (below), each suite preceded by a warmup run and a container
  recreate so cgroup peak memory describes only that suite. Latency
  percentiles are per-request from the client; guard time comes from the
  `X-Json-Guard-Inspection-Us` response header populated by the module's
  own timer.
- **Constrained WAF runs:** `make waf-correctness` then `make waf-perf` —
  guard + ModSecurity + full CRS in one container, deterministic corpus,
  expected status asserted for every request.
- **Body integrity:** every body that reached an upstream with a known
  fixture hash retained its original byte length and SHA-256 digest — the
  guard never mutates or truncates the body it validates.

Engine profiles (see `benchmark/engines.json`):

| Engine | Stack |
|---|---|
| `nginx-baseline` | plain NGINX, no JSON processing |
| `nginx-guard` | NGINX + json_guard |
| `nginx-modsecurity-processor` | NGINX + ModSecurity JSON processor |
| `nginx-guard-modsecurity-processor` | guard before the processor |
| `nginx-modsecurity-crs` | processor + full CRS 4.25.0 |
| `nginx-guard-modsecurity-crs` | guard before processor + full CRS |
| `coraza-processor` | Caddy + Coraza JSON processor |
| `coraza-crs` | Coraza + full CRS 4.25.0 |

---

## 1. Parser micro-throughput

Generated corpora (`scripts/gen_large_json.py`), idle host, single thread:

| Body | Median | Throughput |
|---|---:|---:|
| 92 B object | < 1 µs | — |
| 100 KiB | 0.38 ms | 260 MiB/s |
| 1 MiB | 3.7 ms | 271 MiB/s |
| 10 MiB | 37.8 ms | 265 MiB/s |
| 20 MiB | 75.7 ms | 264 MiB/s |

Throughput is roughly flat in body size and varies with token density.
Peak RSS of the benchmark process is 1.9 MiB; the parser itself uses a
fixed-size ~96 KiB state struct — validation memory does not grow with
body size.

## 2. Per-request guard cost

From `make waf-perf` (guard + ModSecurity + full CRS, 4 workers, 175/175
correct outcomes). "Guard p50" is the module's self-reported inspection
time; "Total p50" is the client-observed end-to-end latency.

| Case | Guard p50 | Total p50 | Guard share |
|---|---:|---:|---:|
| Small JSON object (~100 B) | 0.01 ms | 46.8 ms | < 0.1% |
| Small JSON attacks (SQLi/XSS/CMDi) | 0.01 ms | 4.2–5.1 ms | < 0.3% |
| 1 MiB clean JSON | 4.1 ms | 77.3 ms | 5.3% |
| 20 MiB clean JSON | 96.3 ms | 2920 ms | 3.3% |
| 20 MiB SQLi at document tail | 82.9 ms | 2031 ms (403) | 4.1% |

The accepted 20 MiB tail-SQLi row is the core claim: the guard costs ~83 ms
and CRS still inspects the *entire* body — the attack at the far end of a
20 MiB document is still blocked. The tail is not sacrificed.

Cross-WAF run, accepted 20 MiB bodies under full CRS, single worker: the
guard's timer reports a **75.2 ms median, 0.67% of the ModSecurity-only
full-CRS median** for the same body; the end-to-end median differential
including run noise was 86.1 ms (0.77%).

### Early rejection economics

Rejected bodies never reach CRS, which is where the savings are:

| Case (20 MiB) | Outcome | Latency |
|---|---|---:|
| Clean, accepted | 200 (full CRS scan) | 2920 ms |
| Malformed JSON at tail | 400 by guard | 313 ms |
| Token/cardinality over limit | 413 by guard | 241 ms (guard portion 3.5 ms — limit trips early in the stream) |
| SQLi at tail, accepted by guard | 403 by CRS | 2031 ms |

Cross-WAF confirms the malformed-tail result without CRS: 323 ms median
with the guard first vs 542 ms with ModSecurity's JSON processor alone —
**40.4% lower rejection latency**. The trade-off in the other direction is
honest: an *accepted* body in the processor-only configuration is scanned
twice (guard, then processor), costing 19.1% more end-to-end than the
processor alone.

## 3. End-to-end engine comparison

### Processor suites (large JSON, no CRS)

32-request corpus dominated by 1–100 MiB bodies, 4 workers:

| Engine | MiB/s | Peak RAM | p50 / p95 |
|---|---:|---:|---|
| nginx-baseline | 127.2 | 368 MiB | 639 / 3678 ms |
| nginx-guard | 167.2 | 363 MiB | 414 / 2579 ms |
| nginx-modsecurity-processor | 74.8 | 1654 MiB | 593 / 6526 ms |
| nginx-guard-modsecurity-processor | 105.8 | 1150 MiB | 519 / 3400 ms |
| coraza-processor | 55.7 | 2148 MiB | 822 / 7894 ms |

Read carefully: `nginx-guard` shows *higher* throughput than baseline
because this corpus contains malformed and over-limit cases that the guard
rejects early — baseline must proxy every byte upstream. On a corpus of
only well-formed bodies the guard would sit at or slightly below baseline.
Likewise guard+processor beats processor alone on this mixed corpus for the
same reason, not because parsing gets faster.

### Full CRS suites

20 MiB bodies under full CRS 4.25.0, single worker:

| Engine | MiB/s | p50 | p95 |
|---|---:|---:|---:|
| nginx-modsecurity-crs | 1.80 | 88.6 ms | 11.1 s |
| nginx-guard-modsecurity-crs | 1.77 | 58.2 ms | 11.3 s |
| coraza-crs | 0.27 | 45.4 ms | 75.3 s |

With the guard in front, CRS throughput is unchanged (1.77 vs 1.80 MiB/s,
within run noise) and the correctness suite wall time *drops* from 150 s to
104 s because guard-rejected malformed bodies never reach rule evaluation.

Small-body mixed traffic, 4 workers: 108.4 req/s without the guard vs
109.1 req/s with it — indistinguishable; the guard's per-body cost at this
size is ~10 µs against ~7 ms requests.

### Coraza observations

Under this harness Coraza+Caddy struggled with very large JSON: a single
64 MiB string took **268.2 s** under full CRS and pushed peak container
memory to 3.5 GiB (ModSecurity completed the same case in 46.6 s with a
1.0 GiB peak), and the CRS suite ran at 0.27 MiB/s vs 1.8 MiB/s for
ModSecurity. Coraza also enforces its own structural limits on this corpus
(10,000-element arrays rejected with 413). These are observations for
Coraza 3.7.0 via coraza-caddy under this exact configuration — they are not
a general Coraza-vs-ModSecurity verdict, and the guard's value proposition
(cheap structural admission before rule evaluation) applies in front of
either engine.

### Large-body boundaries

| Body | baseline | guard | modsec-proc | guard+modsec-proc | coraza-proc |
|---|---|---|---|---|---|
| 64 MiB − 1 string | 200 | 200 | 200 | 200 | 200 |
| 64 MiB string | 200 | 200 | 200 | 200 | 200 |
| 64 MiB + 1 string | 200 | **413** | 200 | **413** | 200 |
| 129 MiB body | 413 (client_max_body_size) | 413 | 413 | 413 | 413 |

The guard is the only engine that enforces the 64 MiB single-value limit;
the 100 MiB multi-value document (four values under the limit) is accepted,
and its SHA-256 at the upstream matches.

## 4. Outcome correctness

- `make waf-correctness` (serial, 21 cases): **21/21** expected statuses.
- `make waf-perf` (mixed, 175 requests incl. SQLi/XSS/XXE/CMDi across
  JSON, form, XML, query-string routes): **175/175**.
- Cross-WAF correctness (51-case structural corpus): guard-only and
  guard+processor 51/51; guard+CRS 50/51 (the miss is `fp_source_code`, a
  CRS false positive, see table). Discrepancies elsewhere are behavioral,
  not failures:

| Engine | Case | Observed | Why |
|---|---|---|---|
| nginx-modsecurity (all) | `unpaired_surrogate` | 200 allowed | libmodsecurity's JSON processor tolerates unpaired UTF-16 surrogates; the guard rejects them (strict RFC 8259) with 400 |
| coraza (both) | `unpaired_surrogate` | 200 allowed | same — only the guard enforces this |
| coraza (both) | `invalid_utf8` | 400 | Coraza forwards the body; the 400 comes from the upstream app, not Coraza |
| every CRS engine | `fp_source_code` | 403 | CRS 4.25.0 default paranoia level flags source-code-like bodies; a CRS tuning issue (use the CRS exclusions package), independent of the guard |

## Reproducing

```sh
make test                        # parser unit tests (75)
make bench-micro                 # §1 numbers, ~1 min, run on idle host
make cross-waf-full              # §3, all 8 engines, ~90 min + image build
make waf-correctness             # §4 serial run, ~5 min
make waf-perf                    # §2 mixed run, ~10 min
```

Prerequisites: Docker with Compose, ~10 GiB free disk for images and
payloads. `run_waf_perf.sh` expects the API upstreams from
`docker/docker-compose.api.yml` to be running — start them with
`docker compose -f docker/docker-compose.api.yml up -d json_api xml_api form_api web_app`
if you have not run the integration suite in that compose project.

Artifacts from the runs quoted here (reports, per-request JSON, cgroup
snapshots, container inspects, config hashes):

| Run | Path |
|---|---|
| Cross-WAF (all engines) | `artifacts/cross-waf/20260824-004254/` |
| Constrained correctness | `artifacts/waf-perf/20260824-021348/` |
| Constrained perf | `artifacts/waf-perf/20260824-021836/` |

## Limitations

- Loopback client on the same host as the WAF containers; absolute
  latencies include loopback upload time for large bodies.
- WSL2 host — see the caveat above; treat cross-engine *ratios* as the
  signal, not absolute values.
- Post-read validation: the guard runs after NGINX has spooled the body,
  so upload time is not overlapped and these numbers do not change that.
- `fp_source_code` blocking is CRS default behavior, included to keep the
  corpus honest about false positives; it is not a guard or engine defect.
- The guard's inspection timer is self-reported by the module
  (`json_guard_inspection_us`); end-to-end client latencies are measured
  independently and agree with it (guard share of total tracks the timer
  within a few percent).
