# ngx_json_guard

**Post-read chunked JSON structural guard for NGINX — used *before* ModSecurity, not instead of it.**

`ngx_json_guard` is an NGINX C module that validates large JSON request bodies against structural safety limits with a streaming parser. The current NGINX integration is **post-read chunked validation**: NGINX first reads/spools the body through its normal request-body path, then this module walks the resulting buffers/temp file in bounded chunks. It helps you safely enable **full** ModSecurity / CRS inspection of large JSON bodies by rejecting malformed or structurally abusive JSON before upstream handling, while still preserving the body for later full inspection.

> **This is NOT a WAF.**  
> **This does NOT replace ModSecurity.**  
> **This does NOT implement CRS or signature matching.**  
> **This does NOT detect SQLi/XSS.**  
>
> It only validates JSON structure and configured limits. ModSecurity remains the final inspection engine.

---

## Problem statement

Large JSON request bodies are awkward for WAF deployments:

- Operators raise or disable body limits and risk memory pressure.
- Operators use `ProcessPartial` / truncation and miss attacks in the uninspected tail.
- Deeply nested or huge-string JSON can stress parsers before rules even run.

`ngx_json_guard` addresses the structural risk layer: validate JSON structure and limits before upstream handling, then let ModSecurity/CRS do full content inspection on bodies that are at least well-formed and within configured shape limits.

---

## What this module does

- Validates JSON with a streaming parser over NGINX request-body buffers/temp files after the body has been read/spooled.
- Enforces configurable limits: depth, key/string/number lengths, token counts, object/array sizes.
- Rejects malformed JSON (trailing commas, bad escapes, bad UTF-8, trailing garbage, etc.).
- Returns **400** for malformed JSON, **413** for structural limit violations.
- Leaves the request body in place so **ModSecurity can still inspect it fully**.

## What this module does not do

- Does **not** build a full JSON DOM.
- Does **not** store the full body in module memory.
- Does **not** implement ModSecurity rules or CRS.
- Does **not** match attack signatures (SQLi, XSS, etc.).
- Does **not** bypass or replace ModSecurity.
- Does **not** proxy upstream before validation finishes.
- Does **not** use Lua, Python, Rust, or external services for validation.

---

## Architecture

```
Client request
    |
    v
NGINX reads/spools body
  (memory buffers and/or client_body temp files)
    |
    v
ngx_json_guard validates buffered/spooled chunks
    |
    +-- malformed / over limit --> 400 or 413 (stop)
    |
    v
allow request to continue (body still available)
    |
    v
ModSecurity + CRS  -->  full inspection (final engine)
    |
    v
upstream application
```

### Request lifecycle (ModSecurity compatibility)

1. **PREACCESS** handler runs for a main request when `json_guard on` and `Content-Type` is JSON, regardless of HTTP method.
2. Module calls `ngx_http_read_client_request_body()` — the **same** NGINX body path used by other modules.
3. Post-body handler feeds `r->request_body` chains (and temp files) into the streaming parser in bounded chunks.
4. On success: module returns `NGX_DECLINED`; **body remains in `r->request_body`**.
5. ModSecurity (typically also preaccess) can still perform full inspection on the same buffers/temp file.
6. On failure: request is finalized with 400/413 before proxying upstream.

**Module order:** the example loads `ngx_http_json_guard_module.so` before `ngx_http_modsecurity_module.so`, and the Docker build tests that the guard runs first. Textual `load_module` order alone is not a portable guarantee: NGINX reverses phase-handler registration arrays and dynamic modules may carry ordering metadata. Re-test effective ordering with the exact NGINX and ModSecurity-nginx binaries you deploy.

The module never discards or replaces the body. It only reads it for validation.

This is not live validation while upload bytes arrive from the client. Until a body-filter or lower-level incremental integration is added, describe the NGINX behavior as **post-read chunked validation**.

---

## Repository layout

```
ngx_json_guard/
  README.md
  Makefile
  config                              # NGINX dynamic/static module build
  ngx_http_json_guard_module.c        # NGINX HTTP module
  src/
    json_guard_parser.c               # Standalone streaming parser
    json_guard_parser.h
    json_guard_limits.h
  tests/
    test_json_guard_parser.c          # Unit tests (+ payload fixtures)
    bench_json_guard_parser.c
    payloads/                         # JSON fixtures used by unit tests
  scripts/
    gen_large_json.py
    bench_parser.sh
    cross_waf_bench.py              # File-backed cross-engine workload runner
    run_cross_waf_bench.sh          # One constrained WAF profile at a time
    run_docker_integration.sh
    waf_perf.py                       # Mixed correctness/performance harness
    run_waf_perf.sh                   # Reproducible constrained run wrapper
  conf/
    nginx.conf.example                # Example NGINX site config
    modsecurity/
      main.conf                       # Endpoint-tuned CRS profile
      main-full.conf                  # Full CRS comparison profile
      minimal.conf                    # Deterministic lifecycle test profile
      json_guard_integration_rules.conf
  docker/
    Dockerfile                        # NGINX + ModSecurity + this module
    docker-compose.yml
    nginx.conf                        # Integration NGINX config
    entrypoint.sh
  integration/
    echo_backend.py                   # Upstream body-preservation probe
    run_integration_tests.sh
  benchmark/
    docker-compose.yml                # Shared APIs plus switchable WAF targets
    engines.json                      # Eight benchmark engine descriptors
    Dockerfile.coraza                 # Pinned official Coraza/Caddy connector
    nginx.conf / Caddyfile
    nginx/ modsecurity/ coraza/       # Profile-specific configuration
```

---

## Standalone parser

The parser is a pure-C finite state machine:

- No recursion; explicit container stack.
- Chunks may split anywhere (strings, escapes, `\uXXXX`, numbers, literals).
- Validates strict RFC 8259-style JSON structure.
- Supports top-level object, array, and (optionally) scalar.
- Memory use is **O(depth)**, not O(body size).

### Build & test (no NGINX required)

```bash
cc -Wall -Wextra -Werror -O2 -I./src \
  tests/test_json_guard_parser.c src/json_guard_parser.c \
  -o tests/test_json_guard_parser

./tests/test_json_guard_parser
```

Or:

```bash
make test
make test-asan
```

### Benchmark

```bash
# Generate large JSON
python3 scripts/gen_large_json.py --size-mb 10 --output /tmp/large10.json
python3 scripts/gen_large_json.py --size-mb 50 --output /tmp/large50.json
python3 scripts/gen_large_json.py --size-mb 100 --output /tmp/large100.json

# Time + max RSS (when /usr/bin/time -v is available)
./scripts/bench_parser.sh /tmp/large10.json
./scripts/bench_parser.sh --generate 100
```

Expect parse time linear in body size and **RSS roughly flat** relative to body size. The parser uses fixed-capacity nesting and duplicate-key tables rather than retaining the document.

---

## Build as NGINX dynamic module

Requires an NGINX source tree matching your runtime version.

```bash
# Example: dynamic module against nginx sources
cd /path/to/nginx-1.x.y

./configure --with-compat --add-dynamic-module=/path/to/ngx_json_guard
make modules

# Install the .so where NGINX loads modules from, e.g.:
# cp objs/ngx_http_json_guard_module.so /etc/nginx/modules/
```

Static build:

```bash
./configure --add-module=/path/to/ngx_json_guard
make
make install
```

---

## Directives

| Directive | Default | Description |
|-----------|---------|-------------|
| `json_guard` | `off` | Enable structural validation in this location/server |
| `json_guard_max_depth` | `100` | Max nesting depth |
| `json_guard_max_key_length` | `4096` | Max decoded Unicode scalar values in an object key |
| `json_guard_max_string_length` | `1048576` | Max decoded Unicode scalar values in a string value |
| `json_guard_max_number_length` | `256` | Max number token length |
| `json_guard_max_total_tokens` | `10000000` | Max structural/scalar tokens |
| `json_guard_max_object_members` | `1000000` | Max members per object |
| `json_guard_max_array_elements` | `1000000` | Max elements per array |
| `json_guard_allow_top_level_scalar` | `off` | Allow top-level `true`/`false`/`null`/number/string |
| `json_guard_reject_duplicate_keys` | `off` | Optional bounded duplicate-key rejection |

### Inspection timing

The module exposes `$json_guard_inspection_us` after validation completes. It
measures the body-buffer/temp-file walk plus parser feed and finish, in
microseconds. It excludes client upload time, ModSecurity, proxying, and the
upstream application. The value is intended for diagnostics and benchmarking,
not security decisions.

```nginx
add_header X-Json-Guard-Inspection-Us $json_guard_inspection_us always;
```

### Content-Type behavior

Validation runs only for:

- `application/json`
- `application/*+json`
- Parameterized forms such as `application/json; charset=utf-8`

Skipped for multipart, urlencoded, text/plain, missing Content-Type, and subrequests. Method does not affect selection: DELETE, custom methods, and other requests with a JSON Content-Type are validated too. A JSON-typed request with no body is rejected as empty JSON.

### Return codes

| Condition | Status |
|-----------|--------|
| Malformed JSON | **400 Bad Request** |
| Structural limit exceeded | **413 Payload Too Large** |
| Internal error | **500** |

---

## Example NGINX config

See also `conf/nginx.conf.example` and the integration config at `docker/nginx.conf`.

```nginx
load_module modules/ngx_http_json_guard_module.so;
# Verify effective PREACCESS ordering with your exact dynamic-module build.
load_module modules/ngx_http_modsecurity_module.so;

http {
    client_max_body_size 500m;
    client_body_buffer_size 64k;
    client_body_in_file_only clean;
    client_body_temp_path /var/lib/nginx/client_body_temp 1 2;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    server {
        listen 8080;

        location /api/ {
            json_guard on;
            json_guard_max_depth 100;
            json_guard_max_string_length 1048576;

            # Optional tighter limits for untrusted APIs:
            # json_guard_max_total_tokens 1000000;
            # json_guard_max_object_members 10000;
            # json_guard_reject_duplicate_keys on;

            proxy_pass http://backend;
        }
    }
}
```

### Example ModSecurity settings

```apache
SecRequestBodyAccess On
SecRequestBodyLimit 524288000
SecRequestBodyNoFilesLimit 524288000
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 100

# Prefer full body inspection — do not rely on ProcessPartial for JSON APIs
# when ngx_json_guard is providing early structural rejection.
```

**Again:** `ngx_json_guard` only validates structure/limits. ModSecurity + CRS still perform attack detection.

---

## Security notes

- Treat this as a **guard layer**, not a security boundary by itself.
- Always keep ModSecurity (or equivalent) enabled for JSON APIs that need attack detection.
- Tune limits to your API schema; defaults are intentionally generous for large bodies.
- Empty JSON bodies with `Content-Type: application/json` are rejected as incomplete/malformed.
- Top-level scalars are rejected by default (`json_guard_allow_top_level_scalar off`).
- Duplicate-key rejection is optional and disabled by default.
- `\u` escapes are validated, including rejection of unpaired UTF-16 surrogate escapes.
- Key and string length limits count decoded Unicode scalar values, so raw UTF-8 and equivalent surrogate-pair escapes count consistently.
- Compressed request bodies are not decompressed by this module.
- Full raw-body preservation does not by itself prove that every JSON value reaches CRS targets such as `ARGS`. If `SecArgumentsLimit` is configured, pair it with a fail-closed rule and integration-test attacks near the end of high-member-count documents.
- Do not claim “WAF offloading” complete after enabling this module alone.

---

## Known limitations

- Validates structure only; does **not** canonicalize JSON for ModSecurity.
- Duplicate-key rejection uses a fixed fingerprint table, not full key storage. It is bounded and fail-closed if the table fills; extremely unlikely fingerprint collisions are rejected as duplicates.
- Compressed bodies (`Content-Encoding`) are not supported unless decompressed before this module.
- NDJSON / JSON Lines is not supported in v1.
- Multipart bodies are not validated (skipped).
- Very large single JSON strings are bounded by `max_string_length`.
- Temp-file body reads use blocking local `ngx_read_file` in bounded chunks (not client-socket blocking).
- Module order: for earliest reject, ensure this module’s access handler runs before other body consumers when possible; see NGINX module load order and integration-test this with `modsecurity-nginx` in your exact build.
- This is a guard layer; **ModSecurity remains the final inspection engine**.

---

## Parser API (standalone)

```c
typedef enum {
    JG_OK = 0,
    JG_NEED_MORE,
    JG_REJECT_MALFORMED,
    JG_REJECT_LIMIT,
    JG_INTERNAL_ERROR
} jg_result_t;

void jg_parser_init(jg_parser_t *parser, const jg_limits_t *limits);
jg_result_t jg_parser_feed(jg_parser_t *parser,
                           const unsigned char *data, size_t len);
jg_result_t jg_parser_finish(jg_parser_t *parser);
jg_error_t  jg_parser_error(const jg_parser_t *parser);
const char *jg_error_string(jg_error_t err);
```

---

## Docker integration test (ordering + full-body preservation)

The Docker image builds NGINX with:

- `ngx_http_json_guard_module` (this project)
- `ngx_http_modsecurity_module` + libmodsecurity v3
- A tiny Python echo upstream that reports body length, sha256, and marker presence

```bash
# Build image + run integration suite (several minutes first build)
make docker-test
# or:
./scripts/run_docker_integration.sh
```

What the suite proves:

| # | Case | Expected | Proof |
|---|------|----------|--------|
| 1 | Valid small JSON | 200 | Upstream receives body |
| 2 | Trailing comma | **400** | `json_guard` rejects before upstream |
| 3 | Valid JSON + attack marker | **403** | ModSecurity still inspects after guard ACCEPT |
| 4 | Large JSON + tail marker | 200 | Upstream `body_len` matches; tail marker present |
| 5 | `text/plain` + malformed JSON | not 400 | Content-Type gate skips guard |
| 6 | `application/vnd.api+json` | 200 | `*+json` Content-Type match |
| 7 | Excessive nesting | **413** | Structural limit |
| 8 | `/noguard/` malformed | 200 | Contrast path without guard |
| 9 | Duplicate object key | **400** | Optional duplicate-key rejection enabled in Docker config |
| 10 | Malformed DELETE JSON | **400** | JSON validation is independent of HTTP method |
| 11 | Two requests on one connection | 200, 200 | Body-read reference is released for keep-alive reuse |
| 12 | Mixed-case `*+json` with OWS | 200 | Case-insensitive media-type matching and trimming |

Log lines of interest inside the container:

```text
json_guard: ACCEPT structurally OK
json_guard: REJECT status=400 ...
```

Manual compose:

```bash
docker compose -f docker/docker-compose.yml up --build -d
./integration/run_integration_tests.sh http://127.0.0.1:8080
docker compose -f docker/docker-compose.yml down
```

## Constrained WAF lab

`docker/docker-compose.api.yml` runs four inert upstreams behind one WAF:

| Route | Body type | Protection |
|---|---|---|
| `/json/` | JSON | JSON Guard, ModSecurity, CRS |
| `/xml/` | XML | ModSecurity XML processor, CRS |
| `/form/` | URL-encoded | ModSecurity, CRS |
| `/web/` | Query/text | ModSecurity, CRS |

The image pins OWASP CRS `v4.25.0`. The WAF container, and only that container,
is capped at `2 vCPU`, `4 GiB` RAM, and no additional swap. Two NGINX workers
match the CPU quota. The backends parse and log bounded samples; they never
execute submitted values.

```bash
docker compose -f docker/docker-compose.api.yml up --build -d
curl -X POST http://127.0.0.1:8081/json/ingest \
  -H 'Host: waf.local' \
  -H 'Content-Type: application/json' \
  --data-binary '{"user":{"id":42,"name":"Ada"},"active":true}'
```

The default `main.conf` is an endpoint-tuned CRS profile. Full CRS remains on
for web, form, and XML routes. On `/json/`, it retains protocol rules, primary
libinjection SQLi/XSS checks, and selected LFI/RCE checks while excluding costly
secondary and language-specific families. These exclusions are a policy choice,
not equivalent security coverage; validate them against the real API threat
model. Use the full comparison profile with:

```bash
WAF_CONFIG=main-full.conf docker compose \
  -f docker/docker-compose.api.yml up --build -d
```

The constrained JSON profile accepts single strings up to 64 MiB but limits a
document to 100,000 tokens, 10,000 members per object, and 10,000 elements per
array. A 200k-line/high-member JSON document is therefore deliberately rejected
with 413 before CRS. Full CRS performs per-argument rule evaluation; accepting
arbitrarily many JSON values would make CPU work attacker-controlled.

### Correctness and performance

```bash
# One of every case, including 20 MiB clean/tail-attack/malformed payloads
make waf-correctness

# 175 mixed requests, four clients, repeated large payloads
make waf-perf

# Reproduce the untuned full-CRS comparison
WAF_CONFIG=main-full.conf PROFILE=correctness WORKERS=1 \
  SMALL_REPEAT=1 LARGE_REPEAT=1 ./scripts/run_waf_perf.sh
```

Each run writes exact payload fixtures, JSON results, a Markdown report,
cgroup CPU/memory counters, logs, config snapshots, and hashes under
`artifacts/waf-perf/`. The `X-Json-Guard-Inspection-Us` response header measures
only the Guard's temp-file/buffer walk and parser work. Total HTTP latency also
contains upload, CRS, proxy, and upstream time. ModSecurity v3 exposes no exact
portable phase-2 timer here, so CRS cost is obtained by controlled profile or
`/guard-only` differential measurements.

Measured on the fixed `2 vCPU / 4 GiB` WAF budget:

| Run | 20 MiB clean | 20 MiB tail SQLi | Peak RAM | Result |
|---|---:|---:|---:|---|
| Full CRS, serial | 18.05 s | 18.11 s | 392 MiB | 21/21 correct |
| Tuned JSON, serial | 2.77 s | 2.49 s | 364 MiB | 21/21 correct |
| Tuned mixed, 4 clients | 3.74 s p50 | 2.83 s p50 | 607 MiB | 175/175 correct |

The mixed run processed 243 MiB of request bodies in 11.01 seconds
(`22.08 MiB/s`) at 184.6% average CPU. JSON Guard itself took roughly 145-152 ms
p50 for accepted 20 MiB bodies; most remaining time was ModSecurity/CRS. These
are local lab measurements, not production capacity guarantees. See
`artifacts/waf-perf/FINAL_REPORT.md` for the comparison and caveats.

Synchronous CRS work can occupy both NGINX workers. During the mixed run, a few
small requests waited about 2.8-3.6 seconds behind large scans. Four workers on
the same two CPUs did not fix this: throughput fell, CPU throttling increased,
and peak memory rose to about 1.08 GiB. Latency-sensitive and bulk JSON traffic
should use separate WAF process pools with an aggregate resource budget.

Many-key payload generation remains available, but the constrained profile
expects 413 for the default 200k-line documents:

```bash
./scripts/stress_many_json_pairs.py --payloads 6 --lines 200000 \
  --workers 3 --clean
```

## Cross-WAF JSON processing benchmark

The cross-WAF lab compares structural JSON admission separately from full CRS
rule evaluation. It runs one WAF target at a time against the same four inert
upstreams and reuses one file-backed, SHA-256-manifested payload corpus.

| Profile | Connector | JSON processing | CRS |
|---|---|---|---|
| `nginx-baseline` | NGINX | none | no |
| `nginx-guard` | NGINX | JSON Guard | no |
| `nginx-modsecurity-processor` | ModSecurity-nginx | native JSON | no |
| `nginx-guard-modsecurity-processor` | ModSecurity-nginx | Guard + native JSON | no |
| `nginx-modsecurity-crs` | ModSecurity-nginx | native JSON | v4.25.0 PL1 |
| `nginx-guard-modsecurity-crs` | ModSecurity-nginx | Guard + native JSON | v4.25.0 PL1 |
| `coraza-processor` | official Coraza/Caddy | native JSON | no |
| `coraza-crs` | official Coraza/Caddy | native JSON | v4.25.0 PL1 |

The Coraza image pins Caddy 2.11.3 and `coraza-caddy` commit
`82f09c076b75f0096b8c9ebc58e1ce53e2947198`. `caddy build-info` verifies that
the resulting binary contains Coraza v3.7.0 and `coraza-coreruleset` v4.25.0.
Every active WAF container is limited to 2 vCPU, 4 GiB memory, and zero cgroup
swap; shared upstreams are outside that WAF budget. Body processing is
fail-closed (`SecRequestBodyLimitAction Reject`), never `ProcessPartial`.

```bash
# Focused structural smoke test across all eight profiles
make cross-waf-smoke

# Representative correctness, processor/CRS, and mixed run through 20 MiB
make cross-waf-quick

# Warm-up plus planned repetitions and processor concurrency 1/2/4
make cross-waf-full

# One repetition of 50/100 MiB processor and 64/128 MiB boundary cases
make cross-waf-large

# Limit the run while developing the harness
MODE=quick ENGINES="nginx-guard nginx-modsecurity-processor" \
  RESULTS_ROOT="$PWD/artifacts/cross-waf/local" \
  ./scripts/run_cross_waf_bench.sh
```

Payload generation currently occupies about 705 MiB under
`artifacts/cross-waf/payloads/`. Requests stream those files in 1 MiB client
chunks; concurrent 100 MiB bodies are not retained in Python memory. For every
body that reaches an upstream, the harness checks the upstream-reported byte
length and SHA-256 digest. Each run records raw and normalized outcomes,
latencies, the exact Guard timer when available, matched rule IDs, cgroup CPU,
throttling, current/peak memory, memory events, I/O counters, logs, image
digests, container inspection, and configuration snapshots in JSON, CSV, and
Markdown.

Representative reports from the constrained local run are:

- `artifacts/cross-waf/smoke-final-20260710/COMPARISON.md`: finalized harness
  smoke run, including audit logs and executable build/version metadata.
- `artifacts/cross-waf/quick-20260710/COMPARISON.md`: all eight profiles through
  the representative 20 MiB workload.
- `artifacts/cross-waf/large-20260710/COMPARISON.md`: one-repetition 50/100 MiB
  processor and 64/128 MiB boundary supplement.

The quick Coraza full-CRS row is a reduced 12-request subset, not the complete
NGINX 34-request CRS suite: Coraza/Caddy took about 140 seconds for each clean or
tail-attack 20 MiB full-CRS request on this budget. The report flags unequal
suite counts, so aggregate CRS throughput must not be ranked across those rows.
Compare identical per-case medians. Likewise, only JSON Guard exposes a precise
parser timer; the harness does not fabricate equivalent ModSecurity or Coraza
timings.

Observed parser-policy differences are retained as results. In this run,
ModSecurity/YAJL accepted an unpaired UTF-16 surrogate escape, Coraza allowed
that case and invalid UTF-8 to reach the upstream, and Coraza counted a
10,000-element array differently from a 10,000-member object at the configured
argument boundary. These are compatibility findings, not silently normalized
away. The small benign corpus also produced one common CRS false positive; it
is a sanity check, not a general false-positive ranking.

## Native DigitalOcean benchmark

The native lab runs the same eight profiles directly under systemd without
Docker. It is intentionally restricted to identical Ubuntu 24.04 x64 hosts
with cgroup v2, at least 10 GiB free disk, and no active swap. It installs all
benchmark software under `/opt/ngx-json-guard` and `/etc/ngx-json-guard`; it
does not replace distribution NGINX or modify firewall rules.

The default upstream is a loopback streaming hash sink in its own systemd
cgroup. It does not retain or parse the body. Its response reports body length,
SHA-256, and processing microseconds so upstream work can be separated from WAF
work. NGINX and Coraza bind only to `127.0.0.1:8091` and `127.0.0.1:8092`.

For cleaner WAF measurements, use one separate API droplet for both WAF hosts.
A 1 vCPU / 2 GiB API host is sufficient for an initial serial/concurrency-four
run as long as its reported processing time does not become the bottleneck.
Use the DigitalOcean private VPC address rather than exposing the sink publicly.

On the API droplet:

```bash
git clone <repository-url> ngx_json_guard
cd ngx_json_guard

sudo API_BIND_ADDRESS=10.0.0.5 API_SERVER_LABEL=do-api-1vcpu-2gb \
  ./scripts/native_api_server.sh setup

sudo ./scripts/native_api_server.sh status
```

The API script prints the exact `BACKEND_URL`. Apply it while setting up both
WAF droplets:

```bash
sudo BACKEND_URL=http://10.0.0.5:9100 \
  SERVER_LABEL=do-2vcpu-4gb ./scripts/native_lab.sh all

sudo BACKEND_URL=http://10.0.0.5:9100 \
  SERVER_LABEL=do-4vcpu-8gb ./scripts/native_lab.sh all
```

`BACKEND_URL` is persisted in `/etc/ngx-json-guard/lab.env`; later runs do not
need it repeated. External mode disables the local sink, health-checks the
remote API before every suite, and records `/metrics` deltas plus the
`X-Upstream-Processing-Us` response timing. The metrics include request, byte,
processing-time, cgroup CPU, memory, I/O, and pressure values. If a public IP
must be used, limit TCP port 9100 to the two WAF source IPs with a DigitalOcean
Cloud Firewall; the setup script deliberately does not change host firewall
policy.

After both WAF runs, collect the API-side environment, journal, cgroup, and
cumulative metrics:

```bash
sudo API_SERVER_LABEL=do-api-1vcpu-2gb \
  ./scripts/native_api_server.sh collect
```

```bash
git clone <repository-url> ngx_json_guard
cd ngx_json_guard

# Idempotent source build, service installation, parser/sanitizer tests,
# and native ordering/body-preservation/CRS smoke checks.
sudo ./scripts/native_lab.sh setup

# Individual workloads.
sudo SERVER_LABEL=do-2vcpu-4gb ./scripts/native_lab.sh smoke
sudo SERVER_LABEL=do-2vcpu-4gb ./scripts/native_lab.sh quick
sudo SERVER_LABEL=do-2vcpu-4gb ./scripts/native_lab.sh full
sudo SERVER_LABEL=do-2vcpu-4gb ./scripts/native_lab.sh large

# Setup, full matrix, 50/100 MiB supplement, and one bundle.
sudo SERVER_LABEL=do-2vcpu-4gb ./scripts/native_lab.sh all
```

`all` attempts to create a bundle even if setup or execution fails. Exit code
`3` means the matrix completed but correctness/policy findings were recorded;
other nonzero codes indicate setup or infrastructure failure. An active swap
preflight failure can be explicitly overridden with `ALLOW_SWAP=1`, although
the two comparison hosts should use the same swap policy.

Each suite recreates the active WAF service cgroup. The local backend is also
restarted in local mode; an external backend remains running and is measured
using before/after metrics. Artifacts include request JSON/CSV, audit logs,
journals, exact configs, binary/source hashes, WAF and backend cgroup
CPU/memory/I/O/pressure, and whole-host `vmstat`, `mpstat`, `iostat`, `pidstat`,
load, network, and CPU-steal data. Runs above 5% average steal are flagged as shared-CPU noisy but are never
discarded automatically.

The final files are written below
`artifacts/native/<server-label>-<UTC timestamp>/`. Share
`bundle.tar.zst` and `bundle.tar.zst.sha256` from both hosts. To compare two
directories or bundles locally:

```bash
python3 scripts/compare_native_hosts.py \
  do-2vcpu-4gb/bundle.tar.zst \
  do-4vcpu-8gb/bundle.tar.zst \
  --output-dir artifacts/native/host-comparison
```

The host comparison reports latency speedup, CPU scaling efficiency,
CPU-seconds per MiB, peak memory, correctness parity, and noisy-neighbor flags.
The payload files live under `/var/lib/ngx-json-guard/payloads` and are excluded
from bundles; their manifest and SHA-256 values are included.

---

## Future work / TODOs

- [ ] Event-driven temp-file reads if needed under extreme load.
- [ ] NDJSON mode (optional).
- [ ] Metrics counters (accepted/rejected/malformed/limit via stub_status or Prometheus).

---

## License

Choose and add a license appropriate for your distribution (e.g. BSD-2-Clause, common for NGINX modules). Not specified in this scaffold.
