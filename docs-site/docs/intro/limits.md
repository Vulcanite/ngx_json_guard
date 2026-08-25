# Limits, caveats, and operator notes

`ngx_json_guard` is a structural admission layer. Keep these boundaries
in mind when you enable it in front of ModSecurity (or Coraza).

## What it will not do

- It does **not** detect SQLi, XSS, or any CRS signature. ModSecurity
  remains the inspection engine.
- It does **not** canonicalize JSON for later modules. Duplicate keys,
  when allowed, are left as the client sent them.
- It does **not** decompress `Content-Encoding`. Compressed JSON is
  skipped or will fail as malformed bytes unless something in front
  inflates the body.
- It does **not** validate multipart, urlencoded, or `text/plain` bodies.
  Selection is `Content-Type: application/json` and `application/*+json`.
- NDJSON / JSON Lines is not supported.

## Limit of `0`

A configured `0` on length, token, and width limits means **unlimited**.
`json_guard_max_depth 0` is **not** unlimited: the parser clamps depth to
the internal stack ceiling of **1024**, the same as any value above 1024.

## Duplicate keys

`json_guard_reject_duplicate_keys` is off by default. When on, detection
uses a fixed fingerprint table (1024 slots), not full key storage. If the
table fills, validation **fails closed** (413). Extremely unlikely hash
collisions are treated as duplicates.

## Module order

The guard registers in PREACCESS. Loading
`ngx_http_json_guard_module.so` before `ngx_http_modsecurity_module.so`
is the supported convention, but textual `load_module` order is not a
portable guarantee. Confirm with your binaries: a trailing-comma JSON
body should return the guard's **400**, not a ModSecurity response.

## Empty JSON-typed requests

A request with a JSON `Content-Type` and no body is rejected as
incomplete JSON (**400**), including `GET`/`HEAD` that carry that header.
Split those routes into a location with `json_guard off` if you need
them. A `json_guard_methods` directive is on the roadmap.

## Internal errors

I/O failures reading the spooled body, allocator failures, and parser
internal errors return **500**. Expected client problems are **400**
(malformed) or **413** (limit).

## Body preservation vs CRS argument limits

The module never discards or rewrites the body. That does not by itself
prove every JSON value reaches CRS targets such as `ARGS`. If
`SecArgumentsLimit` is set, pair it with a fail-closed rule and test
attacks near the end of high-member-count documents.
