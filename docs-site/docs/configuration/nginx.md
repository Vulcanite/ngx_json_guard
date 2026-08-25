# NGINX configuration reference

All directives live in the `http`, `server`, or `location` contexts and
follow standard NGINX inheritance: a child block inherits from its parent,
and any directive set in the child overrides the inherited value.

## Enabling the guard

```nginx
json_guard on;
```

When enabled in a location, requests whose `Content-Type` is
`application/json` (any `+json` suffix, case-insensitive, with
parameters such as `charset` tolerated) are validated **regardless of
HTTP method** — a `GET` carrying a JSON body is validated too.

:::note Empty bodies
A request with a JSON content type and **no body** (for example a `GET`
with `Content-Type: application/json`) fails validation and is answered
with **400**. If you serve such requests through the same location, gate
them into a separate `location` with `json_guard off`. A
`json_guard_methods` directive is on the roadmap.
:::

## Response codes

| Condition | Status |
|---|---|
| Malformed JSON (syntax, escapes, UTF-8, trailing garbage) | 400 |
| Structural limit exceeded (depth, lengths, tokens, widths) | 413 |
| Internal error (temp-file I/O, allocator, parser failure) | 500 |

Rejections happen at the edge: the body is not proxied and ModSecurity
never scans it.

## Directives

| Directive | Default | Description |
|---|---|---|
| `json_guard` | `off` | Enable structural validation for this context |
| `json_guard_max_depth` | `100` | Maximum nesting depth (hard ceiling 1024; larger configured values are clamped) |
| `json_guard_max_key_length` | `4096` | Maximum Unicode scalar values in an object key |
| `json_guard_max_string_length` | `1048576` | Maximum Unicode scalar values in a string value (1 MiB of characters) |
| `json_guard_max_number_length` | `256` | Maximum number token length |
| `json_guard_max_total_tokens` | `10000000` | Maximum total structural/scalar tokens |
| `json_guard_max_object_members` | `1000000` | Maximum members per object |
| `json_guard_max_array_elements` | `1000000` | Maximum elements per array |
| `json_guard_allow_top_level_scalar` | `off` | Permit a top-level `true` / `false` / `null` / number / string |
| `json_guard_reject_duplicate_keys` | `off` | Reject objects with duplicate keys (bounded fingerprint table, fails closed) |

A value of `0` for length, token, and width limits means **unlimited**.
`json_guard_max_depth 0` is **not** unlimited: it is clamped to the
internal ceiling of 1024, the same as any configured value above 1024.
Limits are enforced while streaming, so an over-limit body is rejected as
soon as the violation is seen — a `tokens_100001` rejection fires ~3.5 ms
into the stream, not after the whole body arrives.

## Inspection timer variable

| Variable | Meaning |
|---|---|
| `$json_guard_inspection_us` | Microseconds the guard spent walking and validating this body |

It measures the buffer/temp-file walk plus parser feed and finish. It
excludes client upload time, ModSecurity, proxying, and the upstream
application. Useful in `log_format` and as an HTTP header for diagnostics:

```nginx
log_format guard '$remote_addr $status guard_us=$json_guard_inspection_us '
                 'bytes=$request_length rt=$request_time';
access_log /var/log/nginx/api.log guard;
```

## Complete examples

### Guard only (no WAF)

```nginx
http {
    server {
        listen 80;

        location /api/ {
            json_guard on;
            proxy_pass http://app;
        }

        # health checks without bodies bypass the guard
        location = /healthz {
            json_guard off;
            proxy_pass http://app;
        }
    }
}
```

### Guard before ModSecurity + CRS

```nginx
load_module modules/ngx_http_json_guard_module.so;   # guard first
load_module modules/ngx_http_modsecurity_module.so;

events { worker_connections 4096; }

http {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    server {
        listen 80;

        location /api/ {
            json_guard on;

            # With the guard enforcing structure upstream, keep FULL
            # body inspection — do not enable partial processing.
            # SecRequestBodyLimit can be raised safely for JSON routes.
            proxy_pass http://app;
        }

        # non-JSON routes: no guard cost at all
        location /assets/ {
            proxy_pass http://app;
        }
    }
}
```

:::warning Module order is load-bearing
The guard must run before ModSecurity in PREACCESS. Loading the guard's
`load_module` line first is the convention, but textual order is not a
portable guarantee across NGINX builds — verify with your production
binaries by sending a malformed JSON body and confirming the 400 comes
from the guard (check `$json_guard_inspection_us` is set).
:::

### Tight API profile

```nginx
location /v1/events/ {
    json_guard on;
    json_guard_max_depth 16;              # flat event batches
    json_guard_max_key_length 256;
    json_guard_max_string_length 8192;    # no essay fields
    json_guard_max_array_elements 1000;   # bounded batches
    json_guard_reject_duplicate_keys on;  # strict producers
    proxy_pass http://app;
}
```

## Interaction with body size limits

- `client_max_body_size` still applies first: bodies over it are rejected
  by core NGINX with 413 before the guard sees them.
- `client_body_buffer_size` decides whether the body lives in memory
  buffers or is spooled to a `client_body_temp` file. The guard walks
  either transparently, in 64 KiB chunks.
- On the ModSecurity side you can now keep `SecRequestBodyLimit` generous
  and **leave partial processing off** — the structural risk it was
  mitigating is handled before libmodsecurity parses anything.
