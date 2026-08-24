# Install on Linux

Two ways to run `ngx_json_guard` on a Linux host: as a **dynamic module**
against your existing NGINX, or **built statically** into a custom NGINX.
If you just want to evaluate the parser itself, no NGINX is needed at all.

## Build the dynamic module

Dynamic modules must match your runtime NGINX: same version, and
preferably the same `configure` arguments (`nginx -V` prints them). Build
against an NGINX source tree of the exact same version:

```bash
# 1. Get NGINX sources matching your runtime version
curl -O https://nginx.org/download/nginx-1.26.2.tar.gz
tar xf nginx-1.26.2.tar.gz
cd nginx-1.26.2

# 2. Configure with --with-compat and the module
./configure --with-compat \
    --add-dynamic-module=/path/to/ngx_json_guard

# 3. Build only modules
make modules

# 4. Install the .so where your NGINX loads modules from
cp objs/ngx_http_json_guard_module.so /etc/nginx/modules/
```

If your NGINX was built with additional arguments (check `nginx -V`),
pass the same ones to `./configure` — `--with-compat` relaxes some of the
matching requirements but not all.

## Build statically

For a custom NGINX build:

```bash
cd /path/to/nginx-1.26.2
./configure --add-module=/path/to/ngx_json_guard
make
make install
```

## Enable in nginx.conf

```nginx
# top of nginx.conf, before events {}
load_module modules/ngx_http_json_guard_module.so;

http {
    server {
        listen 80;

        location /api/ {
            json_guard on;
            proxy_pass http://app;
        }
    }
}
```

Requests to `/api/` with a JSON `Content-Type` now get structural
validation. Malformed JSON is answered with 400, structural limit
violations with 413. See the
[configuration reference](/docs/configuration/nginx) for every directive.

## Verify it works

```bash
# Valid body → passes to upstream
curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Content-Type: application/json' \
    -d '{"ok": true}' http://localhost/api/echo

# Malformed body → 400 from the guard
curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Content-Type: application/json' \
    -d '{"ok": true,}' http://localhost/api/echo

# Depth over the default limit (100) → 413 from the guard
python3 -c "print('['*200 + ']'*200)" | \
    curl -s -o /dev/null -w '%{http_code}\n' \
        -H 'Content-Type: application/json' \
        --data-binary @- http://localhost/api/echo
```

Expected: `200`, `400`, `413`.

To observe the guard's own cost per request, log the timer variable:

```nginx
log_format guard '$status inspection_us=$json_guard_inspection_us';
access_log /var/log/nginx/guard.log guard;
```

## Standalone parser (no NGINX)

The streaming parser is pure C with no NGINX dependency. Build and run the
unit suite, including an ASan/UBSan build:

```bash
cd /path/to/ngx_json_guard
make test        # 75 parser tests
make test-asan   # same suite under AddressSanitizer + UBSan
```

Quick parser benchmark:

```bash
make bench-micro
```

Output is median-of-15 parse passes per payload size; expect roughly
linear time in body size and flat memory regardless of body size.

## Distribution notes

- **Debian/Ubuntu NGINX**: distro packages are built with their own
  module directory (`/usr/lib/nginx/modules`) and specific configure
  flags; match them exactly or rebuild NGINX.
- **Official NGINX images**: see [Install in Docker](/docs/install/docker) —
  the repo ships a Dockerfile that compiles NGINX + the module +
  ModSecurity + CRS in one image.
- **ABI compatibility** is the recurring gotcha with dynamic modules: if
  NGINX reports a version mismatch on `load_module`, the module was not
  built against the same version/flags as the running binary.
