# Install in Docker

The repository ships Dockerfiles that compile everything from pinned
sources — NGINX, `ngx_json_guard`, libmodsecurity, ModSecurity-nginx and
the OWASP Core Rule Set — so the image you run is the image the
benchmarks ran against.

## Build the WAF image

```bash
cd /path/to/ngx_json_guard
make docker-build        # docker build -f docker/Dockerfile -t ngx_json_guard:test .
```

What ends up inside (versions pinned in `benchmark/native/versions.env`):

| Component | Version |
|---|---|
| NGINX | 1.26.2 |
| ngx_json_guard | built from this repo |
| libmodsecurity | 3.0.13 |
| ModSecurity-nginx | 1.0.3 |
| OWASP CRS | 4.25.0 |

The entrypoint verifies that the guard is registered before ModSecurity in
the PREACCESS phase and fails startup otherwise.

## Run the integration tests

```bash
make docker-test         # scripts/run_docker_integration.sh
```

This brings up the full stack (NGINX + guard + ModSecurity + CRS + echo
backends) and asserts a matrix of expected status codes: valid bodies
200, malformed 400, over-limit 413, SQLi 403 — across routes, content
types, and chunked uploads.

## Run it with your own upstream

The compose stack in `docker/docker-compose.api.yml` wires NGINX to four
fixture upstreams (JSON, XML, form, web). To point it at your app, mount
your own NGINX config:

```yaml
services:
  waf:
    image: ngx_json_guard:test
    ports: ["8080:8080"]
    volumes:
      - ./my-nginx.conf:/etc/nginx/nginx.conf:ro
    # your app reachable at app:9000 from this network
    extra_hosts:
      - "app:host-gateway"
```

A minimal `my-nginx.conf` with the guard in front of ModSecurity:

```nginx
load_module modules/ngx_http_json_guard_module.so;
load_module modules/ngx_http_modsecurity_module.so;

events { worker_connections 1024; }

http {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    server {
        listen 8080;

        location /api/ {
            json_guard on;
            json_guard_max_depth 64;
            proxy_pass http://app:9000;
        }
    }
}
```

## Benchmark images

Two more images exist for reproducing the
[benchmark results](/docs/performance/results):

- `ngx_json_guard_api:test` — fixture upstream apps
  (`docker/Dockerfile.api`)
- `ngx_json_guard_coraza:test` — Caddy + Coraza 3.7.0 + CRS for the
  cross-engine comparison (`benchmark/Dockerfile.coraza`)

```bash
make cross-waf-full     # all eight engine profiles (~90 min + build time)
make waf-correctness    # 21-case constrained run
make waf-perf           # 175-request mixed run
```

Reports, per-request JSON, and cgroup snapshots land under
`artifacts/`. Note that `run_waf_perf.sh` expects the API upstreams from
`docker/docker-compose.api.yml` to be running in the same compose project:

```bash
docker compose -f docker/docker-compose.api.yml up -d \
    json_api xml_api form_api web_app
```

## Notes

- Container resource limits in the benchmark compose files (2 vCPU /
  4 GiB) are what make the published numbers reproducible; keep them if
  you fork the harness.
- The images are benchmark/reference builds. For production, prefer
  building your own image from the same Dockerfiles with your NGINX
  version, and pin to a released tag of this module.
