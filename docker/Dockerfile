# Build NGINX with dynamic modules:
#   - ngx_http_json_guard_module
#   - ngx_http_modsecurity_module (libmodsecurity v3)
#
# Usage (from repo root):
#   docker build -f docker/Dockerfile -t ngx_json_guard:test .
#   docker run --rm -p 8080:8080 ngx_json_guard:test

ARG NGINX_VERSION=1.26.2
ARG MODSECURITY_TAG=v3.0.13
ARG MODSECURITY_NGINX_TAG=v1.0.3
ARG CRS_TAG=v4.25.0

FROM debian:bookworm-slim AS build

ARG NGINX_VERSION
ARG MODSECURITY_TAG
ARG MODSECURITY_NGINX_TAG
ARG CRS_TAG

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libcurl4-openssl-dev \
        libgeoip-dev \
        liblmdb-dev \
        libpcre2-dev \
        libpcre3-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        libyajl-dev \
        pkg-config \
        zlib1g-dev \
        automake \
        autoconf \
        g++ \
        make \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# --- libmodsecurity ---
RUN git clone --depth 1 --branch ${MODSECURITY_TAG} \
        https://github.com/owasp-modsecurity/ModSecurity \
    && cd ModSecurity \
    && git submodule update --init --recursive --depth 1 \
    && ./build.sh \
    && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig

# --- ModSecurity-nginx connector ---
RUN git clone --depth 1 --branch ${MODSECURITY_NGINX_TAG} \
        https://github.com/owasp-modsecurity/ModSecurity-nginx

# --- OWASP Core Rule Set (pinned LTS release) ---
RUN git clone --depth 1 --branch ${CRS_TAG} \
        https://github.com/coreruleset/coreruleset \
    && cp /src/coreruleset/crs-setup.conf.example \
          /src/coreruleset/crs-setup.conf

# --- nginx sources ---
RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
        | tar xz

# --- our module ---
COPY config /src/ngx_json_guard/config
COPY ngx_http_json_guard_module.c /src/ngx_json_guard/ngx_http_json_guard_module.c
COPY src /src/ngx_json_guard/src

WORKDIR /src/nginx-${NGINX_VERSION}

RUN ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/etc/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/tmp/nginx.pid \
        --lock-path=/tmp/nginx.lock \
        --http-client-body-temp-path=/tmp/client_body_temp \
        --http-proxy-temp-path=/tmp/proxy_temp \
        --with-compat \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_stub_status_module \
        --add-dynamic-module=/src/ModSecurity-nginx \
        --add-dynamic-module=/src/ngx_json_guard \
    && make -j"$(nproc)" \
    && make install \
    && mkdir -p /etc/nginx/modules \
    && cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules/ \
    && cp objs/ngx_http_json_guard_module.so /etc/nginx/modules/


# --- runtime ---
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libcurl4 \
        libgeoip1 \
        liblmdb0 \
        libpcre3 \
        libssl3 \
        libxml2 \
        libyajl2 \
        python3 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p \
        /var/log/nginx \
        /var/log/modsec \
        /tmp/client_body_temp \
        /tmp/proxy_temp \
        /etc/nginx/modsec \
        /etc/nginx/modules

COPY --from=build /usr/sbin/nginx /usr/sbin/nginx
COPY --from=build /etc/nginx /etc/nginx
COPY --from=build /usr/local/lib/libmodsecurity.so* /usr/local/lib/
COPY --from=build /usr/local/lib/pkgconfig /usr/local/lib/pkgconfig

# Some installs place unicode.mapping next to modsec
COPY --from=build /src/ModSecurity/unicode.mapping /etc/nginx/modsec/unicode.mapping
COPY --from=build /src/coreruleset /etc/nginx/modsec/crs

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local-lib.conf && ldconfig \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY conf/modsecurity/main.conf /etc/nginx/modsec/main.conf
COPY conf/modsecurity/main-full.conf /etc/nginx/modsec/main-full.conf
COPY conf/modsecurity/minimal.conf /etc/nginx/modsec/minimal.conf
COPY conf/modsecurity/json_guard_integration_rules.conf \
     /etc/nginx/modsec/json_guard_integration_rules.conf
COPY integration/echo_backend.py /usr/local/bin/echo_backend.py
COPY docker/entrypoint.sh /entrypoint.sh

# Provide a minimal mime.types if build tree path differs
RUN if [ ! -f /etc/nginx/mime.types ]; then \
      printf 'types {\n  text/html html;\n  application/json json;\n  text/plain txt;\n}\n' \
        > /etc/nginx/mime.types; \
    fi \
    && chmod +x /entrypoint.sh /usr/local/bin/echo_backend.py

# Fix SecTmpDir references already in main.conf; ensure unicode path works
RUN sed -i 's|/etc/nginx/modsec/unicode.mapping|/etc/nginx/modsec/unicode.mapping|g' \
        /etc/nginx/modsec/main.conf || true

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/entrypoint.sh"]
