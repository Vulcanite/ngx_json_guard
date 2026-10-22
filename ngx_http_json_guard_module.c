/*
 * ngx_http_json_guard_module.c
 *
 * NGINX HTTP module that validates JSON request bodies with a streaming
 * parser after NGINX has read/spooled the body, before the request continues
 * to later modules (typically ModSecurity + CRS) and the upstream application.
 *
 * -------------------------------------------------------------------------
 * Lifecycle (why ModSecurity can still inspect the body afterwards)
 * -------------------------------------------------------------------------
 *
 * 1. Client sends request with a JSON body.
 * 2. This module runs in the PREACCESS phase so it can validate before
 *    ModSecurity's typical preaccess body processing when effective phase
 *    ordering places json_guard ahead of modsecurity.
 * 3. It calls ngx_http_read_client_request_body(), which is NGINX's normal
 *    body-reading path: small bodies stay in memory buffers; large bodies
 *    are spooled to client_body_temp files according to
 *    client_body_buffer_size / client_body_in_file_only.
 * 4. The post-body handler walks r->request_body buffers (and temp file
 *    if present) in bounded chunks, feeding the standalone streaming
 *    parser. The module never builds a DOM and never replaces the body.
 * 5. On success the module returns NGX_DECLINED so the request continues
 *    through remaining phases. r->request_body remains populated, so
 *    ModSecurity (or any other module that reads the client body) can
 *    still perform full inspection — including CRS rules — on the same
 *    buffered/spooled body.
 * 6. On structural failure the module finalizes with 400 (malformed) or
 *    413 (configured limit), so abusive JSON never reaches ModSecurity
 *    or the upstream.
 *
 * This module is NOT a WAF and does NOT replace ModSecurity.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "json_guard_parser.h"
#include "json_guard_limits.h"

/* Read temp-file bodies in this chunk size (bounded, not whole file). */
#define NGX_JSON_GUARD_FILE_CHUNK  65536

typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  allow_top_level_scalar;
    ngx_flag_t  reject_duplicate_keys;
    ngx_uint_t  methods;

    ngx_uint_t  max_depth;
    ngx_uint_t  max_key_length;
    ngx_uint_t  max_string_length;
    ngx_uint_t  max_number_length;
    ngx_uint_t  max_total_tokens;
    ngx_uint_t  max_object_members;
    ngx_uint_t  max_array_elements;
} ngx_http_json_guard_loc_conf_t;

typedef struct {
    ngx_int_t      status;   /* 0 = OK/continue, else HTTP status */
    uint64_t       inspection_us;
    unsigned       done:1;
    unsigned       waiting:1;
    jg_parser_t    parser;
} ngx_http_json_guard_ctx_t;

extern ngx_module_t ngx_http_json_guard_module;

static ngx_int_t ngx_http_json_guard_handler(ngx_http_request_t *r);
static void ngx_http_json_guard_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_json_guard_process_body(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx);
static ngx_int_t ngx_http_json_guard_feed_chain(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx, ngx_chain_t *cl);
static ngx_int_t ngx_http_json_guard_feed_file(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx, ngx_temp_file_t *tf);
static int ngx_http_json_guard_body_is_empty(ngx_http_request_t *r);
static ngx_int_t ngx_http_json_guard_content_type_ok(ngx_http_request_t *r);
static ngx_int_t ngx_http_json_guard_result_to_status(jg_result_t res);
static void ngx_http_json_guard_limits_from_conf(jg_limits_t *lim,
    ngx_http_json_guard_loc_conf_t *conf);

static void *ngx_http_json_guard_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_json_guard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_json_guard_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_json_guard_inspection_us_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_json_guard_init(ngx_conf_t *cf);
static uint64_t ngx_http_json_guard_now_us(void);

static ngx_http_variable_t ngx_http_json_guard_variables[] = {

    { ngx_string("json_guard_inspection_us"), NULL,
      ngx_http_json_guard_inspection_us_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_conf_bitmask_t  ngx_http_json_guard_methods_mask[] = {
    { ngx_string("GET"),      NGX_HTTP_GET },
    { ngx_string("HEAD"),     NGX_HTTP_HEAD },
    { ngx_string("POST"),     NGX_HTTP_POST },
    { ngx_string("PUT"),      NGX_HTTP_PUT },
    { ngx_string("DELETE"),   NGX_HTTP_DELETE },
    { ngx_string("MKCOL"),    NGX_HTTP_MKCOL },
    { ngx_string("COPY"),     NGX_HTTP_COPY },
    { ngx_string("MOVE"),     NGX_HTTP_MOVE },
    { ngx_string("OPTIONS"),  NGX_HTTP_OPTIONS },
    { ngx_string("PROPFIND"), NGX_HTTP_PROPFIND },
    { ngx_string("PROPPATCH"),NGX_HTTP_PROPPATCH },
    { ngx_string("LOCK"),     NGX_HTTP_LOCK },
    { ngx_string("UNLOCK"),   NGX_HTTP_UNLOCK },
    { ngx_string("PATCH"),    NGX_HTTP_PATCH },
    { ngx_string("TRACE"),    NGX_HTTP_TRACE },
    { ngx_null_string, 0 }
};


static uint64_t
ngx_http_json_guard_now_us(void)
{
    struct timeval  tv;

    ngx_gettimeofday(&tv);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}


/* Client-caused rejects (400/413) log at INFO so bad traffic can't flood the error log. */
static ngx_uint_t
ngx_http_json_guard_reject_log_level(ngx_int_t rc)
{
    if (rc == NGX_HTTP_BAD_REQUEST
        || rc == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE)
    {
        return NGX_LOG_INFO;
    }

    return NGX_LOG_ERR;
}


static void
ngx_http_json_guard_log_reject(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx, ngx_int_t rc)
{
    ngx_log_error(ngx_http_json_guard_reject_log_level(rc),
                  r->connection->log, 0,
                  "json_guard: REJECT status=%i err=%s",
                  rc, jg_error_string(jg_parser_error(&ctx->parser)));
}

static ngx_command_t ngx_http_json_guard_commands[] = {

    { ngx_string("json_guard"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, enable),
      NULL },

    { ngx_string("json_guard_max_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_depth),
      NULL },

    { ngx_string("json_guard_max_key_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_key_length),
      NULL },

    { ngx_string("json_guard_max_string_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_string_length),
      NULL },

    { ngx_string("json_guard_max_number_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_number_length),
      NULL },

    { ngx_string("json_guard_max_total_tokens"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_total_tokens),
      NULL },

    { ngx_string("json_guard_max_object_members"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_object_members),
      NULL },

    { ngx_string("json_guard_max_array_elements"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, max_array_elements),
      NULL },

    { ngx_string("json_guard_allow_top_level_scalar"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, allow_top_level_scalar),
      NULL },

    { ngx_string("json_guard_reject_duplicate_keys"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, reject_duplicate_keys),
      NULL },

    { ngx_string("json_guard_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_guard_loc_conf_t, methods),
      &ngx_http_json_guard_methods_mask },

    ngx_null_command
};

static ngx_http_module_t ngx_http_json_guard_module_ctx = {
    ngx_http_json_guard_add_variables,  /* preconfiguration */
    ngx_http_json_guard_init,           /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_json_guard_create_loc_conf,/* create location configuration */
    ngx_http_json_guard_merge_loc_conf  /* merge location configuration */
};


static ngx_int_t
ngx_http_json_guard_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_json_guard_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_json_guard_inspection_us_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_json_guard_ctx_t  *ctx;
    u_char                     *p;

    (void) data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_json_guard_module);
    if (ctx == NULL || !ctx->done) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    v->len = ngx_sprintf(p, "%uL", ctx->inspection_us) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

ngx_module_t ngx_http_json_guard_module = {
    NGX_MODULE_V1,
    &ngx_http_json_guard_module_ctx,    /* module context */
    ngx_http_json_guard_commands,       /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

static void *
ngx_http_json_guard_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_json_guard_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_json_guard_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * NGX_CONF_UNSET means "inherit / use default at merge".
     * Numeric slots use NGX_CONF_UNSET_UINT.
     */
    conf->enable                 = NGX_CONF_UNSET;
    conf->allow_top_level_scalar = NGX_CONF_UNSET;
    conf->reject_duplicate_keys  = NGX_CONF_UNSET;
    /* methods: 0 means unset; merged to POST|PUT|PATCH. */
    conf->max_depth              = NGX_CONF_UNSET_UINT;
    conf->max_key_length         = NGX_CONF_UNSET_UINT;
    conf->max_string_length      = NGX_CONF_UNSET_UINT;
    conf->max_number_length      = NGX_CONF_UNSET_UINT;
    conf->max_total_tokens       = NGX_CONF_UNSET_UINT;
    conf->max_object_members     = NGX_CONF_UNSET_UINT;
    conf->max_array_elements     = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_json_guard_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_json_guard_loc_conf_t *prev = parent;
    ngx_http_json_guard_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->allow_top_level_scalar,
                         prev->allow_top_level_scalar,
                         JG_DEFAULT_ALLOW_TOP_LEVEL_SCALAR);
    ngx_conf_merge_value(conf->reject_duplicate_keys,
                         prev->reject_duplicate_keys,
                         JG_DEFAULT_REJECT_DUPLICATE_KEYS);

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_POST
                                  |NGX_HTTP_PUT
                                  |NGX_HTTP_PATCH));

    ngx_conf_merge_uint_value(conf->max_depth, prev->max_depth,
                              JG_DEFAULT_MAX_DEPTH);
    ngx_conf_merge_uint_value(conf->max_key_length, prev->max_key_length,
                              JG_DEFAULT_MAX_KEY_LENGTH);
    ngx_conf_merge_uint_value(conf->max_string_length, prev->max_string_length,
                              JG_DEFAULT_MAX_STRING_LENGTH);
    ngx_conf_merge_uint_value(conf->max_number_length, prev->max_number_length,
                              JG_DEFAULT_MAX_NUMBER_LENGTH);
    ngx_conf_merge_uint_value(conf->max_total_tokens, prev->max_total_tokens,
                              JG_DEFAULT_MAX_TOTAL_TOKENS);
    ngx_conf_merge_uint_value(conf->max_object_members, prev->max_object_members,
                              JG_DEFAULT_MAX_OBJECT_MEMBERS);
    ngx_conf_merge_uint_value(conf->max_array_elements, prev->max_array_elements,
                              JG_DEFAULT_MAX_ARRAY_ELEMENTS);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_json_guard_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /*
     * PREACCESS phase: after rewrite, typically before/with ModSecurity's
     * preaccess body handler. Effective ordering depends on NGINX phase-handler
     * registration and dynamic-module ordering; verify it in integration tests.
     *
     * Body is read via the standard NGINX API so later modules still see it.
     */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_json_guard_handler;

    return NGX_OK;
}


/* ------------------------------------------------------------------------- */
/* Content-Type matching                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Match application/json and application/xxx+json, including parameters
 * such as "; charset=utf-8". Case-insensitive on type/subtype.
 */
static ngx_int_t
ngx_http_json_guard_content_type_ok(ngx_http_request_t *r)
{
    u_char  *p, *end, *semi;
    size_t   len;
    u_char   low[256];
    size_t   i, n;

    if (r->headers_in.content_type == NULL) {
        return 0;
    }

    p   = r->headers_in.content_type->value.data;
    len = r->headers_in.content_type->value.len;
    if (p == NULL || len == 0) {
        return 0;
    }

    end  = p + len;
    semi = ngx_strlchr(p, end, ';');
    if (semi != NULL) {
        len = (size_t)(semi - p);
    }

    /* trim trailing spaces */
    while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
        len--;
    }
    /* trim leading spaces */
    while (len > 0 && (*p == ' ' || *p == '\t')) {
        p++;
        len--;
    }

    if (len == 0 || len >= sizeof(low)) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        low[i] = ngx_tolower(p[i]);
    }
    low[len] = '\0';

    if (len == sizeof("application/json") - 1
        && ngx_strncmp(low, "application/json", len) == 0)
    {
        return 1;
    }

    /* application/xxx+json (suffix +json) */
    if (len >= sizeof("application/") - 1 + 1 + sizeof("+json") - 1
        && ngx_strncmp(low, "application/", sizeof("application/") - 1) == 0)
    {
        n = sizeof("+json") - 1;
        if (len >= n && ngx_strncmp(low + len - n, "+json", n) == 0) {
            return 1;
        }
    }

    return 0;
}


static void
ngx_http_json_guard_limits_from_conf(jg_limits_t *lim,
    ngx_http_json_guard_loc_conf_t *conf)
{
    jg_limits_set_defaults(lim);

    lim->max_depth              = (size_t) conf->max_depth;
    lim->max_key_length         = (size_t) conf->max_key_length;
    lim->max_string_length      = (size_t) conf->max_string_length;
    lim->max_number_length      = (size_t) conf->max_number_length;
    lim->max_total_tokens       = (size_t) conf->max_total_tokens;
    lim->max_object_members     = (size_t) conf->max_object_members;
    lim->max_array_elements     = (size_t) conf->max_array_elements;
    lim->allow_top_level_scalar = conf->allow_top_level_scalar ? 1 : 0;
    lim->reject_duplicate_keys  = conf->reject_duplicate_keys ? 1 : 0;
}


static ngx_int_t
ngx_http_json_guard_result_to_status(jg_result_t res)
{
    switch (res) {
    case JG_REJECT_MALFORMED:
        return NGX_HTTP_BAD_REQUEST;           /* 400 */
    case JG_REJECT_LIMIT:
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE; /* 413 */
    case JG_REJECT_DUP_TABLE:
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE; /* 413; distinct parser result */
    case JG_INTERNAL_ERROR:
    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR; /* 500 */
    }
}


/* ------------------------------------------------------------------------- */
/* Body feeding                                                              */
/* ------------------------------------------------------------------------- */

static ngx_int_t
ngx_http_json_guard_feed_chain(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx, ngx_chain_t *cl)
{
    jg_result_t   res;
    ngx_buf_t    *b;
    ngx_file_t    file;
    size_t        len;
    u_char       *chunk;
    off_t         offset, remaining;
    ssize_t       n;
    ngx_uint_t    fed_memory;

    chunk = NULL;

    for (; cl; cl = cl->next) {
        fed_memory = 0;

        b = cl->buf;
        if (b == NULL) {
            continue;
        }

        if (ngx_buf_in_memory(b)) {
            if (b->pos == NULL || b->last == NULL || b->last < b->pos) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "json_guard: invalid in-memory body buffer");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (b->last > b->pos) {
                len = (size_t)(b->last - b->pos);
                res = jg_parser_feed(&ctx->parser, b->pos, len);
                if (res != JG_OK && res != JG_NEED_MORE) {
                    return ngx_http_json_guard_result_to_status(res);
                }
                fed_memory = 1;
            }
        }

        /*
         * A buf can carry the same bytes in memory and in the temp file.
         * If its memory bytes were fed, skip the file range so the body
         * is not parsed twice. Empty in-memory bufs still walk the file.
         */
        if (b->in_file && !fed_memory) {
            /*
             * File-backed buffer: read the referenced range in bounded
             * chunks so we never map the whole body into module memory.
             */
            if (b->file == NULL || b->file->fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "json_guard: invalid in-file body buffer");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (b->file_last < b->file_pos) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "json_guard: invalid in-file body range");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (b->file_last == b->file_pos) {
                continue;
            }

            if (chunk == NULL) {
                chunk = ngx_palloc(r->pool, NGX_JSON_GUARD_FILE_CHUNK);
                if (chunk == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            offset = b->file_pos;
            remaining = b->file_last - b->file_pos;
            while (remaining > 0) {
                size_t to_read = NGX_JSON_GUARD_FILE_CHUNK;
                if ((off_t) to_read > remaining) {
                    to_read = (size_t) remaining;
                }
                /*
                 * ngx_read_file() advances file->offset. Copy so we do
                 * not mutate NGINX's shared ngx_file_t.
                 */
                file = *b->file;
                n = ngx_read_file(&file, chunk, to_read, offset);
                if (n == NGX_ERROR || n == 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "json_guard: failed reading in-file body buf");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                res = jg_parser_feed(&ctx->parser, chunk, (size_t) n);
                if (res != JG_OK && res != JG_NEED_MORE) {
                    return ngx_http_json_guard_result_to_status(res);
                }
                offset += n;
                remaining -= n;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_json_guard_feed_file(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx, ngx_temp_file_t *tf)
{
    u_char       *buf;
    ssize_t       n;
    off_t         offset, remaining;
    size_t        to_read;
    jg_result_t   res;
    ngx_int_t     rc;
    ngx_file_t    file;

    if (tf == NULL) {
        return NGX_OK;
    }

    /*
     * ngx_read_file() mutates file->offset (and sys_offset without pread).
     * Read through a local copy so NGINX's temp_file->file stays intact
     * for later body consumers.
     */
    file = tf->file;
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "json_guard: invalid temp file fd");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    remaining = tf->offset;
    if (remaining < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "json_guard: invalid temp file length");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (remaining == 0) {
        return NGX_OK;
    }

    buf = ngx_palloc(r->pool, NGX_JSON_GUARD_FILE_CHUNK);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Sequential read of the spooled body. This is a blocking read on a
     * local temp file (not the client socket). For typical deployments
     * this is acceptable; a fully event-driven file read is a future TODO.
     */
    offset = 0;
    while (remaining > 0) {
        to_read = NGX_JSON_GUARD_FILE_CHUNK;
        if ((off_t) to_read > remaining) {
            to_read = (size_t) remaining;
        }

        n = ngx_read_file(&file, buf, to_read, offset);
        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "json_guard: ngx_read_file() failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "json_guard: unexpected EOF in temp body file");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        res = jg_parser_feed(&ctx->parser, buf, (size_t) n);
        if (res != JG_OK && res != JG_NEED_MORE) {
            rc = ngx_http_json_guard_result_to_status(res);
            ngx_log_error(ngx_http_json_guard_reject_log_level(rc),
                          r->connection->log, 0,
                          "json_guard: reject while reading body file: %s",
                          jg_error_string(jg_parser_error(&ctx->parser)));
            return rc;
        }

        offset += n;
        remaining -= n;
    }

    return NGX_OK;
}


static int
ngx_http_json_guard_body_is_empty(ngx_http_request_t *r)
{
    ngx_http_request_body_t  *rb;
    ngx_chain_t              *cl;
    ngx_buf_t                *b;

    if (r->headers_in.content_length_n == 0) {
        return 1;
    }

    rb = r->request_body;
    if (rb == NULL) {
        return 1;
    }

    if (rb->temp_file && rb->temp_file->offset > 0) {
        return 0;
    }

    if (rb->bufs == NULL) {
        return 1;
    }

    for (cl = rb->bufs; cl; cl = cl->next) {
        b = cl->buf;
        if (b == NULL) {
            continue;
        }

        if (ngx_buf_in_memory(b) && b->pos != NULL && b->last > b->pos) {
            return 0;
        }

        if (b->in_file && b->file_last > b->file_pos) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_http_json_guard_process_body(ngx_http_request_t *r,
    ngx_http_json_guard_ctx_t *ctx)
{
    ngx_http_request_body_t  *rb;
    jg_result_t               res;
    ngx_int_t                 rc;

    if (ngx_http_json_guard_body_is_empty(r)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "json_guard: ACCEPT empty body");
        return NGX_OK;
    }

    rb = r->request_body;

    /*
     * Prefer walking the buf chain (memory and/or in-file ranges). When
     * the body was spooled and bufs are empty, fall back to the temp file.
     * Never double-feed both full temp_file and bufs.
     */
    if (rb->bufs) {
        rc = ngx_http_json_guard_feed_chain(r, ctx, rb->bufs);
        if (rc != NGX_OK) {
            ngx_http_json_guard_log_reject(r, ctx, rc);
            return rc;
        }
    } else if (rb->temp_file && rb->temp_file->file.fd != NGX_INVALID_FILE) {
        rc = ngx_http_json_guard_feed_file(r, ctx, rb->temp_file);
        if (rc != NGX_OK) {
            /* feed_file already logs some paths; ensure REJECT tag exists */
            ngx_http_json_guard_log_reject(r, ctx, rc);
            return rc;
        }
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "json_guard: missing body buffers after non-empty check");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    res = jg_parser_finish(&ctx->parser);
    if (res != JG_OK) {
        rc = ngx_http_json_guard_result_to_status(res);
        ngx_http_json_guard_log_reject(r, ctx, rc);
        return rc;
    }

    /* INFO is available for integration diagnostics without production noise. */
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "json_guard: ACCEPT structurally OK");
    return NGX_OK;
}


/* ------------------------------------------------------------------------- */
/* Handlers                                                                  */
/* ------------------------------------------------------------------------- */

static void
ngx_http_json_guard_post_handler(ngx_http_request_t *r)
{
    ngx_http_json_guard_ctx_t *ctx;
    ngx_int_t                  rc;
    uint64_t                   started, finished;

    /* Balance the reference taken by ngx_http_read_client_request_body(). */
    r->main->count--;

    ctx = ngx_http_get_module_ctx(r, ngx_http_json_guard_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    started = ngx_http_json_guard_now_us();
    rc = ngx_http_json_guard_process_body(r, ctx);
    finished = ngx_http_json_guard_now_us();
    ctx->inspection_us = finished >= started ? finished - started : 0;
    ctx->done = 1;
    ctx->status = rc;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "json_guard: INSPECT status=%i inspection_us=%uL",
                  rc, ctx->inspection_us);

    if (rc != NGX_OK) {
        /*
         * Reject before upstream / further body consumers for this request.
         * Note: if ModSecurity already ran earlier in the phase chain it may
         * have seen the body; load order should place json_guard first when
         * early reject is desired. See README.
         */
        if (ctx->waiting) {
            ctx->waiting = 0;
            ngx_http_finalize_request(r, rc);
        }
        return;
    }

    /*
     * Body validated. If we suspended the phase handler (async body read),
     * resume the phase engine. If body was already available, the access
     * handler will observe ctx->done and return NGX_DECLINED.
     */
    if (ctx->waiting) {
        ctx->waiting = 0;
        ngx_http_core_run_phases(r);
        return;
    }

    /* Synchronous body path: access handler still on stack. */
}


static ngx_int_t
ngx_http_json_guard_handler(ngx_http_request_t *r)
{
    ngx_http_json_guard_loc_conf_t *conf;
    ngx_http_json_guard_ctx_t      *ctx;
    jg_limits_t                     lim;
    ngx_int_t                       rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_json_guard_module);
    if (conf == NULL || !conf->enable) {
        return NGX_DECLINED;
    }

    /* Subrequests: skip unless we explicitly support them later. */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    if (!ngx_http_json_guard_content_type_ok(r)) {
        return NGX_DECLINED;
    }

    /* Default: POST PUT PATCH. GET/HEAD/DELETE/OPTIONS skip the guard. */
    if (!(r->method & (conf->methods & ~(ngx_uint_t) NGX_CONF_BITMASK_SET))) {
        return NGX_DECLINED;
    }

    /* No body / Content-Length: 0 is not a JSON document; pass through. */
    if (r->headers_in.content_length_n == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_json_guard_module);
    if (ctx != NULL) {
        if (ctx->done) {
            if (ctx->status != NGX_OK) {
                return ctx->status;
            }
            return NGX_DECLINED;
        }
        /* Still waiting for body */
        return NGX_DONE;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_json_guard_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_json_guard_limits_from_conf(&lim, conf);
    jg_parser_init(&ctx->parser, &lim);
    if (lim.reject_duplicate_keys) {
        jg_dup_key_slot_t *table;

        table = ngx_pcalloc(r->pool,
                            sizeof(jg_dup_key_slot_t) * JG_DUP_KEY_TABLE_SIZE);
        if (table == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        jg_parser_set_dup_key_table(&ctx->parser, table);
    }
    ctx->status = NGX_OK;
    ngx_http_set_ctx(r, ctx, ngx_http_json_guard_module);

    /*
     * Standard body read. Does not discard the body: after this call
     * r->request_body holds buffers/temp file for all subsequent modules.
     */
    rc = ngx_http_read_client_request_body(r, ngx_http_json_guard_post_handler);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (ctx->done) {
        /* post_handler ran synchronously */
        if (ctx->status != NGX_OK) {
            return ctx->status;
        }
        return NGX_DECLINED;
    }

    /* Body not fully available yet; post_handler will resume phases. */
    ctx->waiting = 1;
    return NGX_DONE;
}
