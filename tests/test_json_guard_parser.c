/*
 * Standalone unit tests for the streaming JSON guard parser.
 *
 * Build:
 *   cc -Wall -Wextra -Werror -O2 -I./src \
 *      tests/test_json_guard_parser.c src/json_guard_parser.c \
 *      -o tests/test_json_guard_parser
 *   ./tests/test_json_guard_parser
 */

#include "json_guard_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed;
static int g_passed;

/* Directory containing tests/payloads relative to CWD (repo root). */
#ifndef JG_PAYLOAD_DIR
#define JG_PAYLOAD_DIR "tests/payloads"
#endif

static unsigned char *
load_file(const char *path, size_t *out_len)
{
    FILE *fp;
    unsigned char *buf;
    long sz;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = (unsigned char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(fp);
    *out_len = (size_t)sz;
    return buf;
}

static unsigned char *
load_payload(const char *name, size_t *out_len)
{
    char path[512];
    int n;

    n = snprintf(path, sizeof(path), "%s/%s", JG_PAYLOAD_DIR, name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return NULL;
    }
    return load_file(path, out_len);
}

static void
expect_result(const char *name, jg_result_t got, jg_result_t want,
              jg_error_t err_got, jg_error_t err_want)
{
    if (got == want && (err_want == JG_ERR_NONE || err_got == err_want)) {
        printf("  PASS  %s\n", name);
        g_passed++;
        return;
    }
    printf("  FAIL  %s: result=%d want=%d err=%s (%d) want_err=%s (%d)\n",
           name, (int)got, (int)want,
           jg_error_string(err_got), (int)err_got,
           jg_error_string(err_want), (int)err_want);
    g_failed++;
}

static jg_result_t
parse_all(jg_parser_t *p, const unsigned char *data, size_t len)
{
    jg_result_t r;

    r = jg_parser_feed(p, data, len);
    if (r != JG_OK && r != JG_NEED_MORE) {
        return r;
    }
    return jg_parser_finish(p);
}

static jg_result_t
parse_byte_at_a_time(jg_parser_t *p, const unsigned char *data, size_t len)
{
    size_t i;
    jg_result_t r;

    for (i = 0; i < len; i++) {
        r = jg_parser_feed(p, data + i, 1);
        if (r != JG_OK && r != JG_NEED_MORE) {
            return r;
        }
    }
    return jg_parser_finish(p);
}

static jg_result_t
parse_chunks(jg_parser_t *p, const unsigned char *data, size_t len,
             size_t chunk)
{
    size_t off = 0;
    jg_result_t r;

    if (chunk == 0) {
        chunk = 1;
    }
    while (off < len) {
        size_t n = len - off;
        if (n > chunk) {
            n = chunk;
        }
        r = jg_parser_feed(p, data + off, n);
        if (r != JG_OK && r != JG_NEED_MORE) {
            return r;
        }
        off += n;
    }
    return jg_parser_finish(p);
}

static void
test_valid_small(void)
{
    jg_parser_t p;
    const char *json = "{\"hello\":\"world\",\"n\":42,\"ok\":true,\"z\":null}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("1. valid small object", r, JG_OK, p.error, JG_ERR_NONE);
}

static void
test_valid_top_level_array(void)
{
    jg_parser_t p;
    const char *json = "[1,2,3,{\"k\":\"v\"},true,null,\"x\"]";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("2. valid top-level array", r, JG_OK, p.error, JG_ERR_NONE);
}

static void
test_valid_nested(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":{\"b\":[{\"c\":1},2],\"d\":false}}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("3. valid nested object", r, JG_OK, p.error, JG_ERR_NONE);
}

static void
test_fragmented_bytewise(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":[1,2,{\"b\":\"c\\n\\u0041\"}],\"x\":false}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_byte_at_a_time(&p, (const unsigned char *)json, strlen(json));
    expect_result("4. fragmented one-byte-at-a-time", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_string_split(void)
{
    jg_parser_t p;
    const char *a = "{\"msg\":\"hel";
    const char *b = "lo world\"}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = jg_parser_feed(&p, (const unsigned char *)a, strlen(a));
    if (r != JG_NEED_MORE && r != JG_OK) {
        expect_result("5. string split across chunks", r, JG_OK,
                      p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_feed(&p, (const unsigned char *)b, strlen(b));
    if (r != JG_OK && r != JG_NEED_MORE) {
        expect_result("5. string split across chunks", r, JG_OK,
                      p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_finish(&p);
    expect_result("5. string split across chunks", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_escape_split(void)
{
    jg_parser_t p;
    /* Split inside \n escape: "\\\n" across chunks as "\\" then "n" */
    const unsigned char c1[] = {'{', '"', 'a', '"', ':', '"', 'x', '\\'};
    const unsigned char c2[] = {'n', 'y', '"', '}'};
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = jg_parser_feed(&p, c1, sizeof(c1));
    if (r != JG_NEED_MORE && r != JG_OK) {
        expect_result("6. escape sequence split", r, JG_OK, p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_feed(&p, c2, sizeof(c2));
    if (r != JG_OK && r != JG_NEED_MORE) {
        expect_result("6. escape sequence split", r, JG_OK, p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_finish(&p);
    expect_result("6. escape sequence split", r, JG_OK, p.error, JG_ERR_NONE);
}

static void
test_unicode_escape_split(void)
{
    jg_parser_t p;
    /* \u0041 split as \u00 | 41 */
    const unsigned char c1[] = {'{', '"', 'a', '"', ':', '"', '\\', 'u', '0', '0'};
    const unsigned char c2[] = {'4', '1', '"', '}'};
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = jg_parser_feed(&p, c1, sizeof(c1));
    if (r != JG_NEED_MORE && r != JG_OK) {
        expect_result("7. unicode escape split", r, JG_OK, p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_feed(&p, c2, sizeof(c2));
    if (r != JG_OK && r != JG_NEED_MORE) {
        expect_result("7. unicode escape split", r, JG_OK, p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_finish(&p);
    expect_result("7. unicode escape split", r, JG_OK, p.error, JG_ERR_NONE);
}

static void
test_trailing_comma(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":1,}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("8. invalid trailing comma", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_UNEXPECTED_TOKEN);

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)"[1,]", 4);
    expect_result("8b. invalid array trailing comma", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_CHAR);
}

static void
test_invalid_escape(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":\"\\q\"}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("9. invalid escape", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_ESCAPE);
}

static void
test_invalid_unicode(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":\"\\u12XG\"}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("10. invalid unicode escape", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_UNICODE_ESCAPE);
}

static void
test_unterminated_string(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":\"hello";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("11. unterminated string", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_UNTERMINATED_STRING);
}

static void
test_invalid_number(void)
{
    jg_parser_t p;
    jg_result_t r;
    jg_limits_t lim;

    jg_limits_set_defaults(&lim);
    lim.allow_top_level_scalar = 1;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)"01", 2);
    expect_result("12. invalid number leading zero", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_TRAILING_GARBAGE);

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)"1.", 2);
    expect_result("12b. invalid number trailing dot", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_NUMBER);

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)"-", 1);
    expect_result("12c. invalid number lone minus", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_NUMBER);

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)"{\"n\":1e}", 8);
    expect_result("12d. invalid number bare exponent", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_NUMBER);
}

static void
test_trailing_garbage(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":1} garbage";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("13. trailing garbage", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_TRAILING_GARBAGE);
}

static void
test_depth_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const char *json = "{\"a\":{\"a\":{\"a\":1}}}";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_depth = 2;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("14. too much nesting", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_DEPTH_LIMIT);
}

static void
test_string_length_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    char buf[64];
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_string_length = 5;

    /* {"s":"123456"} — string length 6 */
    snprintf(buf, sizeof(buf), "{\"s\":\"123456\"}");
    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)buf, strlen(buf));
    expect_result("15. string length limit", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_STRING_LENGTH_LIMIT);
}

static void
test_key_length_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const char *json = "{\"abcdef\":1}";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_key_length = 3;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("16. key length limit", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_KEY_LENGTH_LIMIT);
}

static void
test_number_length_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const char *json = "{\"n\":1234567890}";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_number_length = 5;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("17. number length limit", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_NUMBER_LENGTH_LIMIT);
}

static void
test_token_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const char *json = "[1,2,3,4,5]";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_total_tokens = 3; /* [ + 1 + 2  then fail */

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("18. token limit", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_TOKEN_LIMIT);
}

static void
test_object_member_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const char *within = "{\"a\":1,\"b\":2}";
    const char *over = "{\"a\":1,\"b\":2,\"c\":3}";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_object_members = 2;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)within, strlen(within));
    expect_result("extra: object member limit boundary", r, JG_OK,
                  p.error, JG_ERR_NONE);

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, (const unsigned char *)over, strlen(over));
    expect_result("extra: object member limit exceeded", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_OBJECT_MEMBER_LIMIT);
}

static void
test_array_element_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const char *within = "[1,2]";
    const char *over = "[1,2,3]";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_array_elements = 2;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)within, strlen(within));
    expect_result("extra: array element limit boundary", r, JG_OK,
                  p.error, JG_ERR_NONE);

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, (const unsigned char *)over, strlen(over));
    expect_result("extra: array element limit exceeded", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_ARRAY_ELEMENT_LIMIT);
}

static void
test_unicode_length_units(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    const unsigned char raw[] = {
        '{', '"', 's', '"', ':', '"', 0xF0, 0x9F, 0x98, 0x80, '"', '}'
    };
    const char *escaped = "{\"s\":\"\\uD83D\\uDE00\"}";
    const char *two = "{\"s\":\"\\uD83D\\uDE00x\"}";
    const char *key = "{\"\\uD83D\\uDE00\":1}";
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.max_string_length = 1;
    lim.max_key_length = 1;

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, raw, sizeof(raw));
    expect_result("extra: raw UTF-8 scalar counts once", r, JG_OK,
                  p.error, JG_ERR_NONE);

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, (const unsigned char *)escaped,
                             strlen(escaped));
    expect_result("extra: surrogate pair counts once", r, JG_OK,
                  p.error, JG_ERR_NONE);

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, (const unsigned char *)two, strlen(two));
    expect_result("extra: decoded string scalar limit", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_STRING_LENGTH_LIMIT);

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, (const unsigned char *)key, strlen(key));
    expect_result("extra: surrogate key counts once", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_huge_generated(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    size_t n = 50000;
    size_t i;
    jg_result_t r;
    char *buf;
    size_t cap;
    size_t len = 0;
    int nw;

    /* Build a large but valid array of small objects in memory (~few MB). */
    cap = n * 32 + 16;
    buf = (char *)malloc(cap);
    if (buf == NULL) {
        printf("  FAIL  19. huge valid JSON (malloc)\n");
        g_failed++;
        return;
    }

    buf[len++] = '[';
    for (i = 0; i < n; i++) {
        if (i > 0) {
            buf[len++] = ',';
        }
        nw = snprintf(buf + len, cap - len, "{\"i\":%zu,\"v\":true}", i);
        if (nw < 0 || (size_t)nw >= cap - len) {
            free(buf);
            printf("  FAIL  19. huge valid JSON (snprintf)\n");
            g_failed++;
            return;
        }
        len += (size_t)nw;
    }
    buf[len++] = ']';

    jg_limits_set_defaults(&lim);
    lim.max_total_tokens = 0; /* 0 means no limit? Wait - our code treats 0 as
                                 "no limit" only if we check > 0. Yes. */
    lim.max_array_elements = 0;
    lim.max_object_members = 0;

    jg_parser_init(&p, &lim);
    r = parse_chunks(&p, (const unsigned char *)buf, len, 4096);
    expect_result("19. huge valid JSON (50k objects)", r, JG_OK,
                  p.error, JG_ERR_NONE);

    free(buf);
}

static void
test_malformed_near_end_of_large(void)
{
    jg_parser_t p;
    size_t n = 10000;
    size_t i;
    jg_result_t r;
    char *buf;
    size_t cap;
    size_t len = 0;
    int nw;

    cap = n * 24 + 64;
    buf = (char *)malloc(cap);
    if (buf == NULL) {
        printf("  FAIL  20. malformed near end (malloc)\n");
        g_failed++;
        return;
    }

    buf[len++] = '[';
    for (i = 0; i < n; i++) {
        if (i > 0) {
            buf[len++] = ',';
        }
        nw = snprintf(buf + len, cap - len, "%zu", i);
        if (nw < 0 || (size_t)nw >= cap - len) {
            free(buf);
            printf("  FAIL  20. malformed near end (snprintf)\n");
            g_failed++;
            return;
        }
        len += (size_t)nw;
    }
    /* Trailing comma + garbage near end */
    memcpy(buf + len, ",]", 2);
    len += 2;

    jg_parser_init(&p, NULL);
    r = parse_chunks(&p, (const unsigned char *)buf, len, 1024);
    expect_result("20. malformed near end of large body", r,
                  JG_REJECT_MALFORMED, p.error, JG_ERR_INVALID_CHAR);

    free(buf);
}

static void
test_top_level_scalar_default_off(void)
{
    jg_parser_t p;
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)"42", 2);
    expect_result("extra: top-level scalar rejected by default", r,
                  JG_REJECT_MALFORMED, p.error, JG_ERR_UNEXPECTED_TOKEN);
}

static void
test_top_level_scalar_allowed(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    jg_result_t r;

    jg_limits_set_defaults(&lim);
    lim.allow_top_level_scalar = 1;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)"true", 4);
    expect_result("extra: top-level true allowed", r, JG_OK,
                  p.error, JG_ERR_NONE);

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)"\"hi\"", 4);
    expect_result("extra: top-level string allowed", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_empty_containers(void)
{
    jg_parser_t p;
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)"{}", 2);
    expect_result("extra: empty object", r, JG_OK, p.error, JG_ERR_NONE);

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)"[]", 2);
    expect_result("extra: empty array", r, JG_OK, p.error, JG_ERR_NONE);

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)"{\"a\":[]}", 8);
    expect_result("extra: nested empty array", r, JG_OK, p.error, JG_ERR_NONE);
}

static void
test_utf8_string(void)
{
    jg_parser_t p;
    /* {"c":"é"}  é is C3 A9 */
    const unsigned char json[] = {
        '{', '"', 'c', '"', ':', '"', 0xC3, 0xA9, '"', '}',
    };
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, json, sizeof(json));
    expect_result("extra: valid UTF-8 in string", r, JG_OK, p.error, JG_ERR_NONE);

    /* Split multi-byte across chunks */
    jg_parser_init(&p, NULL);
    r = jg_parser_feed(&p, json, 7); /* up to and including 0xC3 */
    if (r != JG_NEED_MORE && r != JG_OK) {
        expect_result("extra: UTF-8 split across chunks", r, JG_OK,
                      p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_feed(&p, json + 7, sizeof(json) - 7);
    if (r != JG_OK && r != JG_NEED_MORE) {
        expect_result("extra: UTF-8 split across chunks", r, JG_OK,
                      p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_finish(&p);
    expect_result("extra: UTF-8 split across chunks", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_invalid_utf8(void)
{
    jg_parser_t p;
    /* invalid continuation */
    const unsigned char json[] = {
        '{', '"', 'c', '"', ':', '"', 0xC3, 0x28, '"', '}',
    };
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, json, sizeof(json));
    expect_result("extra: invalid UTF-8", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_UTF8);
}

static void
test_whitespace_around(void)
{
    jg_parser_t p;
    const char *json = "  \n\t { \"a\" : 1 }  \r\n";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("extra: surrounding whitespace", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_duplicate_keys_allowed_by_default(void)
{
    jg_parser_t p;
    const char *json = "{\"a\":1,\"a\":2}";
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)json, strlen(json));
    expect_result("extra: duplicate keys accepted by default", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_duplicate_keys_rejected_when_enabled(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    jg_result_t r;
    const char *dup = "{\"a\":1,\"a\":2}";
    const char *escaped_dup = "{\"a\":1,\"\\u0061\":2}";
    const char *nested_same_name = "{\"a\":1,\"b\":{\"a\":2}}";

    jg_limits_set_defaults(&lim);
    lim.reject_duplicate_keys = 1;

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)dup, strlen(dup));
    expect_result("extra: duplicate keys rejected when enabled", r,
                  JG_REJECT_MALFORMED, p.error, JG_ERR_DUPLICATE_KEY);

    jg_parser_init(&p, &lim);
    r = parse_byte_at_a_time(&p, (const unsigned char *)escaped_dup,
                             strlen(escaped_dup));
    expect_result("extra: escaped duplicate key rejected", r,
                  JG_REJECT_MALFORMED, p.error, JG_ERR_DUPLICATE_KEY);

    jg_parser_init(&p, &lim);
    r = parse_all(&p, (const unsigned char *)nested_same_name,
                  strlen(nested_same_name));
    expect_result("extra: same key allowed in nested object", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

static void
test_duplicate_key_table_limit(void)
{
    jg_parser_t p;
    jg_limits_t lim;
    char *buf;
    size_t cap;
    size_t len = 0;
    size_t i;
    int nw;
    jg_result_t r;

    cap = JG_DUP_KEY_TABLE_SIZE * 16 + 32;
    buf = (char *)malloc(cap);
    if (buf == NULL) {
        printf("  FAIL  extra: duplicate-key table limit (malloc)\n");
        g_failed++;
        return;
    }

    buf[len++] = '{';
    for (i = 0; i <= JG_DUP_KEY_TABLE_SIZE; i++) {
        if (i > 0) {
            buf[len++] = ',';
        }
        nw = snprintf(buf + len, cap - len, "\"k%zu\":0", i);
        if (nw < 0 || (size_t)nw >= cap - len) {
            free(buf);
            printf("  FAIL  extra: duplicate-key table limit (snprintf)\n");
            g_failed++;
            return;
        }
        len += (size_t)nw;
    }
    buf[len++] = '}';

    jg_limits_set_defaults(&lim);
    lim.reject_duplicate_keys = 1;
    lim.max_object_members = 0;
    lim.max_total_tokens = 0;

    jg_parser_init(&p, &lim);
    r = parse_chunks(&p, (const unsigned char *)buf, len, 31);
    expect_result("extra: duplicate-key table limit", r, JG_REJECT_LIMIT,
                  p.error, JG_ERR_DUPLICATE_KEY_LIMIT);

    free(buf);
}

static void
test_required_edge_cases(void)
{
    static const struct {
        const char  *name;
        const char  *json;
        jg_result_t  want;
        jg_error_t   want_err;
        int          allow_scalar;
        int          bytewise;
    } cases[] = {
        { "edge: object number leading zero", "{\"a\":01}",
          JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN, 0, 1 },
        { "edge: object lone minus", "{\"a\":-}",
          JG_REJECT_MALFORMED, JG_ERR_INVALID_NUMBER, 0, 1 },
        { "edge: object number trailing dot", "{\"a\":1.}",
          JG_REJECT_MALFORMED, JG_ERR_INVALID_NUMBER, 0, 1 },
        { "edge: object number bare exponent", "{\"a\":1e}",
          JG_REJECT_MALFORMED, JG_ERR_INVALID_NUMBER, 0, 1 },
        { "edge: object number exponent plus only", "{\"a\":1e+}",
          JG_REJECT_MALFORMED, JG_ERR_INVALID_NUMBER, 0, 1 },
        { "edge: true with suffix", "{\"a\":truex}",
          JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN, 0, 1 },
        { "edge: null with suffix", "{\"a\":nullx}",
          JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN, 0, 1 },
        { "edge: array trailing comma", "[\"a\",]",
          JG_REJECT_MALFORMED, JG_ERR_INVALID_CHAR, 0, 1 },
        { "edge: object trailing comma", "{\"a\":1,}",
          JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN, 0, 1 },
        { "edge: concatenated documents", "{}{}",
          JG_REJECT_MALFORMED, JG_ERR_TRAILING_GARBAGE, 0, 1 },
        { "edge: empty body", "",
          JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN, 0, 0 },
        { "edge: top-level number allowed", "42",
          JG_OK, JG_ERR_NONE, 1, 1 },
        { "edge: top-level null allowed", "null",
          JG_OK, JG_ERR_NONE, 1, 1 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        jg_parser_t p;
        jg_limits_t lim;
        jg_result_t r;

        jg_limits_set_defaults(&lim);
        lim.allow_top_level_scalar = cases[i].allow_scalar;

        jg_parser_init(&p, &lim);
        if (cases[i].bytewise) {
            r = parse_byte_at_a_time(&p,
                                     (const unsigned char *)cases[i].json,
                                     strlen(cases[i].json));
        } else {
            r = parse_all(&p, (const unsigned char *)cases[i].json,
                          strlen(cases[i].json));
        }
        expect_result(cases[i].name, r, cases[i].want, p.error,
                      cases[i].want_err);
    }
}

static void
test_control_char_in_string(void)
{
    jg_parser_t p;
    const unsigned char json[] = {
        '{', '"', 'a', '"', ':', '"', 0x01, '"', '}',
    };
    jg_result_t r;

    jg_parser_init(&p, NULL);
    r = parse_byte_at_a_time(&p, json, sizeof(json));
    expect_result("edge: raw control char in string", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_CHAR);
}

static void
test_unicode_surrogates(void)
{
    jg_parser_t p;
    jg_result_t r;
    const char *valid = "{\"a\":\"\\uD800\\uDC00\"}";
    const char *unpaired_high = "{\"a\":\"\\uD800\"}";
    const char *unpaired_low = "{\"a\":\"\\uDC00\"}";
    const unsigned char split1[] = {
        '{', '"', 'a', '"', ':', '"', '\\', 'u', 'D', '8', '0', '0',
        '\\', 'u', 'D'
    };
    const unsigned char split2[] = { 'C', '0', '0', '"', '}' };

    jg_parser_init(&p, NULL);
    r = parse_byte_at_a_time(&p, (const unsigned char *)valid, strlen(valid));
    expect_result("edge: surrogate pair bytewise", r, JG_OK,
                  p.error, JG_ERR_NONE);

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)unpaired_high,
                  strlen(unpaired_high));
    expect_result("edge: unpaired high surrogate", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_UNICODE_ESCAPE);

    jg_parser_init(&p, NULL);
    r = parse_all(&p, (const unsigned char *)unpaired_low,
                  strlen(unpaired_low));
    expect_result("edge: unpaired low surrogate", r, JG_REJECT_MALFORMED,
                  p.error, JG_ERR_INVALID_UNICODE_ESCAPE);

    jg_parser_init(&p, NULL);
    r = jg_parser_feed(&p, split1, sizeof(split1));
    if (r != JG_NEED_MORE && r != JG_OK) {
        expect_result("edge: split surrogate pair", r, JG_OK,
                      p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_feed(&p, split2, sizeof(split2));
    if (r != JG_OK && r != JG_NEED_MORE) {
        expect_result("edge: split surrogate pair", r, JG_OK,
                      p.error, JG_ERR_NONE);
        return;
    }
    r = jg_parser_finish(&p);
    expect_result("edge: split surrogate pair", r, JG_OK,
                  p.error, JG_ERR_NONE);
}

/* ---- Payload file fixtures (tests/payloads/) ---- */

static void
test_payload_file(const char *name, const char *file,
                  jg_result_t want, jg_error_t want_err,
                  const jg_limits_t *lim, int bytewise)
{
    jg_parser_t p;
    unsigned char *data;
    size_t len;
    jg_result_t r;

    data = load_payload(file, &len);
    if (data == NULL) {
        printf("  FAIL  %s: could not load %s/%s\n", name, JG_PAYLOAD_DIR, file);
        g_failed++;
        return;
    }

    jg_parser_init(&p, lim);
    if (bytewise) {
        r = parse_byte_at_a_time(&p, data, len);
    } else {
        r = parse_all(&p, data, len);
    }
    expect_result(name, r, want, p.error, want_err);
    free(data);
}

static void
test_payload_fixtures(void)
{
    jg_limits_t lim;

    test_payload_file("payload: valid_small.json",
                      "valid_small.json", JG_OK, JG_ERR_NONE, NULL, 0);
    test_payload_file("payload: valid_fragmented.json (bytewise)",
                      "valid_fragmented.json", JG_OK, JG_ERR_NONE, NULL, 1);
    test_payload_file("payload: top_level_array.json",
                      "top_level_array.json", JG_OK, JG_ERR_NONE, NULL, 0);
    test_payload_file("payload: invalid_trailing_comma.json",
                      "invalid_trailing_comma.json", JG_REJECT_MALFORMED,
                      JG_ERR_UNEXPECTED_TOKEN, NULL, 0);
    test_payload_file("payload: invalid_escape.json",
                      "invalid_escape.json", JG_REJECT_MALFORMED,
                      JG_ERR_INVALID_ESCAPE, NULL, 0);
    test_payload_file("payload: invalid_unicode.json",
                      "invalid_unicode.json", JG_REJECT_MALFORMED,
                      JG_ERR_INVALID_UNICODE_ESCAPE, NULL, 0);
    test_payload_file("payload: duplicate_keys.json (allowed by default)",
                      "duplicate_keys.json", JG_OK, JG_ERR_NONE, NULL, 0);

    jg_limits_set_defaults(&lim);
    lim.max_depth = 3;
    test_payload_file("payload: too_deep.json (depth=3)",
                      "too_deep.json", JG_REJECT_LIMIT,
                      JG_ERR_DEPTH_LIMIT, &lim, 0);

    jg_limits_set_defaults(&lim);
    lim.max_string_length = 1000; /* fixture has 100000-char string */
    test_payload_file("payload: huge_string.json (limit 1000)",
                      "huge_string.json", JG_REJECT_LIMIT,
                      JG_ERR_STRING_LENGTH_LIMIT, &lim, 0);

    jg_limits_set_defaults(&lim);
    lim.max_string_length = 200000;
    test_payload_file("payload: huge_string.json (allowed)",
                      "huge_string.json", JG_OK, JG_ERR_NONE, &lim, 0);
}

int
main(void)
{
    printf("ngx_json_guard parser unit tests\n");
    printf("================================\n");

    test_valid_small();
    test_valid_top_level_array();
    test_valid_nested();
    test_fragmented_bytewise();
    test_string_split();
    test_escape_split();
    test_unicode_escape_split();
    test_trailing_comma();
    test_invalid_escape();
    test_invalid_unicode();
    test_unterminated_string();
    test_invalid_number();
    test_trailing_garbage();
    test_depth_limit();
    test_string_length_limit();
    test_key_length_limit();
    test_number_length_limit();
    test_token_limit();
    test_object_member_limit();
    test_array_element_limit();
    test_unicode_length_units();
    test_huge_generated();
    test_malformed_near_end_of_large();
    test_top_level_scalar_default_off();
    test_top_level_scalar_allowed();
    test_empty_containers();
    test_utf8_string();
    test_invalid_utf8();
    test_whitespace_around();
    test_duplicate_keys_allowed_by_default();
    test_duplicate_keys_rejected_when_enabled();
    test_duplicate_key_table_limit();
    test_required_edge_cases();
    test_control_char_in_string();
    test_unicode_surrogates();
    test_payload_fixtures();

    printf("================================\n");
    printf("Passed: %d  Failed: %d\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
