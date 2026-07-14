/*
 * json_guard_parser.h — streaming RFC 8259-style JSON structural validator.
 *
 * Does not build a DOM. Does not store full strings. Only counts lengths
 * and tracks container nesting so large bodies can be validated with
 * roughly constant memory relative to body size.
 */

#ifndef JSON_GUARD_PARSER_H
#define JSON_GUARD_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "json_guard_limits.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    JG_OK = 0,
    JG_NEED_MORE,
    JG_REJECT_MALFORMED,
    JG_REJECT_LIMIT,
    JG_INTERNAL_ERROR
} jg_result_t;

typedef enum {
    JG_ERR_NONE = 0,
    JG_ERR_INVALID_CHAR,
    JG_ERR_INVALID_UTF8,
    JG_ERR_INVALID_ESCAPE,
    JG_ERR_INVALID_UNICODE_ESCAPE,
    JG_ERR_UNEXPECTED_TOKEN,
    JG_ERR_UNTERMINATED_STRING,
    JG_ERR_INVALID_NUMBER,
    JG_ERR_TRAILING_GARBAGE,
    JG_ERR_DEPTH_LIMIT,
    JG_ERR_KEY_LENGTH_LIMIT,
    JG_ERR_STRING_LENGTH_LIMIT,
    JG_ERR_NUMBER_LENGTH_LIMIT,
    JG_ERR_TOKEN_LIMIT,
    JG_ERR_OBJECT_MEMBER_LIMIT,
    JG_ERR_ARRAY_ELEMENT_LIMIT,
    JG_ERR_DUPLICATE_KEY,
    JG_ERR_DUPLICATE_KEY_LIMIT
} jg_error_t;

typedef struct {
    size_t max_depth;
    size_t max_key_length;       /* decoded Unicode scalar values */
    size_t max_string_length;    /* decoded Unicode scalar values */
    size_t max_number_length;
    size_t max_total_tokens;
    size_t max_object_members;
    size_t max_array_elements;
    int    allow_top_level_scalar;
    int    reject_duplicate_keys; /* optional; disabled by default */
} jg_limits_t;

/*
 * Parser object is stack-allocatable. Fields are internal; callers must
 * only use the public API below. Layout is exposed so sizeof works.
 */
typedef struct jg_parser_s jg_parser_t;

/* Guaranteed upper bound for static allocation if preferred. */
#define JG_PARSER_SIZE 98304
void jg_limits_set_defaults(jg_limits_t *limits);

void jg_parser_init(jg_parser_t *parser, const jg_limits_t *limits);

/*
 * Feed the next chunk of bytes. Chunks may split anywhere.
 * Returns JG_OK when a complete document is already parsed (more non-ws
 * data would be trailing garbage), JG_NEED_MORE if still incomplete,
 * or a JG_REJECT_* / JG_INTERNAL_ERROR code.
 */
jg_result_t jg_parser_feed(
    jg_parser_t *parser,
    const unsigned char *data,
    size_t len
);

/* Signal end of input after the last feed. */
jg_result_t jg_parser_finish(jg_parser_t *parser);

jg_error_t  jg_parser_error(const jg_parser_t *parser);
const char *jg_error_string(jg_error_t err);

/* Full definition (internal fields — do not touch outside the library). */
struct jg_parser_s {
    jg_limits_t limits;
    int         state;       /* jg_state_t */
    jg_error_t  error;
    jg_result_t result;

    size_t depth;
    size_t tokens;

    struct {
        int    type;
        size_t count;
    } stack[JG_STACK_MAX_DEPTH];

    int    in_key;
    size_t str_len;

    unsigned int unicode_digits;
    unsigned int unicode_value;
    unsigned int unicode_pending_high;

    int    num_sub;
    size_t num_len;

    const char *lit_expect;
    size_t      lit_remain;

    unsigned int utf8_need;
    unsigned int utf8_cp;
    unsigned int utf8_min;

    uint64_t key_hash1;
    uint64_t key_hash2;
    size_t   key_units;

    struct {
        size_t   depth;
        size_t   units;
        uint64_t hash1;
        uint64_t hash2;
        int      occupied;
    } dup_keys[JG_DUP_KEY_TABLE_SIZE];
    size_t dup_key_used;

    int finished;
};

#ifdef __cplusplus
}
#endif

#endif /* JSON_GUARD_PARSER_H */
