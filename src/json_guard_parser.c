/*
 * json_guard_parser.c — streaming JSON structural validator (RFC 8259-style).
 *
 * Design:
 *   - Finite state machine, no recursion.
 *   - Explicit container stack (object/array).
 *   - Does not store strings/keys; only length counters.
 *   - UTF-8 validated across chunk boundaries inside strings.
 *   - Memory usage is O(depth), not O(body size).
 */

#include "json_guard_parser.h"

#define JG_KEY_HASH1_INIT  1469598103934665603ULL
#define JG_KEY_HASH1_PRIME 1099511628211ULL
#define JG_KEY_HASH2_INIT  0x9E3779B97F4A7C15ULL
#define JG_KEY_HASH2_PRIME 0xC2B2AE3D27D4EB4FULL

/* ------------------------------------------------------------------------- */
/* Internal states                                                           */
/* ------------------------------------------------------------------------- */

typedef enum {
    JG_ST_ROOT_START = 0,
    JG_ST_VALUE,                 /* require a value (after array comma) */
    JG_ST_OBJECT_KEY_OR_END,     /* expect "key" or } (empty only if !must_member) */
    JG_ST_OBJECT_KEY,            /* expect "key" only (after comma) */
    JG_ST_OBJECT_COLON,
    JG_ST_OBJECT_VALUE,
    JG_ST_OBJECT_COMMA_OR_END,
    JG_ST_ARRAY_VALUE_OR_END,    /* expect value or ] */
    JG_ST_ARRAY_COMMA_OR_END,
    JG_ST_STRING,
    JG_ST_STRING_ESCAPE,
    JG_ST_STRING_UNICODE,
    JG_ST_NUMBER,
    JG_ST_LITERAL,
    JG_ST_COMPLETE,
    JG_ST_ERROR
} jg_state_t;

typedef enum {
    JG_CT_OBJECT = 0,
    JG_CT_ARRAY
} jg_container_type_t;

typedef enum {
    JG_NUM_START = 0,       /* just saw '-' */
    JG_NUM_INT_ZERO,        /* integer part is single '0' */
    JG_NUM_INT_DIGITS,      /* integer part started with 1-9 */
    JG_NUM_FRAC_START,      /* just saw '.' */
    JG_NUM_FRAC_DIGITS,
    JG_NUM_EXP_START,       /* just saw e/E */
    JG_NUM_EXP_SIGN,        /* just saw +/- after e/E */
    JG_NUM_EXP_DIGITS
} jg_num_sub_t;

/* jg_parser_t is defined in the header; stack[].type holds jg_container_type_t. */

typedef char jg_parser_size_check[
    (sizeof(jg_parser_t) <= JG_PARSER_SIZE) ? 1 : -1
];
/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

void
jg_limits_set_defaults(jg_limits_t *limits)
{
    if (limits == NULL) {
        return;
    }
    limits->max_depth              = JG_DEFAULT_MAX_DEPTH;
    limits->max_key_length         = JG_DEFAULT_MAX_KEY_LENGTH;
    limits->max_string_length      = JG_DEFAULT_MAX_STRING_LENGTH;
    limits->max_number_length      = JG_DEFAULT_MAX_NUMBER_LENGTH;
    limits->max_total_tokens       = JG_DEFAULT_MAX_TOTAL_TOKENS;
    limits->max_object_members     = JG_DEFAULT_MAX_OBJECT_MEMBERS;
    limits->max_array_elements     = JG_DEFAULT_MAX_ARRAY_ELEMENTS;
    limits->allow_top_level_scalar = JG_DEFAULT_ALLOW_TOP_LEVEL_SCALAR;
    limits->reject_duplicate_keys  = JG_DEFAULT_REJECT_DUPLICATE_KEYS;
}

static jg_result_t
jg_fail(jg_parser_t *p, jg_result_t result, jg_error_t err)
{
    p->state  = JG_ST_ERROR;
    p->result = result;
    p->error  = err;
    return result;
}

static int
jg_is_ws(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int
jg_inc_size(size_t *v, size_t add)
{
    if (add > (size_t)-1 - *v) {
        return 0;
    }
    *v += add;
    return 1;
}

static jg_result_t
jg_count_token(jg_parser_t *p)
{
    if (!jg_inc_size(&p->tokens, 1)) {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_TOKEN_LIMIT);
    }
    if (p->limits.max_total_tokens > 0
        && p->tokens > p->limits.max_total_tokens)
    {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_TOKEN_LIMIT);
    }
    return JG_OK;
}

static jg_result_t
jg_push(jg_parser_t *p, jg_container_type_t type)
{
    size_t max_d;

    if (p->depth >= JG_STACK_MAX_DEPTH) {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_DEPTH_LIMIT);
    }

    max_d = p->limits.max_depth;
    if (max_d == 0 || max_d > JG_STACK_MAX_DEPTH) {
        max_d = JG_STACK_MAX_DEPTH;
    }
    if (p->depth + 1 > max_d) {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_DEPTH_LIMIT);
    }

    p->stack[p->depth].type  = (int)type;
    p->stack[p->depth].count = 0;
    p->depth++;
    return JG_OK;
}

static jg_result_t
jg_pop(jg_parser_t *p)
{
    size_t i;

    if (p->depth == 0) {
        return jg_fail(p, JG_INTERNAL_ERROR, JG_ERR_UNEXPECTED_TOKEN);
    }
    if (p->limits.reject_duplicate_keys && p->dup_keys != NULL) {
        for (i = 0; i < JG_DUP_KEY_TABLE_SIZE; i++) {
            if (p->dup_keys[i].occupied && p->dup_keys[i].depth == p->depth) {
                p->dup_keys[i].occupied = 0;
                if (p->dup_key_used > 0) {
                    p->dup_key_used--;
                }
            }
        }
    }
    p->depth--;
    return JG_OK;
}

/* Transition after a complete scalar or closed container. */
static jg_result_t
jg_after_value(jg_parser_t *p)
{
    if (p->depth == 0) {
        p->state = JG_ST_COMPLETE;
        return JG_OK;
    }

    if (p->stack[p->depth - 1].type == (int)JG_CT_OBJECT) {
        p->state = JG_ST_OBJECT_COMMA_OR_END;
    } else {
        p->state = JG_ST_ARRAY_COMMA_OR_END;
    }
    return JG_OK;
}

static jg_result_t
jg_close_container(jg_parser_t *p)
{
    jg_result_t r;

    r = jg_pop(p);
    if (r != JG_OK) {
        return r;
    }
    return jg_after_value(p);
}

/* ------------------------------------------------------------------------- */
/* UTF-8                                                                     */
/* ------------------------------------------------------------------------- */

static jg_result_t
jg_record_key_codepoint(jg_parser_t *p, unsigned int cp)
{
    if (!p->limits.reject_duplicate_keys || !p->in_key) {
        return JG_OK;
    }
    p->key_hash1 ^= (uint64_t) cp;
    p->key_hash1 *= JG_KEY_HASH1_PRIME;
    p->key_hash2 ^= (uint64_t) cp + 0x9E3779B97F4A7C15ULL
                    + (p->key_hash2 << 6) + (p->key_hash2 >> 2);
    p->key_hash2 *= JG_KEY_HASH2_PRIME;
    if (!jg_inc_size(&p->key_units, 1)) {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_DUPLICATE_KEY_LIMIT);
    }
    return JG_OK;
}

static jg_result_t
jg_check_duplicate_key(jg_parser_t *p)
{
    size_t slot, i, pos;

    if (!p->limits.reject_duplicate_keys) {
        return JG_OK;
    }
    if (p->dup_keys == NULL) {
        return jg_fail(p, JG_INTERNAL_ERROR, JG_ERR_DUPLICATE_KEY_LIMIT);
    }
    if (p->depth == 0) {
        return jg_fail(p, JG_INTERNAL_ERROR, JG_ERR_UNEXPECTED_TOKEN);
    }

    slot = (size_t)(p->key_hash1 ^ (p->key_hash2 >> 32))
           % JG_DUP_KEY_TABLE_SIZE;

    for (i = 0; i < JG_DUP_KEY_TABLE_SIZE; i++) {
        pos = (slot + i) % JG_DUP_KEY_TABLE_SIZE;
        if (!p->dup_keys[pos].occupied) {
            if (p->dup_key_used >= JG_DUP_KEY_TABLE_SIZE) {
                return jg_fail(p, JG_REJECT_DUP_TABLE,
                               JG_ERR_DUPLICATE_KEY_LIMIT);
            }
            p->dup_keys[pos].occupied = 1;
            p->dup_keys[pos].depth = p->depth;
            p->dup_keys[pos].units = p->key_units;
            p->dup_keys[pos].hash1 = p->key_hash1;
            p->dup_keys[pos].hash2 = p->key_hash2;
            p->dup_key_used++;
            return JG_OK;
        }
        if (p->dup_keys[pos].depth == p->depth
            && p->dup_keys[pos].units == p->key_units
            && p->dup_keys[pos].hash1 == p->key_hash1
            && p->dup_keys[pos].hash2 == p->key_hash2)
        {
            return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_DUPLICATE_KEY);
        }
    }

    return jg_fail(p, JG_REJECT_DUP_TABLE, JG_ERR_DUPLICATE_KEY_LIMIT);
}

static jg_result_t
jg_utf8_byte(jg_parser_t *p, unsigned char c)
{
    if (p->utf8_need == 0) {
        if ((c & 0xE0) == 0xC0) {
            if (c < 0xC2) {
                return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_UTF8);
            }
            p->utf8_need = 1;
            p->utf8_cp   = c & 0x1F;
            p->utf8_min  = 0x80;
            return JG_OK;
        }
        if ((c & 0xF0) == 0xE0) {
            p->utf8_need = 2;
            p->utf8_cp   = c & 0x0F;
            p->utf8_min  = 0x800;
            return JG_OK;
        }
        if ((c & 0xF8) == 0xF0) {
            if (c > 0xF4) {
                return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_UTF8);
            }
            p->utf8_need = 3;
            p->utf8_cp   = c & 0x07;
            p->utf8_min  = 0x10000;
            return JG_OK;
        }
        return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_UTF8);
    }

    if ((c & 0xC0) != 0x80) {
        return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_UTF8);
    }

    p->utf8_cp = (p->utf8_cp << 6) | (c & 0x3F);
    p->utf8_need--;

    if (p->utf8_need == 0) {
        /* Overlong / surrogate / out-of-range checks */
        if (p->utf8_cp < p->utf8_min
            || p->utf8_cp > 0x10FFFF
            || (p->utf8_cp >= 0xD800 && p->utf8_cp <= 0xDFFF))
        {
            return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_UTF8);
        }
        if (p->in_key) {
            jg_result_t r = jg_record_key_codepoint(p, p->utf8_cp);
            if (r != JG_OK) {
                return r;
            }
        }
        /* 3-byte lead 0xE0 overlong already covered by utf8_min.
         * 3-byte surrogates: 0xED followed by high continuation. */
        p->utf8_cp  = 0;
        p->utf8_min = 0;
    }
    return JG_OK;
}

static jg_result_t
jg_utf8_check_complete(jg_parser_t *p)
{
    if (p->utf8_need != 0) {
        return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_UTF8);
    }
    return JG_OK;
}

static int
jg_is_high_surrogate(unsigned int v)
{
    return v >= 0xD800 && v <= 0xDBFF;
}

static int
jg_is_low_surrogate(unsigned int v)
{
    return v >= 0xDC00 && v <= 0xDFFF;
}

/* ------------------------------------------------------------------------- */
/* Number / string / literal starts                                          */
/* ------------------------------------------------------------------------- */

static int
jg_number_complete(jg_num_sub_t sub)
{
    switch (sub) {
    case JG_NUM_INT_ZERO:
    case JG_NUM_INT_DIGITS:
    case JG_NUM_FRAC_DIGITS:
    case JG_NUM_EXP_DIGITS:
        return 1;
    default:
        return 0;
    }
}

static jg_result_t
jg_start_string(jg_parser_t *p, int is_key)
{
    p->in_key         = is_key;
    p->str_len        = 0;
    p->utf8_need      = 0;
    p->utf8_cp        = 0;
    p->utf8_min       = 0;
    p->unicode_digits = 0;
    p->unicode_value  = 0;
    p->unicode_pending_high = 0;
    p->key_hash1      = JG_KEY_HASH1_INIT;
    p->key_hash2      = JG_KEY_HASH2_INIT;
    p->key_units      = 0;
    p->state          = (int)JG_ST_STRING;
    return JG_OK;
}

static jg_result_t
jg_start_number(jg_parser_t *p, unsigned char c)
{
    jg_result_t r;

    r = jg_count_token(p);
    if (r != JG_OK) {
        return r;
    }

    p->num_len = 1;
    if (c == '-') {
        p->num_sub = (int)JG_NUM_START;
    } else if (c == '0') {
        p->num_sub = (int)JG_NUM_INT_ZERO;
    } else {
        p->num_sub = (int)JG_NUM_INT_DIGITS;
    }
    p->state = (int)JG_ST_NUMBER;
    return JG_OK;
}

static jg_result_t
jg_start_literal(jg_parser_t *p, unsigned char c)
{
    jg_result_t r;

    r = jg_count_token(p);
    if (r != JG_OK) {
        return r;
    }

    if (c == 't') {
        p->lit_expect = "rue";
        p->lit_remain = 3;
    } else if (c == 'f') {
        p->lit_expect = "alse";
        p->lit_remain = 4;
    } else {
        p->lit_expect = "ull";
        p->lit_remain = 3;
    }
    p->state = (int)JG_ST_LITERAL;
    return JG_OK;
}

static jg_result_t
jg_bump_str_len(jg_parser_t *p)
{
    size_t limit;

    if (!jg_inc_size(&p->str_len, 1)) {
        return jg_fail(p, JG_REJECT_LIMIT,
                       p->in_key ? JG_ERR_KEY_LENGTH_LIMIT
                                 : JG_ERR_STRING_LENGTH_LIMIT);
    }

    limit = p->in_key ? p->limits.max_key_length
                      : p->limits.max_string_length;
    if (limit > 0 && p->str_len > limit) {
        return jg_fail(p, JG_REJECT_LIMIT,
                       p->in_key ? JG_ERR_KEY_LENGTH_LIMIT
                                 : JG_ERR_STRING_LENGTH_LIMIT);
    }
    return JG_OK;
}

static jg_result_t
jg_inc_array_element(jg_parser_t *p)
{
    if (p->depth == 0) {
        return JG_OK;
    }
    if (p->stack[p->depth - 1].type != (int)JG_CT_ARRAY) {
        return JG_OK;
    }
    if (!jg_inc_size(&p->stack[p->depth - 1].count, 1)) {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_ARRAY_ELEMENT_LIMIT);
    }
    if (p->limits.max_array_elements > 0
        && p->stack[p->depth - 1].count > p->limits.max_array_elements)
    {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_ARRAY_ELEMENT_LIMIT);
    }
    return JG_OK;
}

static jg_result_t
jg_inc_object_member(jg_parser_t *p)
{
    if (!jg_inc_size(&p->stack[p->depth - 1].count, 1)) {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_OBJECT_MEMBER_LIMIT);
    }
    if (p->limits.max_object_members > 0
        && p->stack[p->depth - 1].count > p->limits.max_object_members)
    {
        return jg_fail(p, JG_REJECT_LIMIT, JG_ERR_OBJECT_MEMBER_LIMIT);
    }
    return JG_OK;
}

/*
 * Begin a JSON value at character c.
 * count_array: if 1, increment enclosing array element count.
 * top_level:   if 1, enforce allow_top_level_scalar.
 */
static jg_result_t
jg_begin_value(jg_parser_t *p, unsigned char c, int top_level, int count_array)
{
    jg_result_t r;

    if (top_level && !p->limits.allow_top_level_scalar) {
        if (c != '{' && c != '[') {
            return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);
        }
    }

    if (count_array) {
        r = jg_inc_array_element(p);
        if (r != JG_OK) {
            return r;
        }
    }

    if (c == '{') {
        r = jg_count_token(p);
        if (r != JG_OK) {
            return r;
        }
        r = jg_push(p, JG_CT_OBJECT);
        if (r != JG_OK) {
            return r;
        }
        p->state = JG_ST_OBJECT_KEY_OR_END;
        return JG_OK;
    }

    if (c == '[') {
        r = jg_count_token(p);
        if (r != JG_OK) {
            return r;
        }
        r = jg_push(p, JG_CT_ARRAY);
        if (r != JG_OK) {
            return r;
        }
        p->state = JG_ST_ARRAY_VALUE_OR_END;
        return JG_OK;
    }

    if (c == '"') {
        r = jg_count_token(p);
        if (r != JG_OK) {
            return r;
        }
        return jg_start_string(p, 0);
    }

    if (c == '-' || (c >= '0' && c <= '9')) {
        return jg_start_number(p, c);
    }

    if (c == 't' || c == 'f' || c == 'n') {
        return jg_start_literal(p, c);
    }

    return jg_fail(p, JG_REJECT_MALFORMED, JG_ERR_INVALID_CHAR);
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

void
jg_parser_init(jg_parser_t *parser, const jg_limits_t *limits)
{
    if (parser == NULL) {
        return;
    }

    /* Caller zeroed the object (see jg_parser_init contract in the header). */

    if (limits != NULL) {
        parser->limits = *limits;
    } else {
        jg_limits_set_defaults(&parser->limits);
    }

    if (parser->limits.max_depth == 0
        || parser->limits.max_depth > JG_STACK_MAX_DEPTH)
    {
        parser->limits.max_depth = JG_STACK_MAX_DEPTH;
    }

    parser->state  = JG_ST_ROOT_START;
    parser->error  = JG_ERR_NONE;
    parser->result = JG_NEED_MORE;
    parser->dup_keys = NULL;
    parser->dup_key_used = 0;
}

void
jg_parser_set_dup_key_table(jg_parser_t *parser, jg_dup_key_slot_t *table)
{
    if (parser == NULL) {
        return;
    }
    parser->dup_keys = table;
    parser->dup_key_used = 0;
}

jg_error_t
jg_parser_error(const jg_parser_t *parser)
{
    if (parser == NULL) {
        return JG_ERR_NONE;
    }
    return parser->error;
}

const char *
jg_error_string(jg_error_t err)
{
    switch (err) {
    case JG_ERR_NONE:                   return "none";
    case JG_ERR_INVALID_CHAR:           return "invalid character";
    case JG_ERR_INVALID_UTF8:           return "invalid UTF-8";
    case JG_ERR_INVALID_ESCAPE:         return "invalid escape sequence";
    case JG_ERR_INVALID_UNICODE_ESCAPE: return "invalid unicode escape";
    case JG_ERR_UNEXPECTED_TOKEN:       return "unexpected token";
    case JG_ERR_UNTERMINATED_STRING:    return "unterminated string";
    case JG_ERR_INVALID_NUMBER:         return "invalid number";
    case JG_ERR_TRAILING_GARBAGE:       return "trailing garbage";
    case JG_ERR_DEPTH_LIMIT:            return "depth limit exceeded";
    case JG_ERR_KEY_LENGTH_LIMIT:       return "key length limit exceeded";
    case JG_ERR_STRING_LENGTH_LIMIT:    return "string length limit exceeded";
    case JG_ERR_NUMBER_LENGTH_LIMIT:    return "number length limit exceeded";
    case JG_ERR_TOKEN_LIMIT:            return "token limit exceeded";
    case JG_ERR_OBJECT_MEMBER_LIMIT:    return "object member limit exceeded";
    case JG_ERR_ARRAY_ELEMENT_LIMIT:    return "array element limit exceeded";
    case JG_ERR_DUPLICATE_KEY:          return "duplicate object key";
    case JG_ERR_DUPLICATE_KEY_LIMIT:    return "duplicate-key table limit exceeded";
    default:                            return "unknown error";
    }
}

/* ------------------------------------------------------------------------- */
/* Feed                                                                      */
/* ------------------------------------------------------------------------- */

jg_result_t
jg_parser_feed(jg_parser_t *parser, const unsigned char *data, size_t len)
{
    size_t i;
    jg_result_t r;

    if (parser == NULL) {
        return JG_INTERNAL_ERROR;
    }
    if (parser->state == JG_ST_ERROR) {
        return parser->result;
    }
    if (parser->finished) {
        return jg_fail(parser, JG_INTERNAL_ERROR, JG_ERR_UNEXPECTED_TOKEN);
    }
    if (len > 0 && data == NULL) {
        return jg_fail(parser, JG_INTERNAL_ERROR, JG_ERR_UNEXPECTED_TOKEN);
    }

    for (i = 0; i < len; i++) {
        unsigned char c = data[i];

        switch (parser->state) {

        case JG_ST_ROOT_START:
            if (jg_is_ws(c)) {
                break;
            }
            r = jg_begin_value(parser, c, 1, 0);
            if (r != JG_OK) {
                return r;
            }
            break;

        case JG_ST_VALUE:
            /* After array comma: value required (rejects trailing comma). */
            if (jg_is_ws(c)) {
                break;
            }
            r = jg_begin_value(parser, c, 0, 1);
            if (r != JG_OK) {
                return r;
            }
            break;

        case JG_ST_OBJECT_VALUE:
            if (jg_is_ws(c)) {
                break;
            }
            r = jg_begin_value(parser, c, 0, 0);
            if (r != JG_OK) {
                return r;
            }
            break;

        case JG_ST_ARRAY_VALUE_OR_END:
            if (jg_is_ws(c)) {
                break;
            }
            if (c == ']') {
                r = jg_close_container(parser);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            r = jg_begin_value(parser, c, 0, 1);
            if (r != JG_OK) {
                return r;
            }
            break;

        case JG_ST_ARRAY_COMMA_OR_END:
            if (jg_is_ws(c)) {
                break;
            }
            if (c == ']') {
                r = jg_close_container(parser);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            if (c == ',') {
                parser->state = JG_ST_VALUE; /* require next value */
                break;
            }
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

        case JG_ST_OBJECT_KEY_OR_END:
            if (jg_is_ws(c)) {
                break;
            }
            if (c == '}') {
                r = jg_close_container(parser);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            if (c == '"') {
                r = jg_inc_object_member(parser);
                if (r != JG_OK) {
                    return r;
                }
                r = jg_count_token(parser);
                if (r != JG_OK) {
                    return r;
                }
                r = jg_start_string(parser, 1);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

        case JG_ST_OBJECT_KEY:
            /* After comma: key required (rejects trailing comma). */
            if (jg_is_ws(c)) {
                break;
            }
            if (c == '"') {
                r = jg_inc_object_member(parser);
                if (r != JG_OK) {
                    return r;
                }
                r = jg_count_token(parser);
                if (r != JG_OK) {
                    return r;
                }
                r = jg_start_string(parser, 1);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

        case JG_ST_OBJECT_COLON:
            if (jg_is_ws(c)) {
                break;
            }
            if (c == ':') {
                parser->state = JG_ST_OBJECT_VALUE;
                break;
            }
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

        case JG_ST_OBJECT_COMMA_OR_END:
            if (jg_is_ws(c)) {
                break;
            }
            if (c == '}') {
                r = jg_close_container(parser);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            if (c == ',') {
                parser->state = JG_ST_OBJECT_KEY; /* require next key */
                break;
            }
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

        case JG_ST_STRING:
            if (parser->utf8_need > 0) {
                r = jg_utf8_byte(parser, c);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            if (parser->unicode_pending_high != 0) {
                if (c != '\\') {
                    return jg_fail(parser, JG_REJECT_MALFORMED,
                                   JG_ERR_INVALID_UNICODE_ESCAPE);
                }
                parser->state = JG_ST_STRING_ESCAPE;
                break;
            }
            if (c == '"') {
                r = jg_utf8_check_complete(parser);
                if (r != JG_OK) {
                    return r;
                }
                if (parser->in_key) {
                    r = jg_check_duplicate_key(parser);
                    if (r != JG_OK) {
                        return r;
                    }
                    parser->in_key = 0;
                    parser->state  = JG_ST_OBJECT_COLON;
                } else {
                    r = jg_after_value(parser);
                    if (r != JG_OK) {
                        return r;
                    }
                }
                break;
            }
            if (c == '\\') {
                parser->state = JG_ST_STRING_ESCAPE;
                break;
            }
            if (c < 0x20) {
                return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_INVALID_CHAR);
            }
            if (c <= 0x7F) {
                r = jg_record_key_codepoint(parser, (unsigned int)c);
                if (r != JG_OK) {
                    return r;
                }
                r = jg_bump_str_len(parser);
                if (r != JG_OK) {
                    return r;
                }
                break;
            }
            r = jg_utf8_byte(parser, c);
            if (r != JG_OK) {
                return r;
            }
            r = jg_bump_str_len(parser);
            if (r != JG_OK) {
                return r;
            }
            break;

        case JG_ST_STRING_ESCAPE:
            if (parser->unicode_pending_high != 0 && c != 'u') {
                return jg_fail(parser, JG_REJECT_MALFORMED,
                               JG_ERR_INVALID_UNICODE_ESCAPE);
            }
            switch (c) {
            case '"': case '\\': case '/':
            case 'b': case 'f': case 'n': case 'r': case 't':
                switch (c) {
                case 'b':
                    r = jg_record_key_codepoint(parser, '\b');
                    break;
                case 'f':
                    r = jg_record_key_codepoint(parser, '\f');
                    break;
                case 'n':
                    r = jg_record_key_codepoint(parser, '\n');
                    break;
                case 'r':
                    r = jg_record_key_codepoint(parser, '\r');
                    break;
                case 't':
                    r = jg_record_key_codepoint(parser, '\t');
                    break;
                default:
                    r = jg_record_key_codepoint(parser, (unsigned int)c);
                    break;
                }
                if (r != JG_OK) {
                    return r;
                }
                r = jg_bump_str_len(parser);
                if (r != JG_OK) {
                    return r;
                }
                parser->state = JG_ST_STRING;
                break;
            case 'u':
                parser->unicode_digits = 0;
                parser->unicode_value  = 0;
                parser->state = JG_ST_STRING_UNICODE;
                break;
            default:
                return jg_fail(parser, JG_REJECT_MALFORMED,
                               JG_ERR_INVALID_ESCAPE);
            }
            break;

        case JG_ST_STRING_UNICODE: {
            unsigned int v;
            int scalar_complete;

            if (c >= '0' && c <= '9') {
                v = (unsigned int)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                v = (unsigned int)(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                v = (unsigned int)(c - 'A' + 10);
            } else {
                return jg_fail(parser, JG_REJECT_MALFORMED,
                               JG_ERR_INVALID_UNICODE_ESCAPE);
            }
            parser->unicode_value = (parser->unicode_value << 4) | v;
            parser->unicode_digits++;
            if (parser->unicode_digits >= 4) {
                scalar_complete = 0;
                if (parser->unicode_pending_high != 0) {
                    if (!jg_is_low_surrogate(parser->unicode_value)) {
                        return jg_fail(parser, JG_REJECT_MALFORMED,
                                       JG_ERR_INVALID_UNICODE_ESCAPE);
                    }
                    r = jg_record_key_codepoint(parser,
                        0x10000
                        + (((parser->unicode_pending_high - 0xD800) << 10)
                           | (parser->unicode_value - 0xDC00)));
                    if (r != JG_OK) {
                        return r;
                    }
                    parser->unicode_pending_high = 0;
                    scalar_complete = 1;
                } else if (jg_is_high_surrogate(parser->unicode_value)) {
                    parser->unicode_pending_high = parser->unicode_value;
                } else if (jg_is_low_surrogate(parser->unicode_value)) {
                    return jg_fail(parser, JG_REJECT_MALFORMED,
                                   JG_ERR_INVALID_UNICODE_ESCAPE);
                } else {
                    r = jg_record_key_codepoint(parser, parser->unicode_value);
                    if (r != JG_OK) {
                        return r;
                    }
                    scalar_complete = 1;
                }
                if (scalar_complete) {
                    r = jg_bump_str_len(parser);
                    if (r != JG_OK) {
                        return r;
                    }
                }
                parser->unicode_digits = 0;
                parser->unicode_value  = 0;
                parser->state = JG_ST_STRING;
            }
            break;
        }

        case JG_ST_NUMBER: {
            int consumed = 0;

            switch (parser->num_sub) {
            case JG_NUM_START:
                if (c == '0') {
                    parser->num_sub = JG_NUM_INT_ZERO;
                    consumed = 1;
                } else if (c >= '1' && c <= '9') {
                    parser->num_sub = JG_NUM_INT_DIGITS;
                    consumed = 1;
                } else {
                    return jg_fail(parser, JG_REJECT_MALFORMED,
                                   JG_ERR_INVALID_NUMBER);
                }
                break;

            case JG_NUM_INT_ZERO:
                if (c == '.') {
                    parser->num_sub = JG_NUM_FRAC_START;
                    consumed = 1;
                } else if (c == 'e' || c == 'E') {
                    parser->num_sub = JG_NUM_EXP_START;
                    consumed = 1;
                }
                break;

            case JG_NUM_INT_DIGITS:
                if (c >= '0' && c <= '9') {
                    consumed = 1;
                } else if (c == '.') {
                    parser->num_sub = JG_NUM_FRAC_START;
                    consumed = 1;
                } else if (c == 'e' || c == 'E') {
                    parser->num_sub = JG_NUM_EXP_START;
                    consumed = 1;
                }
                break;

            case JG_NUM_FRAC_START:
                if (c >= '0' && c <= '9') {
                    parser->num_sub = JG_NUM_FRAC_DIGITS;
                    consumed = 1;
                } else {
                    return jg_fail(parser, JG_REJECT_MALFORMED,
                                   JG_ERR_INVALID_NUMBER);
                }
                break;

            case JG_NUM_FRAC_DIGITS:
                if (c >= '0' && c <= '9') {
                    consumed = 1;
                } else if (c == 'e' || c == 'E') {
                    parser->num_sub = JG_NUM_EXP_START;
                    consumed = 1;
                }
                break;

            case JG_NUM_EXP_START:
                if (c == '+' || c == '-') {
                    parser->num_sub = JG_NUM_EXP_SIGN;
                    consumed = 1;
                } else if (c >= '0' && c <= '9') {
                    parser->num_sub = JG_NUM_EXP_DIGITS;
                    consumed = 1;
                } else {
                    return jg_fail(parser, JG_REJECT_MALFORMED,
                                   JG_ERR_INVALID_NUMBER);
                }
                break;

            case JG_NUM_EXP_SIGN:
                if (c >= '0' && c <= '9') {
                    parser->num_sub = JG_NUM_EXP_DIGITS;
                    consumed = 1;
                } else {
                    return jg_fail(parser, JG_REJECT_MALFORMED,
                                   JG_ERR_INVALID_NUMBER);
                }
                break;

            case JG_NUM_EXP_DIGITS:
                if (c >= '0' && c <= '9') {
                    consumed = 1;
                }
                break;
            }

            if (consumed) {
                if (!jg_inc_size(&parser->num_len, 1)) {
                    return jg_fail(parser, JG_REJECT_LIMIT,
                                   JG_ERR_NUMBER_LENGTH_LIMIT);
                }
                if (parser->limits.max_number_length > 0
                    && parser->num_len > parser->limits.max_number_length)
                {
                    return jg_fail(parser, JG_REJECT_LIMIT,
                                   JG_ERR_NUMBER_LENGTH_LIMIT);
                }
                break;
            }

            if (!jg_number_complete(parser->num_sub)) {
                return jg_fail(parser, JG_REJECT_MALFORMED,
                               JG_ERR_INVALID_NUMBER);
            }
            r = jg_after_value(parser);
            if (r != JG_OK) {
                return r;
            }
            i--; /* reprocess delimiter in new state */
            break;
        }

        case JG_ST_LITERAL:
            if (parser->lit_remain == 0) {
                return jg_fail(parser, JG_INTERNAL_ERROR,
                               JG_ERR_UNEXPECTED_TOKEN);
            }
            if (c != (unsigned char)parser->lit_expect[0]) {
                return jg_fail(parser, JG_REJECT_MALFORMED,
                               JG_ERR_UNEXPECTED_TOKEN);
            }
            parser->lit_expect++;
            parser->lit_remain--;
            if (parser->lit_remain == 0) {
                r = jg_after_value(parser);
                if (r != JG_OK) {
                    return r;
                }
            }
            break;

        case JG_ST_COMPLETE:
            if (jg_is_ws(c)) {
                break;
            }
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_TRAILING_GARBAGE);

        case JG_ST_ERROR:
            return parser->result;

        default:
            return jg_fail(parser, JG_INTERNAL_ERROR, JG_ERR_UNEXPECTED_TOKEN);
        }
    }

    if (parser->state == JG_ST_ERROR) {
        return parser->result;
    }
    if (parser->state == JG_ST_COMPLETE) {
        parser->result = JG_OK;
        return JG_OK;
    }
    parser->result = JG_NEED_MORE;
    return JG_NEED_MORE;
}

jg_result_t
jg_parser_finish(jg_parser_t *parser)
{
    jg_result_t r;

    if (parser == NULL) {
        return JG_INTERNAL_ERROR;
    }
    if (parser->state == JG_ST_ERROR) {
        return parser->result;
    }
    if (parser->finished) {
        return parser->result;
    }
    parser->finished = 1;

    switch (parser->state) {
    case JG_ST_COMPLETE:
        parser->result = JG_OK;
        return JG_OK;

    case JG_ST_ROOT_START:
        return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

    case JG_ST_NUMBER:
        if (!jg_number_complete(parser->num_sub)) {
            return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_INVALID_NUMBER);
        }
        r = jg_after_value(parser);
        if (r != JG_OK) {
            return r;
        }
        if (parser->state == JG_ST_COMPLETE) {
            parser->result = JG_OK;
            return JG_OK;
        }
        return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

    case JG_ST_STRING:
    case JG_ST_STRING_ESCAPE:
    case JG_ST_STRING_UNICODE:
        if (parser->unicode_pending_high != 0) {
            return jg_fail(parser, JG_REJECT_MALFORMED,
                           JG_ERR_INVALID_UNICODE_ESCAPE);
        }
        return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNTERMINATED_STRING);

    case JG_ST_LITERAL:
        return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);

    default:
        return jg_fail(parser, JG_REJECT_MALFORMED, JG_ERR_UNEXPECTED_TOKEN);
    }
}
