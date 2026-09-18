/*
 * json_guard_limits.h — default structural safety limits for ngx_json_guard.
 *
 * These defaults are intentionally generous for large JSON request bodies
 * while still bounding worst-case nesting and token growth.
 */

#ifndef JSON_GUARD_LIMITS_H
#define JSON_GUARD_LIMITS_H

#include <stddef.h>

/* Default structural limits (also used by the NGINX module). */
#define JG_DEFAULT_MAX_DEPTH            100
#define JG_DEFAULT_MAX_KEY_LENGTH       4096
#define JG_DEFAULT_MAX_STRING_LENGTH    1048576   /* 1 MiB */
#define JG_DEFAULT_MAX_NUMBER_LENGTH    256
#define JG_DEFAULT_MAX_TOTAL_TOKENS     10000000
#define JG_DEFAULT_MAX_OBJECT_MEMBERS   1000000
#define JG_DEFAULT_MAX_ARRAY_ELEMENTS   1000000
#define JG_DEFAULT_ALLOW_TOP_LEVEL_SCALAR 0
#define JG_DEFAULT_REJECT_DUPLICATE_KEYS  0

/* Hard ceiling on container nesting depth for the fixed stack. */
#define JG_STACK_MAX_DEPTH              1024

/*
 * Optional duplicate-key detection uses a caller-provided fingerprint
 * table of JG_DUP_KEY_TABLE_SIZE slots. Enabling the feature plus an
 * object with more unique keys than the table fails closed with
 * JG_REJECT_DUP_TABLE (distinct from JG_REJECT_LIMIT). Raise is not
 * supported; disable the feature or split the object.
 */
#define JG_DUP_KEY_TABLE_SIZE           1024

#endif /* JSON_GUARD_LIMITS_H */
