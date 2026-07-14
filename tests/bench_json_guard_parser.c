/*
 * Minimal streaming benchmark driver for the standalone parser.
 *
 * Build (also done by scripts/bench_parser.sh):
 *   cc -Wall -Wextra -Werror -O2 -I./src \
 *      tests/bench_json_guard_parser.c src/json_guard_parser.c \
 *      -o tests/bench_json_guard_parser
 */

#include "json_guard_parser.h"

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    FILE *fp;
    jg_parser_t p;
    jg_limits_t lim;
    unsigned char buf[65536];
    size_t n;
    jg_result_t r;
    size_t total = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file.json>\n", argv[0]);
        return 2;
    }

    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 2;
    }

    jg_limits_set_defaults(&lim);
    lim.max_total_tokens = 0;
    lim.max_array_elements = 0;
    lim.max_object_members = 0;
    jg_parser_init(&p, &lim);

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        total += n;
        r = jg_parser_feed(&p, buf, n);
        if (r != JG_OK && r != JG_NEED_MORE) {
            fclose(fp);
            fprintf(stderr, "REJECT mid-stream after %zu bytes: %s\n",
                    total, jg_error_string(p.error));
            return 1;
        }
    }
    fclose(fp);

    r = jg_parser_finish(&p);
    if (r != JG_OK) {
        fprintf(stderr, "REJECT finish after %zu bytes: %s\n",
                total, jg_error_string(p.error));
        return 1;
    }

    printf("OK bytes=%zu\n", total);
    return 0;
}
