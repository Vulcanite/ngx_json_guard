/* Repeat-capable micro benchmark for the standalone json_guard parser.
 * Usage: bench_json_guard_repeat <file.json> <passes>
 * Loads the file into memory, then times repeated full parse passes
 * (64 KiB chunks, parser reset each pass) with CLOCK_MONOTONIC.
 * Pass 0 is an untimed warmup. Prints one line:
 *   passes median_s min_s max_s bytes mib_per_s_median
 */
#include "json_guard_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double
now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int
cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int
main(int argc, char **argv)
{
    FILE *fp;
    unsigned char *data;
    unsigned char chunk[65536];
    long fsize;
    size_t off, n;
    int passes, i, ok;
    double *times, med;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <file.json> <passes>\n", argv[0]);
        return 2;
    }
    passes = atoi(argv[2]);
    if (passes < 3) {
        fprintf(stderr, "passes must be >= 3\n");
        return 2;
    }

    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 2;
    }
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = malloc((size_t)fsize);
    if (data == NULL || fread(data, 1, (size_t)fsize, fp) != (size_t)fsize) {
        fprintf(stderr, "read failed\n");
        return 2;
    }
    fclose(fp);

    times = calloc((size_t)passes, sizeof(double));

    /* warmup pass (untimed) plus timed passes */
    for (i = 0; i <= passes; i++) {
        jg_parser_t p;
        jg_limits_t lim;
        double t0;

        jg_limits_set_defaults(&lim);
        lim.max_total_tokens = 0;
        lim.max_array_elements = 0;
        lim.max_object_members = 0;
        jg_parser_init(&p, &lim);

        t0 = now_s();
        off = 0;
        ok = 1;
        while (off < (size_t)fsize) {
            jg_result_t r;

            n = (size_t)fsize - off;
            if (n > sizeof(chunk)) {
                n = sizeof(chunk);
            }
            memcpy(chunk, data + off, n);
            off += n;
            r = jg_parser_feed(&p, chunk, n);
            if (r != JG_OK && r != JG_NEED_MORE) {
                ok = 0;
                break;
            }
        }
        if (ok && jg_parser_finish(&p) != JG_OK) {
            ok = 0;
        }
        if (!ok) {
            fprintf(stderr, "REJECT: %s\n", jg_error_string(p.error));
            return 1;
        }
        if (i > 0) {
            times[i - 1] = now_s() - t0;
        }
    }

    qsort(times, (size_t)passes, sizeof(double), cmp);
    med = times[passes / 2];
    printf("%d %.6f %.6f %.6f %ld %.1f\n", passes, med, times[0],
           times[passes - 1], fsize, (double)fsize / (1024.0 * 1024.0) / med);
    return 0;
}
