/*
 * Copyright (C) 2017 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "skinny128-cipher.h"
#include "skinny128-parallel.h"
#include "skinny64-cipher.h"
#include "skinny64-parallel.h"
#include "mantis-cipher.h"
#include "mantis-parallel.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(CLOCK_MONOTONIC) || defined(CLOCK_PROCESS_CPUTIME_ID)
#define POSIX_TIMER 1
#define HAVE_TIMER 1
#endif

static unsigned iters_per_sec = 1;
static unsigned multiplier = 1;

typedef int64_t timestamp_t;

/* Common key data */
static uint8_t const key_data[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
};

/* The get_timestamp() function gets the current time in ns resolution */
#if defined(POSIX_TIMER)
timestamp_t get_timestamp(void)
{
    struct timespec ts;
#if defined(CLOCK_PROCESS_CPUTIME_ID)
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
#else
timestamp_t get_timestamp(void)
{
    return 0;
}
#endif

/* Calibrate the performance framework by figuring out roughly
   how many iterations to run per second for each algorithm.
   We use Skinny-64-192 in ECB mode to calibrate as it is mid-range
   in performance amongst the algorithm types. */
void calibrate(void)
{
    uint8_t block[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    Skinny64Key_t ks;
    unsigned count;
    timestamp_t start;
    timestamp_t end;
    printf("Calibrating ... ");
    fflush(stdout);
    skinny64_set_key(&ks, key_data, 24);
    iters_per_sec = 0;
    start = get_timestamp();
    do {
        iters_per_sec += 1000;
        for (count = 0; count < 1000; ++count)
            skinny64_ecb_encrypt(block, block, &ks);
        end = get_timestamp();
    } while ((end - start) < 1000000000LL);
    printf("done\n");
}

/* Run an operation over and over and determine the number of ops/sec */
#define RUN_OP(result, op) \
    do { \
        timestamp_t start, end; \
        unsigned total = iters_per_sec * multiplier; \
        unsigned count = total; \
        start = get_timestamp(); \
        while (count > 0) { \
            (op); \
            --count; \
        } \
        end = get_timestamp(); \
        (result) = 1000000000.0 * total / (end - start); \
    } while (0)

/* Run an operation over and over and determine the number of MB/sec */
#define RUN_MB(result, op, size, blksize) \
    do { \
        timestamp_t start, end; \
        unsigned total = iters_per_sec * multiplier; \
        unsigned count; \
        if ((size) != (blksize)) \
            total /= (size) / (blksize); \
        count = total; \
        total *= (size); \
        start = get_timestamp(); \
        while (count > 0) { \
            (op); \
            --count; \
        } \
        end = get_timestamp(); \
        (result) = 1000000000.0 * total / ((end - start) * 1024.0 * 1024.0); \
    } while (0)

void report(const char *name, double set_key,
            double enc, double dec, double ctr,
            double penc, double pdec)
{
    if (set_key >= 0) {
        printf("%-25s %12.3f %12.3f %12.3f %12.3f\n",
               name, set_key, enc, dec, ctr);
    } else {
        /* The set key operation is trivial, so no point reporting it */
        printf("%-25s %12s %12.3f %12.3f %12.3f\n",
               name, "", enc, dec, ctr);
    }
    if (penc != 0 || pdec != 0) {
        char new_name[64];
        snprintf(new_name, sizeof(new_name), "%s-Parallel", name);
        printf("%-38s %12.3f %12.3f\n",
               new_name, penc, pdec);
    }
}

void skinny64_perf(const char *name, unsigned key_size)
{
    uint8_t block[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    uint8_t buffer[1024];
    double set_key, enc, dec, ctr, penc, pdec;
    Skinny64Key_t ks;
    Skinny64CTR_t c;
    Skinny64ParallelECB_t e;

    RUN_OP(set_key, skinny64_set_key(&ks, key_data, key_size));
    RUN_MB(enc, skinny64_ecb_encrypt(block, block, &ks), 8, 8);
    RUN_MB(dec, skinny64_ecb_decrypt(block, block, &ks), 8, 8);

    skinny64_ctr_init(&c);
    skinny64_ctr_set_key(&c, key_data, key_size);
    memset(buffer, 0xBA, sizeof(buffer));
    RUN_MB(ctr, skinny64_ctr_encrypt(buffer, buffer, 1024, &c), 1024, 8);
    skinny64_ctr_cleanup(&c);

    skinny64_parallel_ecb_init(&e);
    skinny64_parallel_ecb_set_key(&e, key_data, key_size);
    memset(buffer, 0xBA, sizeof(buffer));
    RUN_MB(penc, skinny64_parallel_ecb_encrypt(buffer, buffer, 1024, &e), 1024, 8);
    RUN_MB(pdec, skinny64_parallel_ecb_decrypt(buffer, buffer, 1024, &e), 1024, 8);
    skinny64_parallel_ecb_cleanup(&e);

    report(name, set_key, enc, dec, ctr, penc, pdec);
}

void skinny128_perf(const char *name, unsigned key_size)
{
    uint8_t block[16] = {9, 8, 7, 6, 5, 4, 3, 2,
                         1, 0, 9, 8, 7, 6, 5, 4};
    uint8_t buffer[1024];
    double set_key, enc, dec, ctr, penc, pdec;
    Skinny128Key_t ks;
    Skinny128CTR_t c;
    Skinny128ParallelECB_t e;

    RUN_OP(set_key, skinny128_set_key(&ks, key_data, key_size));
    RUN_MB(enc, skinny128_ecb_encrypt(block, block, &ks), 16, 16);
    RUN_MB(dec, skinny128_ecb_decrypt(block, block, &ks), 16, 16);

    skinny128_ctr_init(&c);
    skinny128_ctr_set_key(&c, key_data, key_size);
    memset(buffer, 0xBA, sizeof(buffer));
    RUN_MB(ctr, skinny128_ctr_encrypt(buffer, buffer, 1024, &c), 1024, 16);
    skinny128_ctr_cleanup(&c);

    skinny128_parallel_ecb_init(&e);
    skinny128_parallel_ecb_set_key(&e, key_data, key_size);
    memset(buffer, 0xBA, sizeof(buffer));
    RUN_MB(penc, skinny128_parallel_ecb_encrypt(buffer, buffer, 1024, &e), 1024, 8);
    RUN_MB(pdec, skinny128_parallel_ecb_decrypt(buffer, buffer, 1024, &e), 1024, 8);
    skinny128_parallel_ecb_cleanup(&e);

    report(name, set_key, enc, dec, ctr, penc, pdec);
}

void mantis_perf(const char *name, unsigned rounds)
{
    uint8_t block[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    uint8_t buffer[1024];
    uint8_t tweak[1024];
    double enc, dec, ctr, penc, pdec;
    MantisKey_t ks;
    MantisCTR_t c;
    MantisParallelECB_t e;
    unsigned index;

    mantis_set_key(&ks, key_data, 16, rounds, MANTIS_ENCRYPT);
    RUN_MB(enc, mantis_ecb_crypt(block, block, &ks), 8, 8);
    mantis_swap_modes(&ks);
    RUN_MB(dec, mantis_ecb_crypt(block, block, &ks), 8, 8);

    mantis_ctr_init(&c);
    mantis_ctr_set_key(&c, key_data, 16, rounds);
    memset(buffer, 0xBA, sizeof(buffer));
    RUN_MB(ctr, mantis_ctr_encrypt(buffer, buffer, 1024, &c), 1024, 8);
    mantis_ctr_cleanup(&c);

    mantis_parallel_ecb_init(&e);
    mantis_parallel_ecb_set_key
        (&e, key_data, MANTIS_KEY_SIZE, rounds, MANTIS_ENCRYPT);
    memset(buffer, 0xBA, sizeof(buffer));
    for (index = 0; index < sizeof(tweak); ++index)
        tweak[index] = (uint8_t)(index % 251);
    RUN_MB(penc, mantis_parallel_ecb_crypt
                    (buffer, buffer, tweak, 1024, &e), 1024, 8);
    mantis_parallel_ecb_swap_modes(&e);
    RUN_MB(pdec, mantis_parallel_ecb_crypt
                    (buffer, buffer, tweak, 1024, &e), 1024, 8);
    mantis_parallel_ecb_cleanup(&e);

    report(name, -1, enc, dec, ctr, penc, pdec);
}

int main(int argc, char *argv[])
{
#if defined(HAVE_TIMER)
    calibrate();

    printf("\n");
    printf("                       Set Key (ops/s)  ENC (MiB/s)  DEC (MiB/s)  CTR (MiB/s)\n");

    skinny64_perf("Skinny-64-64", 8);
    skinny64_perf("Skinny-64-128", 16);
    skinny64_perf("Skinny-64-192", 24);

    skinny128_perf("Skinny-128-128", 16);
    skinny128_perf("Skinny-128-256", 32);
    skinny128_perf("Skinny-128-384", 48);

    mantis_perf("Mantis5", 5);
    mantis_perf("Mantis6", 6);
    mantis_perf("Mantis7", 7);
    mantis_perf("Mantis8", 8);
#else
    fprintf(stderr, "Do not know how to measure time - performance tests skipped\n");
#endif
    return 0;
}
