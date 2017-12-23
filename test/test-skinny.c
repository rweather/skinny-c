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

typedef struct
{
    const char *name;
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    uint8_t key[48];
    unsigned key_size;

} SkinnyTestVector;

typedef struct
{
    const char *name;
    uint8_t plaintext[8];
    uint8_t ciphertext[8];
    uint8_t key[16];
    uint8_t tweak[8];
    unsigned rounds;

} MantisTestVector;

/* Test vectors from the SKINNY specification paper */
static SkinnyTestVector const testVector64_64 = {
    "Skinny-64-64",
    {0x06, 0x03, 0x4f, 0x95, 0x77, 0x24, 0xd1, 0x9d},
    {0xbb, 0x39, 0xdf, 0xb2, 0x42, 0x9b, 0x8a, 0xc7},
    {0xf5, 0x26, 0x98, 0x26, 0xfc, 0x68, 0x12, 0x38},
    8
};
static SkinnyTestVector const testVector64_128 = {
    "Skinny-64-128",
    {0xcf, 0x16, 0xcf, 0xe8, 0xfd, 0x0f, 0x98, 0xaa},
    {0x6c, 0xed, 0xa1, 0xf4, 0x3d, 0xe9, 0x2b, 0x9e},
    {0x9e, 0xb9, 0x36, 0x40, 0xd0, 0x88, 0xda, 0x63,
     0x76, 0xa3, 0x9d, 0x1c, 0x8b, 0xea, 0x71, 0xe1},
    16
};
static SkinnyTestVector const testVector64_192 = {
    "Skinny-64-192",
    {0x53, 0x0c, 0x61, 0xd3, 0x5e, 0x86, 0x63, 0xc3},
    {0xdd, 0x2c, 0xf1, 0xa8, 0xf3, 0x30, 0x30, 0x3c},
    {0xed, 0x00, 0xc8, 0x5b, 0x12, 0x0d, 0x68, 0x61,
     0x87, 0x53, 0xe2, 0x4b, 0xfd, 0x90, 0x8f, 0x60,
     0xb2, 0xdb, 0xb4, 0x1b, 0x42, 0x2d, 0xfc, 0xd0},
    24
};
static SkinnyTestVector const testVector128_128 = {
    "Skinny-128-128",
    {0xf2, 0x0a, 0xdb, 0x0e, 0xb0, 0x8b, 0x64, 0x8a,
     0x3b, 0x2e, 0xee, 0xd1, 0xf0, 0xad, 0xda, 0x14},
    {0x22, 0xff, 0x30, 0xd4, 0x98, 0xea, 0x62, 0xd7,
     0xe4, 0x5b, 0x47, 0x6e, 0x33, 0x67, 0x5b, 0x74},
    {0x4f, 0x55, 0xcf, 0xb0, 0x52, 0x0c, 0xac, 0x52,
     0xfd, 0x92, 0xc1, 0x5f, 0x37, 0x07, 0x3e, 0x93},
    16
};
static SkinnyTestVector const testVector128_256 = {
    "Skinny-128-256",
    {0x3a, 0x0c, 0x47, 0x76, 0x7a, 0x26, 0xa6, 0x8d,
     0xd3, 0x82, 0xa6, 0x95, 0xe7, 0x02, 0x2e, 0x25},
    {0xb7, 0x31, 0xd9, 0x8a, 0x4b, 0xde, 0x14, 0x7a,
     0x7e, 0xd4, 0xa6, 0xf1, 0x6b, 0x9b, 0x58, 0x7f},
    {0x00, 0x9c, 0xec, 0x81, 0x60, 0x5d, 0x4a, 0xc1,
     0xd2, 0xae, 0x9e, 0x30, 0x85, 0xd7, 0xa1, 0xf3,
     0x1a, 0xc1, 0x23, 0xeb, 0xfc, 0x00, 0xfd, 0xdc,
     0xf0, 0x10, 0x46, 0xce, 0xed, 0xdf, 0xca, 0xb3},
    32
};
static SkinnyTestVector const testVector128_384 = {
    "Skinny-128-384",
    {0xa3, 0x99, 0x4b, 0x66, 0xad, 0x85, 0xa3, 0x45,
     0x9f, 0x44, 0xe9, 0x2b, 0x08, 0xf5, 0x50, 0xcb},
    {0x94, 0xec, 0xf5, 0x89, 0xe2, 0x01, 0x7c, 0x60,
     0x1b, 0x38, 0xc6, 0x34, 0x6a, 0x10, 0xdc, 0xfa},
    {0xdf, 0x88, 0x95, 0x48, 0xcf, 0xc7, 0xea, 0x52,
     0xd2, 0x96, 0x33, 0x93, 0x01, 0x79, 0x74, 0x49,
     0xab, 0x58, 0x8a, 0x34, 0xa4, 0x7f, 0x1a, 0xb2,
     0xdf, 0xe9, 0xc8, 0x29, 0x3f, 0xbe, 0xa9, 0xa5,
     0xab, 0x1a, 0xfa, 0xc2, 0x61, 0x10, 0x12, 0xcd,
     0x8c, 0xef, 0x95, 0x26, 0x18, 0xc3, 0xeb, 0xe8},
    48
};
static MantisTestVector const testMantis5 = {
    "Mantis5",
    {0x3b, 0x5c, 0x77, 0xa4, 0x92, 0x1f, 0x97, 0x18},
    {0xd6, 0x52, 0x20, 0x35, 0xc1, 0xc0, 0xc6, 0xc1},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    5
};
static MantisTestVector const testMantis6 = {
    "Mantis6",
    {0xd6, 0x52, 0x20, 0x35, 0xc1, 0xc0, 0xc6, 0xc1},
    {0x60, 0xe4, 0x34, 0x57, 0x31, 0x19, 0x36, 0xfd},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    6
};
static MantisTestVector const testMantis7 = {
    "Mantis7",
    {0x60, 0xe4, 0x34, 0x57, 0x31, 0x19, 0x36, 0xfd},
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    7
};
static MantisTestVector const testMantis8 = {
    "Mantis8",
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x97, 0x1e, 0xa0, 0x1a, 0x86, 0xb4, 0x10, 0xbb},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    8
};

static int error = 0;

static void skinny64EcbTest(const SkinnyTestVector *test)
{
    Skinny64Key_t ks;
    uint8_t plaintext[SKINNY64_BLOCK_SIZE];
    uint8_t ciphertext[SKINNY64_BLOCK_SIZE];
    int plaintext_ok, ciphertext_ok;

    printf("%s ECB: ", test->name);
    fflush(stdout);

    skinny64_set_key(&ks, test->key, test->key_size);
    skinny64_ecb_encrypt(ciphertext, test->plaintext, &ks);
    skinny64_ecb_decrypt(plaintext, test->ciphertext, &ks);

    plaintext_ok = memcmp(plaintext, test->plaintext, SKINNY64_BLOCK_SIZE) == 0;
    ciphertext_ok = memcmp(ciphertext, test->ciphertext, SKINNY64_BLOCK_SIZE) == 0;

    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

#define CTR_BLOCK_COUNT 256

static void skinny64CtrTest(const SkinnyTestVector *test)
{
    static uint8_t const base_counter[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    Skinny64Key_t ks;
    Skinny64CTR_t ctr;
    uint8_t counter[SKINNY64_BLOCK_SIZE];
    uint8_t plaintext[CTR_BLOCK_COUNT][SKINNY64_BLOCK_SIZE];
    uint8_t ciphertext[CTR_BLOCK_COUNT][SKINNY64_BLOCK_SIZE];
    uint8_t actual[CTR_BLOCK_COUNT][SKINNY64_BLOCK_SIZE];
    unsigned index, carry, posn, inc, size;
    int ok = 1;

    printf("%s CTR: ", test->name);
    fflush(stdout);

    /* Simple implementation of counter mode to cross-check the real one */
    skinny64_set_key(&ks, test->key, test->key_size);
    for (index = 0; index < CTR_BLOCK_COUNT; ++index) {
        carry = index;
        for (posn = SKINNY64_BLOCK_SIZE; posn > 0; ) {
            --posn;
            carry += base_counter[posn];
            counter[posn] = (uint8_t)carry;
            carry >>= 8;
        }
        skinny64_ecb_encrypt(&(ciphertext[index]), counter, &ks);
        for (posn = 0; posn < SKINNY64_BLOCK_SIZE; ++posn) {
            plaintext[index][posn] =
                test->plaintext[(posn + index) % SKINNY64_BLOCK_SIZE];
            ciphertext[index][posn] ^= plaintext[index][posn];
        }
    }

    /* Encrypt the entire plaintext in a single request */
    memset(actual, 0, sizeof(actual));
    skinny64_ctr_init(&ctr);
    skinny64_ctr_set_key(&ctr, test->key, test->key_size);
    skinny64_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    skinny64_ctr_encrypt(actual, plaintext, sizeof(plaintext), &ctr);
    if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Decrypt the ciphertext back to the plaintext, in-place */
    skinny64_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    skinny64_ctr_encrypt(actual, actual, sizeof(ciphertext), &ctr);
    skinny64_ctr_cleanup(&ctr);
    if (memcmp(plaintext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Use various size increments to check data that is not block-aligned */
    for (inc = 1; inc <= (SKINNY64_BLOCK_SIZE * 3); ++inc) {
        memset(actual, 0, sizeof(actual));
        skinny64_ctr_init(&ctr);
        skinny64_ctr_set_key(&ctr, test->key, test->key_size);
        skinny64_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
        for (posn = 0; posn < sizeof(plaintext); posn += inc) {
            size = sizeof(plaintext) - posn;
            if (size > inc)
                size = inc;
            skinny64_ctr_encrypt
                (((uint8_t *)actual) + posn,
                 ((uint8_t *)plaintext) + posn, size, &ctr);
        }
        skinny64_ctr_cleanup(&ctr);
        if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
            ok = 0;
    }

    /* Report the results */
    if (ok) {
        printf("ok\n");
    } else {
        printf("INCORRECT\n");
        error = 1;
    }
}

static void skinny64ParallelEcbTest(const SkinnyTestVector *test)
{
    Skinny64Key_t ks;
    Skinny64ParallelECB_t ctx;
    uint8_t plaintext[SKINNY64_BLOCK_SIZE * 128];
    uint8_t ciphertext[SKINNY64_BLOCK_SIZE * 128];
    uint8_t rplaintext[SKINNY64_BLOCK_SIZE * 128];
    int plaintext_ok, ciphertext_ok;
    unsigned index;

    printf("%s Parallel ECB: ", test->name);
    fflush(stdout);

    for (index = 0; index < sizeof(plaintext); ++index) {
        plaintext[index] = (uint8_t)(index % 251);
    }

    skinny64_parallel_ecb_init(&ctx);
    skinny64_parallel_ecb_set_key(&ctx, test->key, test->key_size);
    skinny64_parallel_ecb_encrypt(ciphertext, plaintext, sizeof(plaintext), &ctx);
    skinny64_parallel_ecb_decrypt(rplaintext, ciphertext, sizeof(ciphertext), &ctx);
    skinny64_parallel_ecb_cleanup(&ctx);

    plaintext_ok = memcmp(rplaintext, plaintext, sizeof(plaintext)) == 0;

    skinny64_set_key(&ks, test->key, test->key_size);
    for (index = 0; index < sizeof(plaintext); index += SKINNY64_BLOCK_SIZE) {
        skinny64_ecb_encrypt(rplaintext + index, plaintext + index, &ks);
    }

    ciphertext_ok = memcmp(rplaintext, ciphertext, sizeof(ciphertext)) == 0;

    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

static void skinny128EcbTest(const SkinnyTestVector *test)
{
    Skinny128Key_t ks;
    uint8_t plaintext[SKINNY128_BLOCK_SIZE];
    uint8_t ciphertext[SKINNY128_BLOCK_SIZE];
    int plaintext_ok, ciphertext_ok;

    printf("%s ECB: ", test->name);
    fflush(stdout);

    skinny128_set_key(&ks, test->key, test->key_size);
    skinny128_ecb_encrypt(ciphertext, test->plaintext, &ks);
    skinny128_ecb_decrypt(plaintext, test->ciphertext, &ks);

    plaintext_ok = memcmp(plaintext, test->plaintext, SKINNY128_BLOCK_SIZE) == 0;
    ciphertext_ok = memcmp(ciphertext, test->ciphertext, SKINNY128_BLOCK_SIZE) == 0;

    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

static void skinny128CtrTest(const SkinnyTestVector *test)
{
    static uint8_t const base_counter[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
    };
    Skinny128Key_t ks;
    Skinny128CTR_t ctr;
    uint8_t counter[SKINNY128_BLOCK_SIZE];
    uint8_t plaintext[CTR_BLOCK_COUNT][SKINNY128_BLOCK_SIZE];
    uint8_t ciphertext[CTR_BLOCK_COUNT][SKINNY128_BLOCK_SIZE];
    uint8_t actual[CTR_BLOCK_COUNT][SKINNY128_BLOCK_SIZE];
    unsigned index, carry, posn, inc, size;
    int ok = 1;

    printf("%s CTR: ", test->name);
    fflush(stdout);

    /* Simple implementation of counter mode to cross-check the real one */
    skinny128_set_key(&ks, test->key, test->key_size);
    for (index = 0; index < CTR_BLOCK_COUNT; ++index) {
        carry = index;
        for (posn = SKINNY128_BLOCK_SIZE; posn > 0; ) {
            --posn;
            carry += base_counter[posn];
            counter[posn] = (uint8_t)carry;
            carry >>= 8;
        }
        skinny128_ecb_encrypt(&(ciphertext[index]), counter, &ks);
        for (posn = 0; posn < SKINNY128_BLOCK_SIZE; ++posn) {
            plaintext[index][posn] =
                test->plaintext[(posn + index) % SKINNY128_BLOCK_SIZE];
            ciphertext[index][posn] ^= plaintext[index][posn];
        }
    }

    /* Encrypt the entire plaintext in a single request */
    memset(actual, 0, sizeof(actual));
    skinny128_ctr_init(&ctr);
    skinny128_ctr_set_key(&ctr, test->key, test->key_size);
    skinny128_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    skinny128_ctr_encrypt(actual, plaintext, sizeof(plaintext), &ctr);
    if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Decrypt the ciphertext back to the plaintext, in-place */
    skinny128_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    skinny128_ctr_encrypt(actual, actual, sizeof(ciphertext), &ctr);
    skinny128_ctr_cleanup(&ctr);
    if (memcmp(plaintext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Use various size increments to check data that is not block-aligned */
    for (inc = 1; inc <= (SKINNY128_BLOCK_SIZE * 3); ++inc) {
        memset(actual, 0, sizeof(actual));
        skinny128_ctr_init(&ctr);
        skinny128_ctr_set_key(&ctr, test->key, test->key_size);
        skinny128_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
        for (posn = 0; posn < sizeof(plaintext); posn += inc) {
            size = sizeof(plaintext) - posn;
            if (size > inc)
                size = inc;
            skinny128_ctr_encrypt
                (((uint8_t *)actual) + posn,
                 ((uint8_t *)plaintext) + posn, size, &ctr);
        }
        skinny128_ctr_cleanup(&ctr);
        if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
            ok = 0;
    }

    /* Report the results */
    if (ok) {
        printf("ok\n");
    } else {
        printf("INCORRECT\n");
        error = 1;
    }
}

static void skinny128ParallelEcbTest(const SkinnyTestVector *test)
{
    Skinny128Key_t ks;
    Skinny128ParallelECB_t ctx;
    uint8_t plaintext[SKINNY128_BLOCK_SIZE * 128];
    uint8_t ciphertext[SKINNY128_BLOCK_SIZE * 128];
    uint8_t rplaintext[SKINNY128_BLOCK_SIZE * 128];
    int plaintext_ok, ciphertext_ok;
    unsigned index;

    printf("%s Parallel ECB: ", test->name);
    fflush(stdout);

    for (index = 0; index < sizeof(plaintext); ++index) {
        plaintext[index] = (uint8_t)(index % 251);
    }

    skinny128_parallel_ecb_init(&ctx);
    skinny128_parallel_ecb_set_key(&ctx, test->key, test->key_size);
    skinny128_parallel_ecb_encrypt(ciphertext, plaintext, sizeof(plaintext), &ctx);
    skinny128_parallel_ecb_decrypt(rplaintext, ciphertext, sizeof(ciphertext), &ctx);
    skinny128_parallel_ecb_cleanup(&ctx);

    plaintext_ok = memcmp(rplaintext, plaintext, sizeof(plaintext)) == 0;

    skinny128_set_key(&ks, test->key, test->key_size);
    for (index = 0; index < sizeof(plaintext); index += SKINNY128_BLOCK_SIZE) {
        skinny128_ecb_encrypt(rplaintext + index, plaintext + index, &ks);
    }

    ciphertext_ok = memcmp(rplaintext, ciphertext, sizeof(ciphertext)) == 0;

    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

static void mantisEcbTest(const MantisTestVector *test)
{
    MantisKey_t ks;
    uint8_t plaintext1[MANTIS_BLOCK_SIZE];
    uint8_t ciphertext1[MANTIS_BLOCK_SIZE];
    uint8_t plaintext2[MANTIS_BLOCK_SIZE];
    uint8_t ciphertext2[MANTIS_BLOCK_SIZE];
    int plaintext_ok, ciphertext_ok;

    printf("%s ECB: ", test->name);
    fflush(stdout);

    /* Start with the mode set to encrypt first */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ecb_crypt(ciphertext1, test->plaintext, &ks);
    mantis_swap_modes(&ks); /* Switch to decryption */
    mantis_ecb_crypt(plaintext1, test->ciphertext, &ks);

    /* Perform the test again with the mode set to decrypt first */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_DECRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ecb_crypt(plaintext2, test->ciphertext, &ks);
    mantis_swap_modes(&ks); /* Switch to encryption */
    mantis_ecb_crypt(ciphertext2, test->plaintext, &ks);

    /* Check the results */
    plaintext_ok =
        memcmp(plaintext1, test->plaintext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(plaintext2, test->plaintext, MANTIS_BLOCK_SIZE) == 0;
    ciphertext_ok =
        memcmp(ciphertext1, test->ciphertext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(ciphertext2, test->ciphertext, MANTIS_BLOCK_SIZE) == 0;

    /* Do the above again, but supply the tweak during encryption */
    memset(plaintext1, 0, sizeof(plaintext1));
    memset(plaintext2, 0, sizeof(plaintext2));
    memset(ciphertext1, 0, sizeof(ciphertext1));
    memset(ciphertext2, 0, sizeof(ciphertext2));
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    mantis_ecb_crypt_tweaked(ciphertext1, test->plaintext, test->tweak, &ks);
    mantis_swap_modes(&ks);
    mantis_ecb_crypt_tweaked(plaintext1, test->ciphertext, test->tweak, &ks);
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_DECRYPT);
    mantis_ecb_crypt_tweaked(plaintext2, test->ciphertext, test->tweak, &ks);
    mantis_swap_modes(&ks);
    mantis_ecb_crypt_tweaked(ciphertext2, test->plaintext, test->tweak, &ks);

    /* Check the results */
    plaintext_ok &=
        memcmp(plaintext1, test->plaintext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(plaintext2, test->plaintext, MANTIS_BLOCK_SIZE) == 0;
    ciphertext_ok &=
        memcmp(ciphertext1, test->ciphertext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(ciphertext2, test->ciphertext, MANTIS_BLOCK_SIZE) == 0;

    /* Report the results */
    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

static void mantisCtrTest(const MantisTestVector *test)
{
    static uint8_t const base_counter[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    MantisKey_t ks;
    MantisCTR_t ctr;
    uint8_t counter[MANTIS_BLOCK_SIZE];
    uint8_t plaintext[CTR_BLOCK_COUNT][MANTIS_BLOCK_SIZE];
    uint8_t ciphertext[CTR_BLOCK_COUNT][MANTIS_BLOCK_SIZE];
    uint8_t actual[CTR_BLOCK_COUNT][MANTIS_BLOCK_SIZE];
    unsigned index, carry, posn, inc, size;
    int ok = 1;

    printf("%s CTR: ", test->name);
    fflush(stdout);

    /* Simple implementation of counter mode to cross-check the real one */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE, test->rounds, MANTIS_ENCRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    for (index = 0; index < CTR_BLOCK_COUNT; ++index) {
        carry = index;
        for (posn = MANTIS_BLOCK_SIZE; posn > 0; ) {
            --posn;
            carry += base_counter[posn];
            counter[posn] = (uint8_t)carry;
            carry >>= 8;
        }
        mantis_ecb_crypt(&(ciphertext[index]), counter, &ks);
        for (posn = 0; posn < MANTIS_BLOCK_SIZE; ++posn) {
            plaintext[index][posn] =
                test->plaintext[(posn + index) % MANTIS_BLOCK_SIZE];
            ciphertext[index][posn] ^= plaintext[index][posn];
        }
    }

    /* Encrypt the entire plaintext in a single request */
    memset(actual, 0, sizeof(actual));
    mantis_ctr_init(&ctr);
    mantis_ctr_set_key(&ctr, test->key, MANTIS_KEY_SIZE, test->rounds);
    mantis_ctr_set_tweak(&ctr, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    mantis_ctr_encrypt(actual, plaintext, sizeof(plaintext), &ctr);
    if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Decrypt the ciphertext back to the plaintext, in-place */
    mantis_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    mantis_ctr_encrypt(actual, actual, sizeof(ciphertext), &ctr);
    mantis_ctr_cleanup(&ctr);
    if (memcmp(plaintext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Use various size increments to check data that is not block-aligned */
    for (inc = 1; inc <= (MANTIS_BLOCK_SIZE * 3); ++inc) {
        memset(actual, 0, sizeof(actual));
        mantis_ctr_init(&ctr);
        mantis_ctr_set_key(&ctr, test->key, MANTIS_KEY_SIZE, test->rounds);
        mantis_ctr_set_tweak(&ctr, test->tweak, MANTIS_TWEAK_SIZE);
        mantis_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
        for (posn = 0; posn < sizeof(plaintext); posn += inc) {
            size = sizeof(plaintext) - posn;
            if (size > inc)
                size = inc;
            mantis_ctr_encrypt
                (((uint8_t *)actual) + posn,
                 ((uint8_t *)plaintext) + posn, size, &ctr);
        }
        mantis_ctr_cleanup(&ctr);
        if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
            ok = 0;
    }

    /* Report the results */
    if (ok) {
        printf("ok\n");
    } else {
        printf("INCORRECT\n");
        error = 1;
    }
}

static void mantisParallelEcbTest(const MantisTestVector *test)
{
    MantisKey_t ks;
    MantisParallelECB_t ctx;
    uint8_t plaintext[MANTIS_BLOCK_SIZE * 128];
    uint8_t ciphertext[MANTIS_BLOCK_SIZE * 128];
    uint8_t rplaintext[MANTIS_BLOCK_SIZE * 128];
    uint8_t tweak[MANTIS_BLOCK_SIZE * 128];
    int plaintext_ok, ciphertext_ok;
    unsigned index;

    printf("%s Parallel ECB: ", test->name);
    fflush(stdout);

    for (index = 0; index < sizeof(plaintext); ++index) {
        plaintext[index] = (uint8_t)(index % 251);
        tweak[sizeof(tweak) - 1 - index] = (uint8_t)(index % 251);
    }

    mantis_parallel_ecb_init(&ctx);
    mantis_parallel_ecb_set_key
        (&ctx, test->key, MANTIS_KEY_SIZE, test->rounds, MANTIS_ENCRYPT);
    mantis_parallel_ecb_crypt
        (ciphertext, plaintext, tweak, sizeof(plaintext), &ctx);
    mantis_parallel_ecb_swap_modes(&ctx);
    mantis_parallel_ecb_crypt
        (rplaintext, ciphertext, tweak, sizeof(ciphertext), &ctx);
    mantis_parallel_ecb_cleanup(&ctx);

    plaintext_ok = memcmp(rplaintext, plaintext, sizeof(plaintext)) == 0;

    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    for (index = 0; index < sizeof(plaintext); index += MANTIS_BLOCK_SIZE) {
        mantis_set_tweak(&ks, tweak + index, MANTIS_TWEAK_SIZE);
        mantis_ecb_crypt(rplaintext + index, plaintext + index, &ks);
    }

    ciphertext_ok = memcmp(rplaintext, ciphertext, sizeof(ciphertext)) == 0;

    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

/* Define to 1 to include the sbox generator */
#define GEN_SBOX 0

#if GEN_SBOX
void generate_sboxes(void);
#endif

int main(int argc, char **argv)
{
    skinny64EcbTest(&testVector64_64);
    skinny64EcbTest(&testVector64_128);
    skinny64EcbTest(&testVector64_192);

    skinny64CtrTest(&testVector64_64);
    skinny64CtrTest(&testVector64_128);
    skinny64CtrTest(&testVector64_192);

    skinny64ParallelEcbTest(&testVector64_64);
    skinny64ParallelEcbTest(&testVector64_128);
    skinny64ParallelEcbTest(&testVector64_192);

    skinny128EcbTest(&testVector128_128);
    skinny128EcbTest(&testVector128_256);
    skinny128EcbTest(&testVector128_384);

    skinny128CtrTest(&testVector128_128);
    skinny128CtrTest(&testVector128_256);
    skinny128CtrTest(&testVector128_384);

    skinny128ParallelEcbTest(&testVector128_128);
    skinny128ParallelEcbTest(&testVector128_256);
    skinny128ParallelEcbTest(&testVector128_384);

    mantisEcbTest(&testMantis5);
    mantisEcbTest(&testMantis6);
    mantisEcbTest(&testMantis7);
    mantisEcbTest(&testMantis8);

    mantisCtrTest(&testMantis5);
    mantisCtrTest(&testMantis6);
    mantisCtrTest(&testMantis7);
    mantisCtrTest(&testMantis8);

    mantisParallelEcbTest(&testMantis5);
    mantisParallelEcbTest(&testMantis6);
    mantisParallelEcbTest(&testMantis7);
    mantisParallelEcbTest(&testMantis8);

#if GEN_SBOX
    generate_sboxes();
#endif
    return error;
}

#if GEN_SBOX

/* This sbox generator is used to verify the bit-sliced implementation.
   We do not use this in the actual implementation because table lookups
   do not have constant-cache behaviour. */

int permute1(int y)
{
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    return ((y & 0x01) << 2) |
           ((y & 0x06) << 5) |
           ((y & 0x20) >> 5) |
           ((y & 0xC8) >> 2) |
           ((y & 0x10) >> 1);
}

int permute1_inv(int y)
{
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    return ((y & 0x08) << 1) |
           ((y & 0x32) << 2) |
           ((y & 0x01) << 5) |
           ((y & 0xC0) >> 5) |
           ((y & 0x04) >> 2);
}

int permute2(int y)
{
    return (y & 0xF9) | ((y >> 1) & 0x02) | ((y << 1) & 0x04);
}

void generate_sbox(void)
{
    int x, y;
    printf("static unsigned char const sbox[256] = {\n");
    for (x = 0; x <= 255; ++x) {
        y = x;
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute2(y);
        printf("0x%02x, ", y);
        if ((x % 12) == 11)
            printf("\n");
    }
    printf("\n};\n\n");
}

void generate_inv_sbox(void)
{
    int x, y;
    printf("static unsigned char const sbox_inv[256] = {\n");
    for (x = 0; x <= 255; ++x) {
        y = x;
        y = permute2(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        printf("0x%02x, ", y);
        if ((x % 12) == 11)
            printf("\n");
    }
    printf("\n};\n\n");
}

#define NAND(x, y)  (~((x) & (y)))
#define NOR(x, y)   (~((x) | (y)))

void generate_mantis_sbox(void)
{
    int x, y, a, b, c, d;
    int aout, bout, cout, dout;
    printf("static unsigned char const mantis_sbox[14] = {\n");
    for (x = 0; x <= 15; ++x) {
        a = x >> 3;
        b = x >> 2;
        c = x >> 1;
        d = x;
        /* aout = NAND(NAND(~c, NAND(a, b)), (a | d)); */
        aout = ~((c | (a & b)) & (a | d));

        /* bout = NAND(NOR(NOR(a, d), (b & c)), NAND((a & c), d)); */
        bout = (~(a | d)) | (b & c) | (a & c & d);

        /* cout = NAND(NAND(b, d), (NOR(b, d) | a)); */
        cout = (b & d) | ((b | d) & ~a);

        /* dout = NOR(NOR(a, (b | c)), NAND(NAND(a, b), (c | d))); */
        dout = (a | b | c) & (~(a & b)) & (c | d);

        y = ((aout & 0x01) << 3) | ((bout & 0x01) << 2) |
            ((cout & 0x01) << 1) | (dout & 0x01);
        printf("%x, ", y);
    }
    printf("\n};\n\n");
}

void generate_sboxes(void)
{
    generate_sbox();
    generate_inv_sbox();
    generate_mantis_sbox();
}

#endif /* GEN_SBOX */
