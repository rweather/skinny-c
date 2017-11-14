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
#include "skinny128-ctr-internal.h"
#include "skinny-internal.h"
#include <stdlib.h>

#if SKINNY_VEC256_MATH

/* Skinny-128 state represented as a vector of eight 32-bit words */
typedef uint32_t Skinny128Vector_t SKINNY_VECTOR_ATTR(8, 32);

/* This implementation encrypts eight blocks at a time */
#define SKINNY128_CTR_BLOCK_SIZE (SKINNY128_BLOCK_SIZE * 8)

/** Internal state information for Skinny-128 in CTR mode */
typedef struct
{
    /** Key schedule for Skinny-128, with an optional tweak */
    Skinny128TweakedKey_t kt;

    /** Counter value for the next block */
    unsigned char counter[SKINNY128_CTR_BLOCK_SIZE];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[SKINNY128_CTR_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

} Skinny128CTRVec256Ctx_t;

static int skinny128_ctr_vec256_init(Skinny128CTR_t *ctr)
{
    Skinny128CTRVec256Ctx_t *ctx;
    if ((ctx = calloc(1, sizeof(Skinny128CTRVec256Ctx_t))) == NULL)
        return 0;
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;
    ctr->ctx = ctx;
    return 1;
}

static void skinny128_ctr_vec256_cleanup(Skinny128CTR_t *ctr)
{
    if (ctr->ctx) {
        skinny_cleanse(ctr->ctx, sizeof(Skinny128CTRVec256Ctx_t));
        free(ctr->ctx);
        ctr->ctx = 0;
    }
}

static int skinny128_ctr_vec256_set_key
    (Skinny128CTR_t *ctr, const void *key, unsigned size)
{
    Skinny128CTRVec256Ctx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!skinny128_set_key(&(ctx->kt.ks), key, size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_vec256_set_tweaked_key
    (Skinny128CTR_t *ctr, const void *key, unsigned key_size)
{
    Skinny128CTRVec256Ctx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!skinny128_set_tweaked_key(&(ctx->kt), key, key_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_vec256_set_tweak
    (Skinny128CTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    Skinny128CTRVec256Ctx_t *ctx;

    /* Validate the parameters */
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying tweak */
    if (!skinny128_set_tweak(&(ctx->kt), tweak, tweak_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_vec256_set_counter
    (Skinny128CTR_t *ctr, const void *counter, unsigned size)
{
    Skinny128CTRVec256Ctx_t *ctx;
    unsigned index;

    /* Validate the parameters */
    if (size > SKINNY128_BLOCK_SIZE)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(ctx->counter, 0, SKINNY128_BLOCK_SIZE - size);
        memcpy(ctx->counter + SKINNY128_BLOCK_SIZE - size, counter, size);
    } else {
        memset(ctx->counter, 0, SKINNY128_BLOCK_SIZE);
    }
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;

    /* Expand the counter to eight blocks because we are going
       to be encrypting the counter eight blocks at a time */
    for (index = 1; index < 8; ++index) {
        memcpy(ctx->counter + SKINNY128_BLOCK_SIZE * index,
               ctx->counter, SKINNY128_BLOCK_SIZE);
        skinny128_inc_counter
            (ctx->counter + SKINNY128_BLOCK_SIZE * index, index);
    }
    return 1;
}

STATIC_INLINE Skinny128Vector_t skinny128_rotate_right
    (Skinny128Vector_t x, unsigned count)
{
    /* Note: we are rotating the cells right, which actually moves
       the values up closer to the MSB.  That is, we do a left shift
       on the word to rotate the cells in the word right */
    return (x << count) | (x >> (32 - count));
}

#define SBOX_MIX(x)  \
    (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
#define SBOX_SWAP(x)  \
    (((x) & 0xF9F9F9F9U) | \
     (((x) >> 1) & 0x02020202U) | \
     (((x) << 1) & 0x04040404U))

/* Permutation generated by http://programming.sirrida.de/calcperm.php */
#define SBOX_PERMUTE(x)  \
        ((((x) & 0x01010101U) << 2) | \
         (((x) & 0x06060606U) << 5) | \
         (((x) & 0x20202020U) >> 5) | \
         (((x) & 0xC8C8C8C8U) >> 2) | \
         (((x) & 0x10101010U) >> 1))
#define SBOX_PERMUTE_INV(x)  \
        ((((x) & 0x08080808U) << 1) | \
         (((x) & 0x32323232U) << 2) | \
         (((x) & 0x01010101U) << 5) | \
         (((x) & 0xC0C0C0C0U) >> 5) | \
         (((x) & 0x04040404U) >> 2))

STATIC_INLINE Skinny128Vector_t skinny128_sbox(Skinny128Vector_t x)
{
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE(x);
    x = SBOX_MIX(x);
    return SBOX_SWAP(x);
}

static void skinny128_ecb_encrypt_eight
    (void *output, const void *input, const Skinny128Key_t *ks)
{
    Skinny128Vector_t row0;
    Skinny128Vector_t row1;
    Skinny128Vector_t row2;
    Skinny128Vector_t row3;
    const Skinny128HalfCells_t *schedule;
    unsigned index;
    Skinny128Vector_t temp;

    /* Read the rows of all eight blocks into memory */
    row0 = (Skinny128Vector_t)
        {READ_WORD32(input,   0), READ_WORD32(input,  16),
         READ_WORD32(input,  32), READ_WORD32(input,  48),
         READ_WORD32(input,  64), READ_WORD32(input,  80),
         READ_WORD32(input,  96), READ_WORD32(input, 112)};
    row1 = (Skinny128Vector_t)
        {READ_WORD32(input,   4), READ_WORD32(input,  20),
         READ_WORD32(input,  36), READ_WORD32(input,  52),
         READ_WORD32(input,  68), READ_WORD32(input,  84),
         READ_WORD32(input, 100), READ_WORD32(input, 116)};
    row2 = (Skinny128Vector_t)
        {READ_WORD32(input,   8), READ_WORD32(input,  24),
         READ_WORD32(input,  40), READ_WORD32(input,  56),
         READ_WORD32(input,  72), READ_WORD32(input,  88),
         READ_WORD32(input, 104), READ_WORD32(input, 120)};
    row3 = (Skinny128Vector_t)
        {READ_WORD32(input,  12), READ_WORD32(input,  28),
         READ_WORD32(input,  44), READ_WORD32(input,  60),
         READ_WORD32(input,  76), READ_WORD32(input,  92),
         READ_WORD32(input, 108), READ_WORD32(input, 124)};

    /* Perform all encryption rounds on the eight blocks in parallel */
    schedule = ks->schedule;
    for (index = ks->rounds; index > 0; --index, ++schedule) {
        /* Apply the S-box to all bytes in the state */
        row0 = skinny128_sbox(row0);
        row1 = skinny128_sbox(row1);
        row2 = skinny128_sbox(row2);
        row3 = skinny128_sbox(row3);

        /* Apply the subkey for this round */
        row0 ^= schedule->row[0];
        row1 ^= schedule->row[1];
        row2 ^= 0x02;

        /* Shift the rows */
        row1 = skinny128_rotate_right(row1, 8);
        row2 = skinny128_rotate_right(row2, 16);
        row3 = skinny128_rotate_right(row3, 24);

        /* Mix the columns */
        row1 ^= row2;
        row2 ^= row0;
        temp = row3 ^ row2;
        row3 = row2;
        row2 = row1;
        row1 = row0;
        row0 = temp;
    }

    /* Write the rows of all eight blocks back to memory */
    WRITE_WORD32(output,   0, row0[0]);
    WRITE_WORD32(output,   4, row1[0]);
    WRITE_WORD32(output,   8, row2[0]);
    WRITE_WORD32(output,  12, row3[0]);
    WRITE_WORD32(output,  16, row0[1]);
    WRITE_WORD32(output,  20, row1[1]);
    WRITE_WORD32(output,  24, row2[1]);
    WRITE_WORD32(output,  28, row3[1]);
    WRITE_WORD32(output,  32, row0[2]);
    WRITE_WORD32(output,  36, row1[2]);
    WRITE_WORD32(output,  40, row2[2]);
    WRITE_WORD32(output,  44, row3[2]);
    WRITE_WORD32(output,  48, row0[3]);
    WRITE_WORD32(output,  52, row1[3]);
    WRITE_WORD32(output,  56, row2[3]);
    WRITE_WORD32(output,  60, row3[3]);
    WRITE_WORD32(output,  64, row0[4]);
    WRITE_WORD32(output,  68, row1[4]);
    WRITE_WORD32(output,  72, row2[4]);
    WRITE_WORD32(output,  76, row3[4]);
    WRITE_WORD32(output,  80, row0[5]);
    WRITE_WORD32(output,  84, row1[5]);
    WRITE_WORD32(output,  88, row2[5]);
    WRITE_WORD32(output,  92, row3[5]);
    WRITE_WORD32(output,  96, row0[6]);
    WRITE_WORD32(output, 100, row1[6]);
    WRITE_WORD32(output, 104, row2[6]);
    WRITE_WORD32(output, 108, row3[6]);
    WRITE_WORD32(output, 112, row0[7]);
    WRITE_WORD32(output, 116, row1[7]);
    WRITE_WORD32(output, 120, row2[7]);
    WRITE_WORD32(output, 124, row3[7]);
}

static int skinny128_ctr_vec256_encrypt
    (void *output, const void *input, size_t size, Skinny128CTR_t *ctr)
{
    Skinny128CTRVec256Ctx_t *ctx;
    uint8_t *out = (uint8_t *)output;
    const uint8_t *in = (const uint8_t *)input;

    /* Validate the parameters */
    if (!output || !input)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Encrypt the input in CTR mode to create the output */
    while (size > 0) {
        if (ctx->offset >= SKINNY128_CTR_BLOCK_SIZE) {
            /* We need a new keystream block */
            skinny128_ecb_encrypt_eight
                (ctx->ecounter, ctx->counter, &(ctx->kt.ks));
            skinny128_inc_counter(ctx->counter, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE * 2, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE * 3, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE * 4, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE * 5, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE * 6, 8);
            skinny128_inc_counter(ctx->counter + SKINNY128_BLOCK_SIZE * 7, 8);

            /* XOR an entire keystream block in one go if possible */
            if (size >= SKINNY128_CTR_BLOCK_SIZE) {
                skinny128_xor(out, in, ctx->ecounter);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE,
                              in + SKINNY128_BLOCK_SIZE,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE * 2,
                              in + SKINNY128_BLOCK_SIZE * 2,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE * 2);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE * 3,
                              in + SKINNY128_BLOCK_SIZE * 3,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE * 3);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE * 4,
                              in + SKINNY128_BLOCK_SIZE * 4,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE * 4);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE * 5,
                              in + SKINNY128_BLOCK_SIZE * 5,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE * 5);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE * 6,
                              in + SKINNY128_BLOCK_SIZE * 6,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE * 6);
                skinny128_xor(out + SKINNY128_BLOCK_SIZE * 7,
                              in + SKINNY128_BLOCK_SIZE * 7,
                              ctx->ecounter + SKINNY128_BLOCK_SIZE * 7);
                out += SKINNY128_CTR_BLOCK_SIZE;
                in += SKINNY128_CTR_BLOCK_SIZE;
                size -= SKINNY128_CTR_BLOCK_SIZE;
            } else {
                /* Last partial block in the request */
                skinny_xor(out, in, ctx->ecounter, size);
                ctx->offset = size;
                break;
            }
        } else {
            /* Left-over keystream data from the last request */
            size_t temp = SKINNY128_CTR_BLOCK_SIZE - ctx->offset;
            if (temp > size)
                temp = size;
            skinny_xor(out, in, ctx->ecounter + ctx->offset, temp);
            ctx->offset += temp;
            out += temp;
            in += temp;
            size -= temp;
        }
    }
    return 1;
}

/** Vtable for the 128-bit SIMD Skinny-128-CTR implementation */
Skinny128CTRVtable_t const _skinny128_ctr_vec256 = {
    skinny128_ctr_vec256_init,
    skinny128_ctr_vec256_cleanup,
    skinny128_ctr_vec256_set_key,
    skinny128_ctr_vec256_set_tweaked_key,
    skinny128_ctr_vec256_set_tweak,
    skinny128_ctr_vec256_set_counter,
    skinny128_ctr_vec256_encrypt
};

#endif /* SKINNY_VEC256_MATH */
