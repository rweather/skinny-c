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

/* This implementation encrypts eight blocks at a time */
#define SKINNY128_CTR_BLOCK_SIZE (SKINNY128_BLOCK_SIZE * 8)

/** Internal state information for Skinny-128 in CTR mode */
typedef struct
{
    /** Key schedule for Skinny-128, with an optional tweak */
    Skinny128TweakedKey_t kt;

    /** Counter values for the next block, pre-formatted into row vectors */
    SkinnyVector8x32_t counter[4];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[SKINNY128_CTR_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

    /** Base pointer for unaligned memory allocation */
    void *base_ptr;

} Skinny128CTRVec256Ctx_t;

static int skinny128_ctr_vec256_init(Skinny128CTR_t *ctr)
{
    Skinny128CTRVec256Ctx_t *ctx;
    void *base_ptr;
    if ((ctx = skinny_calloc(sizeof(Skinny128CTRVec256Ctx_t), &base_ptr)) == NULL)
        return 0;
    ctx->base_ptr = base_ptr;
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;
    ctr->ctx = ctx;
    return 1;
}

static void skinny128_ctr_vec256_cleanup(Skinny128CTR_t *ctr)
{
    if (ctr->ctx) {
        Skinny128CTRVec256Ctx_t *ctx = ctr->ctx;
        void *base_ptr = ctx->base_ptr;
        skinny_cleanse(ctx, sizeof(Skinny128CTRVec256Ctx_t));
        free(base_ptr);
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

/* Increment a specific column in an array of row vectors */
STATIC_INLINE void skinny128_ctr_increment
    (SkinnyVector8x32_t *counter, unsigned column, unsigned inc)
{
    uint8_t *ctr = ((uint8_t *)counter) + column * 4;
    uint8_t *ptr;
    unsigned index;
    for (index = 16; index > 0; ) {
        --index;
        ptr = ctr + (index & 0x0C) * 8;
#if SKINNY_LITTLE_ENDIAN
        ptr += index & 0x03;
#else
        ptr += 3 - (index & 0x03);
#endif
        inc += ptr[0];
        ptr[0] = (uint8_t)inc;
        inc >>= 8;
    }
}

static int skinny128_ctr_vec256_set_counter
    (Skinny128CTR_t *ctr, const void *counter, unsigned size)
{
    Skinny128CTRVec256Ctx_t *ctx;
    unsigned char block[SKINNY128_BLOCK_SIZE];

    /* Validate the parameters */
    if (size > SKINNY128_BLOCK_SIZE)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(block, 0, SKINNY128_BLOCK_SIZE - size);
        memcpy(block + SKINNY128_BLOCK_SIZE - size, counter, size);
    } else {
        memset(block, 0, SKINNY128_BLOCK_SIZE);
    }
    ctx->offset = SKINNY128_CTR_BLOCK_SIZE;

    /* Load the counter block and convert into row vectors */
    ctx->counter[0] = skinny_to_vec8x32(READ_WORD32(block,  0));
    ctx->counter[1] = skinny_to_vec8x32(READ_WORD32(block,  4));
    ctx->counter[2] = skinny_to_vec8x32(READ_WORD32(block,  8));
    ctx->counter[3] = skinny_to_vec8x32(READ_WORD32(block, 12));

    /* Increment the second through seventh columns of each row vector */
    skinny128_ctr_increment(ctx->counter, 1, 1);
    skinny128_ctr_increment(ctx->counter, 2, 2);
    skinny128_ctr_increment(ctx->counter, 3, 3);
    skinny128_ctr_increment(ctx->counter, 4, 4);
    skinny128_ctr_increment(ctx->counter, 5, 5);
    skinny128_ctr_increment(ctx->counter, 6, 6);
    skinny128_ctr_increment(ctx->counter, 7, 7);

    /* Clean up and exit */
    skinny_cleanse(block, sizeof(block));
    return 1;
}

STATIC_INLINE SkinnyVector8x32_t skinny128_rotate_right
    (SkinnyVector8x32_t x, unsigned count)
{
    /* Note: we are rotating the cells right, which actually moves
       the values up closer to the MSB.  That is, we do a left shift
       on the word to rotate the cells in the word right */
    return (x << count) | (x >> (32 - count));
}

/* This function evaluates the S-box on four 256-bit vectors in parallel
   by interleaving the operations.  This tends to make better use of YMM
   registers on x86-64 CPU's that have AVX2 support or better as the CPU
   can schedule unrelated operations to operate in parallel. */
STATIC_INLINE void skinny128_sbox_four
    (SkinnyVector8x32_t *u, SkinnyVector8x32_t *v,
     SkinnyVector8x32_t *s, SkinnyVector8x32_t *t)
{
    SkinnyVector8x32_t x1 = *u;
    SkinnyVector8x32_t y1;
    SkinnyVector8x32_t x2 = *v;
    SkinnyVector8x32_t y2;
    SkinnyVector8x32_t x3 = *s;
    SkinnyVector8x32_t y3;
    SkinnyVector8x32_t x4 = *t;
    SkinnyVector8x32_t y4;

    x1 ^= ((~((x1 >> 2) | (x1 >> 3))) & 0x11111111U);
    x2 ^= ((~((x2 >> 2) | (x2 >> 3))) & 0x11111111U);
    x3 ^= ((~((x3 >> 2) | (x3 >> 3))) & 0x11111111U);
    x4 ^= ((~((x4 >> 2) | (x4 >> 3))) & 0x11111111U);

    y1  = ((~((x1 << 5) | (x1 << 1))) & 0x20202020U);
    y2  = ((~((x2 << 5) | (x2 << 1))) & 0x20202020U);
    y3  = ((~((x3 << 5) | (x3 << 1))) & 0x20202020U);
    y4  = ((~((x4 << 5) | (x4 << 1))) & 0x20202020U);

    x1 ^= ((~((x1 << 5) | (x1 << 4))) & 0x40404040U) ^ y1;
    x2 ^= ((~((x2 << 5) | (x2 << 4))) & 0x40404040U) ^ y2;
    x3 ^= ((~((x3 << 5) | (x3 << 4))) & 0x40404040U) ^ y3;
    x4 ^= ((~((x4 << 5) | (x4 << 4))) & 0x40404040U) ^ y4;

    y1  = ((~((x1 << 2) | (x1 << 1))) & 0x80808080U);
    y2  = ((~((x2 << 2) | (x2 << 1))) & 0x80808080U);
    y3  = ((~((x3 << 2) | (x3 << 1))) & 0x80808080U);
    y4  = ((~((x4 << 2) | (x4 << 1))) & 0x80808080U);

    x1 ^= ((~((x1 >> 2) | (x1 << 1))) & 0x02020202U) ^ y1;
    x2 ^= ((~((x2 >> 2) | (x2 << 1))) & 0x02020202U) ^ y2;
    x3 ^= ((~((x3 >> 2) | (x3 << 1))) & 0x02020202U) ^ y3;
    x4 ^= ((~((x4 >> 2) | (x4 << 1))) & 0x02020202U) ^ y4;

    y1  = ((~((x1 >> 5) | (x1 << 1))) & 0x04040404U);
    y2  = ((~((x2 >> 5) | (x2 << 1))) & 0x04040404U);
    y3  = ((~((x3 >> 5) | (x3 << 1))) & 0x04040404U);
    y4  = ((~((x4 >> 5) | (x4 << 1))) & 0x04040404U);

    x1 ^= ((~((x1 >> 1) | (x1 >> 2))) & 0x08080808U) ^ y1;
    x2 ^= ((~((x2 >> 1) | (x2 >> 2))) & 0x08080808U) ^ y2;
    x3 ^= ((~((x3 >> 1) | (x3 >> 2))) & 0x08080808U) ^ y3;
    x4 ^= ((~((x4 >> 1) | (x4 >> 2))) & 0x08080808U) ^ y4;

    *u = ((x1 & 0x08080808U) << 1) |
         ((x1 & 0x32323232U) << 2) |
         ((x1 & 0x01010101U) << 5) |
         ((x1 & 0x80808080U) >> 6) |
         ((x1 & 0x40404040U) >> 4) |
         ((x1 & 0x04040404U) >> 2);

    *v = ((x2 & 0x08080808U) << 1) |
         ((x2 & 0x32323232U) << 2) |
         ((x2 & 0x01010101U) << 5) |
         ((x2 & 0x80808080U) >> 6) |
         ((x2 & 0x40404040U) >> 4) |
         ((x2 & 0x04040404U) >> 2);

    *s = ((x3 & 0x08080808U) << 1) |
         ((x3 & 0x32323232U) << 2) |
         ((x3 & 0x01010101U) << 5) |
         ((x3 & 0x80808080U) >> 6) |
         ((x3 & 0x40404040U) >> 4) |
         ((x3 & 0x04040404U) >> 2);

    *t = ((x4 & 0x08080808U) << 1) |
         ((x4 & 0x32323232U) << 2) |
         ((x4 & 0x01010101U) << 5) |
         ((x4 & 0x80808080U) >> 6) |
         ((x4 & 0x40404040U) >> 4) |
         ((x4 & 0x04040404U) >> 2);
}

static void skinny128_ecb_encrypt_eight
    (void *output, const SkinnyVector8x32_t *input, const Skinny128Key_t *ks)
{
    SkinnyVector8x32_t row0;
    SkinnyVector8x32_t row1;
    SkinnyVector8x32_t row2;
    SkinnyVector8x32_t row3;
    const Skinny128HalfCells_t *schedule;
    unsigned index;
    SkinnyVector8x32_t temp;

    /* Read the rows of all eight counter blocks into memory */
    row0 = input[0];
    row1 = input[1];
    row2 = input[2];
    row3 = input[3];

    /* Perform all encryption rounds on the eight blocks in parallel */
    schedule = ks->schedule;
    for (index = ks->rounds; index > 0; --index, ++schedule) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox_four(&row0, &row1, &row2, &row3);

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
#if SKINNY_LITTLE_ENDIAN && SKINNY_UNALIGNED
    *((SkinnyVector8x32U_t *)output) =
        (SkinnyVector8x32_t){row0[0], row1[0], row2[0], row3[0],
                             row0[1], row1[1], row2[1], row3[1]};
    *((SkinnyVector8x32U_t *)(output + 32)) =
        (SkinnyVector8x32_t){row0[2], row1[2], row2[2], row3[2],
                             row0[3], row1[3], row2[3], row3[3]};
    *((SkinnyVector8x32U_t *)(output + 64)) =
        (SkinnyVector8x32_t){row0[4], row1[4], row2[4], row3[4],
                             row0[5], row1[5], row2[5], row3[5]};
    *((SkinnyVector8x32U_t *)(output + 96)) =
        (SkinnyVector8x32_t){row0[6], row1[6], row2[6], row3[6],
                             row0[7], row1[7], row2[7], row3[7]};
#else
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
#endif
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
            skinny128_ctr_increment(ctx->counter, 0, 8);
            skinny128_ctr_increment(ctx->counter, 1, 8);
            skinny128_ctr_increment(ctx->counter, 2, 8);
            skinny128_ctr_increment(ctx->counter, 3, 8);
            skinny128_ctr_increment(ctx->counter, 4, 8);
            skinny128_ctr_increment(ctx->counter, 5, 8);
            skinny128_ctr_increment(ctx->counter, 6, 8);
            skinny128_ctr_increment(ctx->counter, 7, 8);

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

#else /* !SKINNY_VEC256_MATH */

/* Stubbed out */
Skinny128CTRVtable_t const _skinny128_ctr_vec256;

#endif /* !SKINNY_VEC256_MATH */
