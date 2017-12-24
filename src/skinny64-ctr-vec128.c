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

#include "skinny64-cipher.h"
#include "skinny64-ctr-internal.h"
#include "skinny-internal.h"
#include <stdlib.h>

#if SKINNY_VEC128_MATH

/* This implementation encrypts eight blocks at a time */
#define SKINNY64_CTR_BLOCK_SIZE (SKINNY64_BLOCK_SIZE * 8)

/** Internal state information for Skinny-64 in CTR mode */
typedef struct
{
    /** Key schedule for Skinny-64, with an optional tweak */
    Skinny64TweakedKey_t kt;

    /** Counter values for the next block, pre-formatted into row vectors */
    SkinnyVector8x16_t counter[4];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[SKINNY64_CTR_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

    /** Base pointer for unaligned memory allocation */
    void *base_ptr;

} Skinny64CTRVec128Ctx_t;

static int skinny64_ctr_vec128_init(Skinny64CTR_t *ctr)
{
    Skinny64CTRVec128Ctx_t *ctx;
    void *base_ptr;
    if ((ctx = skinny_calloc(sizeof(Skinny64CTRVec128Ctx_t), &base_ptr)) == NULL)
        return 0;
    ctx->base_ptr = base_ptr;
    ctx->offset = SKINNY64_CTR_BLOCK_SIZE;
    ctr->ctx = ctx;
    return 1;
}

static void skinny64_ctr_vec128_cleanup(Skinny64CTR_t *ctr)
{
    if (ctr->ctx) {
        Skinny64CTRVec128Ctx_t *ctx = ctr->ctx;
        void *base_ptr = ctx->base_ptr;
        skinny_cleanse(ctx, sizeof(Skinny64CTRVec128Ctx_t));
        free(base_ptr);
        ctr->ctx = 0;
    }
}

static int skinny64_ctr_vec128_set_key(Skinny64CTR_t *ctr, const void *key, unsigned size)
{
    Skinny64CTRVec128Ctx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!skinny64_set_key(&(ctx->kt.ks), key, size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY64_CTR_BLOCK_SIZE;
    return 1;
}

static int skinny64_ctr_vec128_set_tweaked_key
    (Skinny64CTR_t *ctr, const void *key, unsigned key_size)
{
    Skinny64CTRVec128Ctx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!skinny64_set_tweaked_key(&(ctx->kt), key, key_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY64_CTR_BLOCK_SIZE;
    return 1;
}

static int skinny64_ctr_vec128_set_tweak
    (Skinny64CTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    Skinny64CTRVec128Ctx_t *ctx;

    /* Validate the parameters */
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying tweak */
    if (!skinny64_set_tweak(&(ctx->kt), tweak, tweak_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY64_CTR_BLOCK_SIZE;
    return 1;
}

/* Increment a specific column in an array of row vectors */
STATIC_INLINE void skinny64_ctr_increment
    (SkinnyVector8x16_t *counter, unsigned column, unsigned inc)
{
    uint8_t *ctr = ((uint8_t *)counter) + column * 2;
    uint8_t *ptr;
    unsigned index;
    for (index = 8; index > 0; ) {
        --index;
        ptr = ctr + (index & 0x06) * 8;
#if SKINNY_LITTLE_ENDIAN
        ptr += index & 0x01;
#else
        ptr += 1 - (index & 0x01);
#endif
        inc += ptr[0];
        ptr[0] = (uint8_t)inc;
        inc >>= 8;
    }
}

static int skinny64_ctr_vec128_set_counter
    (Skinny64CTR_t *ctr, const void *counter, unsigned size)
{
    Skinny64CTRVec128Ctx_t *ctx;
    unsigned char block[SKINNY64_BLOCK_SIZE];

    /* Validate the parameters */
    if (size > SKINNY64_BLOCK_SIZE)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(block, 0, SKINNY64_BLOCK_SIZE - size);
        memcpy(block + SKINNY64_BLOCK_SIZE - size, counter, size);
    } else {
        memset(block, 0, SKINNY64_BLOCK_SIZE);
    }
    ctx->offset = SKINNY64_CTR_BLOCK_SIZE;

    /* Load the counter block and convert into row vectors */
    ctx->counter[0] = skinny_to_vec8x16(READ_WORD16(block, 0));
    ctx->counter[1] = skinny_to_vec8x16(READ_WORD16(block, 2));
    ctx->counter[2] = skinny_to_vec8x16(READ_WORD16(block, 4));
    ctx->counter[3] = skinny_to_vec8x16(READ_WORD16(block, 6));

    /* Increment the second through seventh columns of each row vector */
    skinny64_ctr_increment(ctx->counter, 1, 1);
    skinny64_ctr_increment(ctx->counter, 2, 2);
    skinny64_ctr_increment(ctx->counter, 3, 3);
    skinny64_ctr_increment(ctx->counter, 4, 4);
    skinny64_ctr_increment(ctx->counter, 5, 5);
    skinny64_ctr_increment(ctx->counter, 6, 6);
    skinny64_ctr_increment(ctx->counter, 7, 7);

    /* Clean up and exit */
    skinny_cleanse(block, sizeof(block));
    return 1;
}

STATIC_INLINE SkinnyVector8x16_t skinny64_rotate_right
    (SkinnyVector8x16_t x, unsigned count)
{
    return (x >> count) | (x << (16 - count));
}

STATIC_INLINE SkinnyVector8x16_t skinny64_sbox(SkinnyVector8x16_t x)
{
    SkinnyVector8x16_t bit0 = ~x;
    SkinnyVector8x16_t bit1 = bit0 >> 1;
    SkinnyVector8x16_t bit2 = bit0 >> 2;
    SkinnyVector8x16_t bit3 = bit0 >> 3;
    bit0 ^= bit3 & bit2;
    bit3 ^= bit1 & bit2;
    bit2 ^= bit1 & bit0;
    bit1 ^= bit0 & bit3;
    x = ((bit0 << 3) & 0x8888U) |
        ( bit1       & 0x1111U) |
        ((bit2 << 1) & 0x2222U) |
        ((bit3 << 2) & 0x4444U);
    return ~x;
}

static void skinny64_ecb_encrypt_eight
    (void *output, const SkinnyVector8x16_t *input, const Skinny64Key_t *ks)
{
    SkinnyVector8x16_t row0;
    SkinnyVector8x16_t row1;
    SkinnyVector8x16_t row2;
    SkinnyVector8x16_t row3;
    const Skinny64HalfCells_t *schedule;
    unsigned index;
    SkinnyVector8x16_t temp;

    /* Read the rows of all eight counter blocks into memory */
    row0 = input[0];
    row1 = input[1];
    row2 = input[2];
    row3 = input[3];

    /* Perform all encryption rounds */
    schedule = ks->schedule;
    for (index = ks->rounds; index > 0; --index, ++schedule) {
        /* Apply the S-box to all bytes in the state */
        row0 = skinny64_sbox(row0);
        row1 = skinny64_sbox(row1);
        row2 = skinny64_sbox(row2);
        row3 = skinny64_sbox(row3);

        /* Apply the subkey for this round */
        row0 ^= schedule->row[0];
        row1 ^= schedule->row[1];
        row2 ^= 0x20;

        /* Shift the rows */
        row1 = skinny64_rotate_right(row1, 4);
        row2 = skinny64_rotate_right(row2, 8);
        row3 = skinny64_rotate_right(row3, 12);

        /* Mix the columns */
        row1 ^= row2;
        row2 ^= row0;
        temp = row3 ^ row2;
        row3 = row2;
        row2 = row1;
        row1 = row0;
        row0 = temp;
    }

    /* Write the rows of all eight blocks back to memory.
       Note: In this case, direct WRITE_WORD16() calls seem to give
       better performance than rearranging the vectors and performing
       an unaligned vector write */
#if 0 /* SKINNY_LITTLE_ENDIAN && SKINNY_UNALIGNED */
    *((SkinnyVector8x16U_t *)output) =
        (SkinnyVector8x16_t){row0[0], row1[0], row2[0], row3[0],
                             row0[1], row1[1], row2[1], row3[1]};
    *((SkinnyVector8x16U_t *)(output + 16)) =
        (SkinnyVector8x16_t){row0[2], row1[2], row2[2], row3[2],
                             row0[3], row1[3], row2[3], row3[3]};
    *((SkinnyVector8x16U_t *)(output + 32)) =
        (SkinnyVector8x16_t){row0[4], row1[4], row2[4], row3[4],
                             row0[5], row1[5], row2[5], row3[5]};
    *((SkinnyVector8x16U_t *)(output + 48)) =
        (SkinnyVector8x16_t){row0[6], row1[6], row2[6], row3[6],
                             row0[7], row1[7], row2[7], row3[7]};
#else
    WRITE_WORD16(output,  0, row0[0]);
    WRITE_WORD16(output,  2, row1[0]);
    WRITE_WORD16(output,  4, row2[0]);
    WRITE_WORD16(output,  6, row3[0]);
    WRITE_WORD16(output,  8, row0[1]);
    WRITE_WORD16(output, 10, row1[1]);
    WRITE_WORD16(output, 12, row2[1]);
    WRITE_WORD16(output, 14, row3[1]);
    WRITE_WORD16(output, 16, row0[2]);
    WRITE_WORD16(output, 18, row1[2]);
    WRITE_WORD16(output, 20, row2[2]);
    WRITE_WORD16(output, 22, row3[2]);
    WRITE_WORD16(output, 24, row0[3]);
    WRITE_WORD16(output, 26, row1[3]);
    WRITE_WORD16(output, 28, row2[3]);
    WRITE_WORD16(output, 30, row3[3]);
    WRITE_WORD16(output, 32, row0[4]);
    WRITE_WORD16(output, 34, row1[4]);
    WRITE_WORD16(output, 36, row2[4]);
    WRITE_WORD16(output, 38, row3[4]);
    WRITE_WORD16(output, 40, row0[5]);
    WRITE_WORD16(output, 42, row1[5]);
    WRITE_WORD16(output, 44, row2[5]);
    WRITE_WORD16(output, 46, row3[5]);
    WRITE_WORD16(output, 48, row0[6]);
    WRITE_WORD16(output, 50, row1[6]);
    WRITE_WORD16(output, 52, row2[6]);
    WRITE_WORD16(output, 54, row3[6]);
    WRITE_WORD16(output, 56, row0[7]);
    WRITE_WORD16(output, 58, row1[7]);
    WRITE_WORD16(output, 60, row2[7]);
    WRITE_WORD16(output, 62, row3[7]);
#endif
}

static int skinny64_ctr_vec128_encrypt
    (void *output, const void *input, size_t size, Skinny64CTR_t *ctr)
{
    Skinny64CTRVec128Ctx_t *ctx;
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
        if (ctx->offset >= SKINNY64_CTR_BLOCK_SIZE) {
            /* We need a new keystream block */
            skinny64_ecb_encrypt_eight
                (ctx->ecounter, ctx->counter, &(ctx->kt.ks));
            skinny64_ctr_increment(ctx->counter, 0, 8);
            skinny64_ctr_increment(ctx->counter, 1, 8);
            skinny64_ctr_increment(ctx->counter, 2, 8);
            skinny64_ctr_increment(ctx->counter, 3, 8);
            skinny64_ctr_increment(ctx->counter, 4, 8);
            skinny64_ctr_increment(ctx->counter, 5, 8);
            skinny64_ctr_increment(ctx->counter, 6, 8);
            skinny64_ctr_increment(ctx->counter, 7, 8);

            /* XOR an entire keystream block in one go if possible */
            if (size >= SKINNY64_CTR_BLOCK_SIZE) {
                skinny64_xor(out, in, ctx->ecounter);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE,
                             in + SKINNY64_BLOCK_SIZE,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE * 2,
                             in + SKINNY64_BLOCK_SIZE * 2,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE * 2);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE * 3,
                             in + SKINNY64_BLOCK_SIZE * 3,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE * 3);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE * 4,
                             in + SKINNY64_BLOCK_SIZE * 4,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE * 4);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE * 5,
                             in + SKINNY64_BLOCK_SIZE * 5,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE * 5);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE * 6,
                             in + SKINNY64_BLOCK_SIZE * 6,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE * 6);
                skinny64_xor(out + SKINNY64_BLOCK_SIZE * 7,
                             in + SKINNY64_BLOCK_SIZE * 7,
                             ctx->ecounter + SKINNY64_BLOCK_SIZE * 7);
                out += SKINNY64_CTR_BLOCK_SIZE;
                in += SKINNY64_CTR_BLOCK_SIZE;
                size -= SKINNY64_CTR_BLOCK_SIZE;
            } else {
                /* Last partial block in the request */
                skinny_xor(out, in, ctx->ecounter, size);
                ctx->offset = size;
                break;
            }
        } else {
            /* Left-over keystream data from the last request */
            size_t temp = SKINNY64_CTR_BLOCK_SIZE - ctx->offset;
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
Skinny64CTRVtable_t const _skinny64_ctr_vec128 = {
    skinny64_ctr_vec128_init,
    skinny64_ctr_vec128_cleanup,
    skinny64_ctr_vec128_set_key,
    skinny64_ctr_vec128_set_tweaked_key,
    skinny64_ctr_vec128_set_tweak,
    skinny64_ctr_vec128_set_counter,
    skinny64_ctr_vec128_encrypt
};

#else /* !SKINNY_VEC128_MATH */

/* Stubbed out */
Skinny64CTRVtable_t const _skinny64_ctr_vec128;

#endif /* !SKINNY_VEC128_MATH */
