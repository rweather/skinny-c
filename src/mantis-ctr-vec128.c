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

#include "mantis-cipher.h"
#include "mantis-ctr-internal.h"
#include "skinny-internal.h"
#include <stdlib.h>

#if SKINNY_VEC128_MATH

/* This implementation encrypts eight blocks at a time */
#define MANTIS_CTR_BLOCK_SIZE (MANTIS_BLOCK_SIZE * 8)

/** Internal state information for Mantis in CTR mode */
typedef struct
{
    /** Key schedule for Mantis */
    MantisKey_t ks;

    /** Counter values for the next block, pre-formatted into row vectors */
    SkinnyVector8x16_t counter[4];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[MANTIS_CTR_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

    /** Base pointer for unaligned memory allocation */
    void *base_ptr;

} MantisCTRVec128Ctx_t;

static int mantis_ctr_vec128_init(MantisCTR_t *ctr)
{
    MantisCTRVec128Ctx_t *ctx;
    void *base_ptr;
    if ((ctx = skinny_calloc(sizeof(MantisCTRVec128Ctx_t), &base_ptr)) == NULL)
        return 0;
    ctx->base_ptr = base_ptr;
    ctx->offset = MANTIS_CTR_BLOCK_SIZE;
    ctr->ctx = ctx;
    return 1;
}

static void mantis_ctr_vec128_cleanup(MantisCTR_t *ctr)
{
    if (ctr->ctx) {
        MantisCTRVec128Ctx_t *ctx = ctr->ctx;
        void *base_ptr = ctx->base_ptr;
        skinny_cleanse(ctx, sizeof(MantisCTRVec128Ctx_t));
        free(base_ptr);
        ctr->ctx = 0;
    }
}

static int mantis_ctr_vec128_set_key
    (MantisCTR_t *ctr, const void *key, unsigned size, unsigned rounds)
{
    MantisCTRVec128Ctx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!mantis_set_key(&(ctx->ks), key, size, rounds, MANTIS_ENCRYPT))
        return 0;

    /* Reset the keystream */
    ctx->offset = MANTIS_CTR_BLOCK_SIZE;
    return 1;
}

static int mantis_ctr_vec128_set_tweak
    (MantisCTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    MantisCTRVec128Ctx_t *ctx;

    /* Validate the parameters */
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying tweak */
    if (!mantis_set_tweak(&(ctx->ks), tweak, tweak_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = MANTIS_CTR_BLOCK_SIZE;
    return 1;
}

/* Increment a specific column in an array of row vectors */
STATIC_INLINE void mantis_ctr_increment
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

static int mantis_ctr_vec128_set_counter
    (MantisCTR_t *ctr, const void *counter, unsigned size)
{
    MantisCTRVec128Ctx_t *ctx;
    unsigned char block[MANTIS_BLOCK_SIZE];

    /* Validate the parameters */
    if (size > MANTIS_BLOCK_SIZE)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(block, 0, MANTIS_BLOCK_SIZE - size);
        memcpy(block + MANTIS_BLOCK_SIZE - size, counter, size);
    } else {
        memset(block, 0, MANTIS_BLOCK_SIZE);
    }
    ctx->offset = MANTIS_CTR_BLOCK_SIZE;

    /* Load the counter block and convert into row vectors */
    ctx->counter[0] = skinny_to_vec8x16(READ_WORD16(block, 0));
    ctx->counter[1] = skinny_to_vec8x16(READ_WORD16(block, 2));
    ctx->counter[2] = skinny_to_vec8x16(READ_WORD16(block, 4));
    ctx->counter[3] = skinny_to_vec8x16(READ_WORD16(block, 6));

    /* Increment the second through seventh columns of each row vector */
    mantis_ctr_increment(ctx->counter, 1, 1);
    mantis_ctr_increment(ctx->counter, 2, 2);
    mantis_ctr_increment(ctx->counter, 3, 3);
    mantis_ctr_increment(ctx->counter, 4, 4);
    mantis_ctr_increment(ctx->counter, 5, 5);
    mantis_ctr_increment(ctx->counter, 6, 6);
    mantis_ctr_increment(ctx->counter, 7, 7);

    /* Clean up and exit */
    skinny_cleanse(block, sizeof(block));
    return 1;
}

/**
 * \brief All cells in a Mantis 8-way block.
 */
typedef union
{
    SkinnyVector8x16_t row[4];

} MantisVectorCells_t;

STATIC_INLINE SkinnyVector8x16_t mantis_sbox(SkinnyVector8x16_t d)
{
    /*
     * MIDORI Sb0 from section 4.2 of https://eprint.iacr.org/2015/1142.pdf
     *
     * {a, b, c, d} -> {aout, bout, cout, dout} where a/aout is the MSB.
     *
     * aout = NAND(NAND(~c, NAND(a, b)), (a | d))
     * bout = NAND(NOR(NOR(a, d), (b & c)), NAND((a & c), d))
     * cout = NAND(NAND(b, d), (NOR(b, d) | a))
     * dout = NOR(NOR(a, (b | c)), NAND(NAND(a, b), (c | d)))
     */
    SkinnyVector8x16_t a = (d >> 3);
    SkinnyVector8x16_t b = (d >> 2);
    SkinnyVector8x16_t c = (d >> 1);
    SkinnyVector8x16_t not_a = ~a;
    SkinnyVector8x16_t ab = not_a | (~b);
    SkinnyVector8x16_t ad = not_a & (~d);
    SkinnyVector8x16_t aout = (((~c) & ab) | ad);
    SkinnyVector8x16_t bout = ad | (b & c) | (a & c & d);
    SkinnyVector8x16_t cout = (b & d) | ((b | d) & not_a);
    SkinnyVector8x16_t dout = (a | b | c) & ab & (c | d);
    return ((aout & 0x1111U) << 3) | ((bout & 0x1111U) << 2) |
           ((cout & 0x1111U) << 1) |  (dout & 0x1111U);
}

STATIC_INLINE void mantis_update_tweak(MantisCells_t *tweak)
{
    /* h = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11] */
    uint16_t row1 = tweak->row[1];
    uint16_t row3 = tweak->row[3];
    tweak->row[1] = tweak->row[0];
    tweak->row[3] = tweak->row[2];
    tweak->row[0] = ((row1 >>  8) & 0x00F0U) |
                     (row1        & 0x000FU) |
                     (row3        & 0xFF00U);
    tweak->row[2] = ((row1 <<  4) & 0x0F00U) |
                    ((row1 >>  4) & 0x00F0U) |
                    ((row3 >>  4) & 0x000FU) |
                    ((row3 << 12) & 0xF000U);
}

STATIC_INLINE void mantis_update_tweak_inverse(MantisCells_t *tweak)
{
    /* h' = [4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3] */
    uint16_t row0 = tweak->row[0];
    uint16_t row2 = tweak->row[2];
    tweak->row[0] = tweak->row[1];
    tweak->row[2] = tweak->row[3];
    tweak->row[1] = ((row2 >>  4) & 0x00F0U) |
                    ((row2 <<  4) & 0x0F00U) |
                     (row0        & 0x000FU) |
                    ((row0 <<  8) & 0xF000U);
    tweak->row[3] =  (row0        & 0xFF00U) |
                    ((row2 <<  4) & 0x00F0U) |
                    ((row2 >> 12) & 0x000FU);
}

STATIC_INLINE void mantis_shift_rows(MantisVectorCells_t *state)
{
    /* P = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2] */
    SkinnyVector8x16_t row0 = state->row[0];
    SkinnyVector8x16_t row1 = state->row[1];
    SkinnyVector8x16_t row2 = state->row[2];
    SkinnyVector8x16_t row3 = state->row[3];
    state->row[0] =  (row0        & 0x00F0U) |
                     (row1        & 0xF000U) |
                    ((row2 >>  8) & 0x000FU) |
                    ((row3 <<  8) & 0x0F00U);
    state->row[1] =  (row0        & 0x000FU) |
                     (row1        & 0x0F00U) |
                    ((row2 >>  8) & 0x00F0U) |
                    ((row3 <<  8) & 0xF000U);
    state->row[2] = ((row0 <<  4) & 0xF000U) |
                    ((row1 <<  4) & 0x00F0U) |
                    ((row2 <<  4) & 0x0F00U) |
                    ((row3 >> 12) & 0x000FU);
    state->row[3] = ((row0 >>  4) & 0x0F00U) |
                    ((row1 >>  4) & 0x000FU) |
                    ((row2 << 12) & 0xF000U) |
                    ((row3 >>  4) & 0x00F0U);
}

STATIC_INLINE void mantis_shift_rows_inverse(MantisVectorCells_t *state)
{
    /* P' = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12] */
    SkinnyVector8x16_t row0 = state->row[0];
    SkinnyVector8x16_t row1 = state->row[1];
    SkinnyVector8x16_t row2 = state->row[2];
    SkinnyVector8x16_t row3 = state->row[3];
    state->row[0] =  (row0        & 0x00F0U) |
                     (row1        & 0x000FU) |
                    ((row2 >>  4) & 0x0F00U) |
                    ((row3 <<  4) & 0xF000U);
    state->row[1] =  (row0        & 0xF000U) |
                     (row1        & 0x0F00U) |
                    ((row2 >>  4) & 0x000FU) |
                    ((row3 <<  4) & 0x00F0U);
    state->row[2] = ((row0 <<  8) & 0x0F00U) |
                    ((row1 <<  8) & 0xF000U) |
                    ((row2 >>  4) & 0x00F0U) |
                    ((row3 >> 12) & 0x000FU);
    state->row[3] = ((row0 >>  8) & 0x000FU) |
                    ((row1 >>  8) & 0x00F0U) |
                    ((row2 << 12) & 0xF000U) |
                    ((row3 <<  4) & 0x0F00U);
}

STATIC_INLINE void mantis_mix_columns(MantisVectorCells_t *state)
{
    SkinnyVector8x16_t t0 = state->row[0];
    SkinnyVector8x16_t t1 = state->row[1];
    SkinnyVector8x16_t t2 = state->row[2];
    SkinnyVector8x16_t t3 = state->row[3];
    state->row[0] = t1 ^ t2 ^ t3;
    state->row[1] = t0 ^ t2 ^ t3;
    state->row[2] = t0 ^ t1 ^ t3;
    state->row[3] = t0 ^ t1 ^ t2;
}

/* Extract the 16 bits for a row from a 64-bit round constant */
#define RC_EXTRACT_ROW(x,shift) \
    (((((uint16_t)((x) >> ((shift) + 8))) & 0xFF)) | \
     ((((uint16_t)((x) >> ((shift))))     & 0xFF) << 8))

/* Extract the rows from a 64-bit round constant */
#define RC(x)    \
    {RC_EXTRACT_ROW((x), 48), RC_EXTRACT_ROW((x), 32), \
     RC_EXTRACT_ROW((x), 16), RC_EXTRACT_ROW((x), 0)}

/* Alpha constant for adjusting k1 for the inverse rounds */
#define ALPHA      0x243F6A8885A308D3ULL
#define ALPHA_ROW0 (RC_EXTRACT_ROW(ALPHA, 48))
#define ALPHA_ROW1 (RC_EXTRACT_ROW(ALPHA, 32))
#define ALPHA_ROW2 (RC_EXTRACT_ROW(ALPHA, 16))
#define ALPHA_ROW3 (RC_EXTRACT_ROW(ALPHA, 0))

/* Round constants for Mantis, split up into 16-bit row values */
static uint16_t const rc[MANTIS_MAX_ROUNDS][4] = {
    RC(0x13198A2E03707344ULL),
    RC(0xA4093822299F31D0ULL),
    RC(0x082EFA98EC4E6C89ULL),
    RC(0x452821E638D01377ULL),
    RC(0xBE5466CF34E90C6CULL),
    RC(0xC0AC29B7C97C50DDULL),
    RC(0x3F84D5B5B5470917ULL),
    RC(0x9216D5D98979FB1BULL)
};

static void mantis_ecb_encrypt_eight
    (void *output, const SkinnyVector8x16_t *input, const MantisKey_t *ks)
{
    const uint16_t *r = rc[0];
    MantisCells_t tweak = ks->tweak;
    MantisCells_t k1 = ks->k1;
    MantisVectorCells_t state;
    unsigned index;

    /* Read the rows of all eight counter blocks into memory */
    state.row[0] = input[0];
    state.row[1] = input[1];
    state.row[2] = input[2];
    state.row[3] = input[3];

    /* XOR the initial whitening key k0 with the state,
       together with k1 and the initial tweak value */
    state.row[0] ^= ks->k0.row[0] ^ k1.row[0] ^ tweak.row[0];
    state.row[1] ^= ks->k0.row[1] ^ k1.row[1] ^ tweak.row[1];
    state.row[2] ^= ks->k0.row[2] ^ k1.row[2] ^ tweak.row[2];
    state.row[3] ^= ks->k0.row[3] ^ k1.row[3] ^ tweak.row[3];

    /* Perform all forward rounds */
    for (index = ks->rounds; index > 0; --index) {
        /* Update the tweak with the forward h function */
        mantis_update_tweak(&tweak);

        /* Apply the S-box */
        state.row[0] = mantis_sbox(state.row[0]);
        state.row[1] = mantis_sbox(state.row[1]);
        state.row[2] = mantis_sbox(state.row[2]);
        state.row[3] = mantis_sbox(state.row[3]);

        /* Add the round constant */
        state.row[0] ^= r[0];
        state.row[1] ^= r[1];
        state.row[2] ^= r[2];
        state.row[3] ^= r[3];
        r += 4;

        /* XOR with the key and tweak */
        state.row[0] ^= k1.row[0] ^ tweak.row[0];
        state.row[1] ^= k1.row[1] ^ tweak.row[1];
        state.row[2] ^= k1.row[2] ^ tweak.row[2];
        state.row[3] ^= k1.row[3] ^ tweak.row[3];

        /* Shift the rows */
        mantis_shift_rows(&state);

        /* Mix the columns */
        mantis_mix_columns(&state);
    }

    /* Half-way there: sbox, mix, sbox */
    state.row[0] = mantis_sbox(state.row[0]);
    state.row[1] = mantis_sbox(state.row[1]);
    state.row[2] = mantis_sbox(state.row[2]);
    state.row[3] = mantis_sbox(state.row[3]);
    mantis_mix_columns(&state);
    state.row[0] = mantis_sbox(state.row[0]);
    state.row[1] = mantis_sbox(state.row[1]);
    state.row[2] = mantis_sbox(state.row[2]);
    state.row[3] = mantis_sbox(state.row[3]);

    /* Convert k1 into k1 XOR alpha for the reverse rounds */
    k1.row[0] ^= ALPHA_ROW0;
    k1.row[1] ^= ALPHA_ROW1;
    k1.row[2] ^= ALPHA_ROW2;
    k1.row[3] ^= ALPHA_ROW3;

    /* Perform all reverse rounds */
    for (index = ks->rounds; index > 0; --index) {
        /* Inverse mix of the columns (same as the forward mix) */
        mantis_mix_columns(&state);

        /* Inverse shift of the rows */
        mantis_shift_rows_inverse(&state);

        /* XOR with the key and tweak */
        state.row[0] ^= k1.row[0] ^ tweak.row[0];
        state.row[1] ^= k1.row[1] ^ tweak.row[1];
        state.row[2] ^= k1.row[2] ^ tweak.row[2];
        state.row[3] ^= k1.row[3] ^ tweak.row[3];

        /* Add the round constant */
        r -= 4;
        state.row[0] ^= r[0];
        state.row[1] ^= r[1];
        state.row[2] ^= r[2];
        state.row[3] ^= r[3];

        /* Apply the inverse S-box (which is the same as the forward S-box) */
        state.row[0] = mantis_sbox(state.row[0]);
        state.row[1] = mantis_sbox(state.row[1]);
        state.row[2] = mantis_sbox(state.row[2]);
        state.row[3] = mantis_sbox(state.row[3]);

        /* Update the tweak with the reverse h function */
        mantis_update_tweak_inverse(&tweak);
    }

    /* XOR the final whitening key k0prime with the state,
       together with k1alpha and the final tweak value */
    state.row[0] ^= ks->k0prime.row[0] ^ k1.row[0] ^ tweak.row[0];
    state.row[1] ^= ks->k0prime.row[1] ^ k1.row[1] ^ tweak.row[1];
    state.row[2] ^= ks->k0prime.row[2] ^ k1.row[2] ^ tweak.row[2];
    state.row[3] ^= ks->k0prime.row[3] ^ k1.row[3] ^ tweak.row[3];

    /* Write the rows of all eight blocks back to memory.
       Note: In this case, direct WRITE_WORD16() calls seem to give
       better performance than rearranging the vectors and performing
       an unaligned vector write */
#if 0 /* SKINNY_LITTLE_ENDIAN && SKINNY_UNALIGNED */
    *((SkinnyVector8x16U_t *)output) =
        (SkinnyVector8x16_t){state.row[0][0], state.row[1][0],
                             state.row[2][0], state.row[3][0],
                             state.row[0][1], state.row[1][1],
                             state.row[2][1], state.row[3][1]};
    *((SkinnyVector8x16U_t *)(output + 16)) =
        (SkinnyVector8x16_t){state.row[0][2], state.row[1][2],
                             state.row[2][2], state.row[3][2],
                             state.row[0][3], state.row[1][3],
                             state.row[2][3], state.row[3][3]};
    *((SkinnyVector8x16U_t *)(output + 32)) =
        (SkinnyVector8x16_t){state.row[0][4], state.row[1][4],
                             state.row[2][4], state.row[3][4],
                             state.row[0][5], state.row[1][5],
                             state.row[2][5], state.row[3][5]};
    *((SkinnyVector8x16U_t *)(output + 48)) =
        (SkinnyVector8x16_t){state.row[0][6], state.row[1][6],
                             state.row[2][6], state.row[3][6],
                             state.row[0][7], state.row[1][7],
                             state.row[2][7], state.row[3][7]};
#else
    WRITE_WORD16(output,  0, state.row[0][0]);
    WRITE_WORD16(output,  2, state.row[1][0]);
    WRITE_WORD16(output,  4, state.row[2][0]);
    WRITE_WORD16(output,  6, state.row[3][0]);
    WRITE_WORD16(output,  8, state.row[0][1]);
    WRITE_WORD16(output, 10, state.row[1][1]);
    WRITE_WORD16(output, 12, state.row[2][1]);
    WRITE_WORD16(output, 14, state.row[3][1]);
    WRITE_WORD16(output, 16, state.row[0][2]);
    WRITE_WORD16(output, 18, state.row[1][2]);
    WRITE_WORD16(output, 20, state.row[2][2]);
    WRITE_WORD16(output, 22, state.row[3][2]);
    WRITE_WORD16(output, 24, state.row[0][3]);
    WRITE_WORD16(output, 26, state.row[1][3]);
    WRITE_WORD16(output, 28, state.row[2][3]);
    WRITE_WORD16(output, 30, state.row[3][3]);
    WRITE_WORD16(output, 32, state.row[0][4]);
    WRITE_WORD16(output, 34, state.row[1][4]);
    WRITE_WORD16(output, 36, state.row[2][4]);
    WRITE_WORD16(output, 38, state.row[3][4]);
    WRITE_WORD16(output, 40, state.row[0][5]);
    WRITE_WORD16(output, 42, state.row[1][5]);
    WRITE_WORD16(output, 44, state.row[2][5]);
    WRITE_WORD16(output, 46, state.row[3][5]);
    WRITE_WORD16(output, 48, state.row[0][6]);
    WRITE_WORD16(output, 50, state.row[1][6]);
    WRITE_WORD16(output, 52, state.row[2][6]);
    WRITE_WORD16(output, 54, state.row[3][6]);
    WRITE_WORD16(output, 56, state.row[0][7]);
    WRITE_WORD16(output, 58, state.row[1][7]);
    WRITE_WORD16(output, 60, state.row[2][7]);
    WRITE_WORD16(output, 62, state.row[3][7]);
#endif
}

static int mantis_ctr_vec128_encrypt
    (void *output, const void *input, size_t size, MantisCTR_t *ctr)
{
    MantisCTRVec128Ctx_t *ctx;
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
        if (ctx->offset >= MANTIS_CTR_BLOCK_SIZE) {
            /* We need a new keystream block */
            mantis_ecb_encrypt_eight(ctx->ecounter, ctx->counter, &(ctx->ks));
            mantis_ctr_increment(ctx->counter, 0, 8);
            mantis_ctr_increment(ctx->counter, 1, 8);
            mantis_ctr_increment(ctx->counter, 2, 8);
            mantis_ctr_increment(ctx->counter, 3, 8);
            mantis_ctr_increment(ctx->counter, 4, 8);
            mantis_ctr_increment(ctx->counter, 5, 8);
            mantis_ctr_increment(ctx->counter, 6, 8);
            mantis_ctr_increment(ctx->counter, 7, 8);

            /* XOR an entire keystream block in one go if possible */
            if (size >= MANTIS_CTR_BLOCK_SIZE) {
                skinny64_xor(out, in, ctx->ecounter);
                skinny64_xor(out + MANTIS_BLOCK_SIZE,
                             in + MANTIS_BLOCK_SIZE,
                             ctx->ecounter + MANTIS_BLOCK_SIZE);
                skinny64_xor(out + MANTIS_BLOCK_SIZE * 2,
                             in + MANTIS_BLOCK_SIZE * 2,
                             ctx->ecounter + MANTIS_BLOCK_SIZE * 2);
                skinny64_xor(out + MANTIS_BLOCK_SIZE * 3,
                             in + MANTIS_BLOCK_SIZE * 3,
                             ctx->ecounter + MANTIS_BLOCK_SIZE * 3);
                skinny64_xor(out + MANTIS_BLOCK_SIZE * 4,
                             in + MANTIS_BLOCK_SIZE * 4,
                             ctx->ecounter + MANTIS_BLOCK_SIZE * 4);
                skinny64_xor(out + MANTIS_BLOCK_SIZE * 5,
                             in + MANTIS_BLOCK_SIZE * 5,
                             ctx->ecounter + MANTIS_BLOCK_SIZE * 5);
                skinny64_xor(out + MANTIS_BLOCK_SIZE * 6,
                             in + MANTIS_BLOCK_SIZE * 6,
                             ctx->ecounter + MANTIS_BLOCK_SIZE * 6);
                skinny64_xor(out + MANTIS_BLOCK_SIZE * 7,
                             in + MANTIS_BLOCK_SIZE * 7,
                             ctx->ecounter + MANTIS_BLOCK_SIZE * 7);
                out += MANTIS_CTR_BLOCK_SIZE;
                in += MANTIS_CTR_BLOCK_SIZE;
                size -= MANTIS_CTR_BLOCK_SIZE;
            } else {
                /* Last partial block in the request */
                skinny_xor(out, in, ctx->ecounter, size);
                ctx->offset = size;
                break;
            }
        } else {
            /* Left-over keystream data from the last request */
            size_t temp = MANTIS_CTR_BLOCK_SIZE - ctx->offset;
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

/** Vtable for the 128-bit SIMD Mantis-CTR implementation */
MantisCTRVtable_t const _mantis_ctr_vec128 = {
    mantis_ctr_vec128_init,
    mantis_ctr_vec128_cleanup,
    mantis_ctr_vec128_set_key,
    mantis_ctr_vec128_set_tweak,
    mantis_ctr_vec128_set_counter,
    mantis_ctr_vec128_encrypt
};

#else /* !SKINNY_VEC128_MATH */

/* Stubbed out */
MantisCTRVtable_t const _mantis_ctr_vec128;

#endif /* SKINNY_VEC128_MATH */
