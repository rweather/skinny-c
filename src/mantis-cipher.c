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
#include "skinny-internal.h"

#if SKINNY_64BIT && SKINNY_LITTLE_ENDIAN

/* Size of each RC row value in bits */
#define RC_ROW_SIZE 64

/* Swap the bits in an RC constant to convert into host-endian */
#define RC(x) \
    (((((uint64_t)((x) >> 56)) & 0xFF)) | \
     ((((uint64_t)((x) >> 48)) & 0xFF) <<  8) | \
     ((((uint64_t)((x) >> 40)) & 0xFF) << 16) | \
     ((((uint64_t)((x) >> 32)) & 0xFF) << 24) | \
     ((((uint64_t)((x) >> 24)) & 0xFF) << 32) | \
     ((((uint64_t)((x) >> 16)) & 0xFF) << 40) | \
     ((((uint64_t)((x) >>  8)) & 0xFF) << 48) | \
     ((((uint64_t)((x)      )) & 0xFF) << 56))

/* Alpha constant for adjusting k1 for the inverse rounds */
#define ALPHA      (RC(0x243F6A8885A308D3ULL))

/* Round constants for Mantis, split up into 64-bit row values */
static uint64_t const rc[MANTIS_MAX_ROUNDS] = {
    RC(0x13198A2E03707344ULL),
    RC(0xA4093822299F31D0ULL),
    RC(0x082EFA98EC4E6C89ULL),
    RC(0x452821E638D01377ULL),
    RC(0xBE5466CF34E90C6CULL),
    RC(0xC0AC29B7C97C50DDULL),
    RC(0x3F84D5B5B5470917ULL),
    RC(0x9216D5D98979FB1BULL)
};

#elif SKINNY_LITTLE_ENDIAN

/* Size of each RC row value in bits */
#define RC_ROW_SIZE 32

/* Extract the 32 bits for a row from a 64-bit round constant */
#define RC_EXTRACT_ROW(x,shift) \
    (((((uint32_t)((x) >> ((shift) + 24))) & 0xFF)) | \
     ((((uint32_t)((x) >> ((shift) + 16))) & 0xFF) <<  8) | \
     ((((uint32_t)((x) >> ((shift) +  8))) & 0xFF) << 16) | \
     ((((uint32_t)((x) >> ((shift))))      & 0xFF) << 24))

/* Extract the rows from a 64-bit round constant */
#define RC(x)    \
    {RC_EXTRACT_ROW((x), 32), RC_EXTRACT_ROW((x), 0)}

/* Alpha constant for adjusting k1 for the inverse rounds */
#define ALPHA      0x243F6A8885A308D3ULL
#define ALPHA_ROW0 (RC_EXTRACT_ROW(ALPHA, 32))
#define ALPHA_ROW1 (RC_EXTRACT_ROW(ALPHA, 0))

/* Round constants for Mantis, split up into 32-bit row values */
static uint32_t const rc[MANTIS_MAX_ROUNDS][2] = {
    RC(0x13198A2E03707344ULL),
    RC(0xA4093822299F31D0ULL),
    RC(0x082EFA98EC4E6C89ULL),
    RC(0x452821E638D01377ULL),
    RC(0xBE5466CF34E90C6CULL),
    RC(0xC0AC29B7C97C50DDULL),
    RC(0x3F84D5B5B5470917ULL),
    RC(0x9216D5D98979FB1BULL)
};

#else

/* Size of each RC row value in bits */
#define RC_ROW_SIZE 16

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

#endif

STATIC_INLINE void mantis_unpack_block
    (MantisCells_t *block, const uint8_t *buf, unsigned offset)
{
#if SKINNY_LITTLE_ENDIAN
    block->lrow[0] = READ_WORD32(buf, offset);
    block->lrow[1] = READ_WORD32(buf, offset + 4);
#else
    block->row[0] = READ_WORD16(buf, offset);
    block->row[1] = READ_WORD16(buf, offset + 2);
    block->row[2] = READ_WORD16(buf, offset + 4);
    block->row[3] = READ_WORD16(buf, offset + 6);
#endif
}

STATIC_INLINE void mantis_unpack_rotated_block
    (MantisCells_t *block, const uint8_t *buf)
{
    uint8_t rotated[MANTIS_BLOCK_SIZE];
    unsigned index;
    uint8_t next;
    uint8_t carry = buf[MANTIS_BLOCK_SIZE - 1];
    for (index = 0; index < MANTIS_BLOCK_SIZE; ++index) {
        next = buf[index];
        rotated[index] = (carry << 7) | (next >> 1);
        carry = next;
    }
    rotated[MANTIS_BLOCK_SIZE - 1] ^= (buf[0] >> 7);
    mantis_unpack_block(block, rotated, 0);
}

int mantis_set_key
    (MantisKey_t *ks, const void *key, unsigned size,
     unsigned rounds, int mode)
{
    /* Validate the parameters */
    if (!ks || !key || size != MANTIS_KEY_SIZE ||
            rounds < MANTIS_MIN_ROUNDS ||
            rounds > MANTIS_MAX_ROUNDS)
        return 0;

    /* Set the round count */
    ks->rounds = rounds;

    /* Set up the encryption or decryption key */
    if (mode == MANTIS_ENCRYPT) {
        /* Encryption */
        mantis_unpack_block(&(ks->k0), key, 0);
        mantis_unpack_block(&(ks->k1), key, 8);
        mantis_unpack_rotated_block(&(ks->k0prime), key);
    } else {
        /* Decryption */
        mantis_unpack_rotated_block(&(ks->k0), key);
        mantis_unpack_block(&(ks->k0prime), key, 0);
        mantis_unpack_block(&(ks->k1), key, 8);
#if RC_ROW_SIZE == 64
        ks->k1.llrow ^= ALPHA;
#elif RC_ROW_SIZE == 32
        ks->k1.lrow[0] ^= ALPHA_ROW0;
        ks->k1.lrow[1] ^= ALPHA_ROW1;
#else
        ks->k1.row[0] ^= ALPHA_ROW0;
        ks->k1.row[1] ^= ALPHA_ROW1;
        ks->k1.row[2] ^= ALPHA_ROW2;
        ks->k1.row[3] ^= ALPHA_ROW3;
#endif
    }

    /* Set up the default tweak of zero */
#if SKINNY_64BIT
    ks->tweak.llrow = 0;
#else
    ks->tweak.lrow[0] = 0;
    ks->tweak.lrow[1] = 0;
#endif

    /* Ready to go */
    return 1;
}

int mantis_set_tweak(MantisKey_t *ks, const void *tweak, unsigned size)
{
    /* Validate the parameters */
    if (!ks || size != MANTIS_TWEAK_SIZE)
        return 0;

    /* Set up the new tweak */
    if (tweak) {
        mantis_unpack_block(&(ks->tweak), tweak, 0);
    } else {
#if SKINNY_64BIT
        ks->tweak.llrow = 0;
#else
        ks->tweak.lrow[0] = 0;
        ks->tweak.lrow[1] = 0;
#endif
    }
    return 1;
}

void mantis_swap_modes(MantisKey_t *ks)
{
    /* Swap k0 with k0prime */
    MantisCells_t tmp = ks->k0;
    ks->k0 = ks->k0prime;
    ks->k0prime = tmp;

    /* XOR k1 with the alpha constant */
#if RC_ROW_SIZE == 64
    ks->k1.llrow ^= ALPHA;
#elif RC_ROW_SIZE == 32
    ks->k1.lrow[0] ^= ALPHA_ROW0;
    ks->k1.lrow[1] ^= ALPHA_ROW1;
#else
    ks->k1.row[0] ^= ALPHA_ROW0;
    ks->k1.row[1] ^= ALPHA_ROW1;
    ks->k1.row[2] ^= ALPHA_ROW2;
    ks->k1.row[3] ^= ALPHA_ROW3;
#endif
}

#if SKINNY_64BIT

STATIC_INLINE uint64_t mantis_sbox(uint64_t d)
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
    uint64_t a = (d >> 3);
    uint64_t b = (d >> 2);
    uint64_t c = (d >> 1);
    uint64_t not_a = ~a;
    uint64_t ab = not_a | (~b);
    uint64_t ad = not_a & (~d);
    uint64_t aout = (((~c) & ab) | ad);
    uint64_t bout = ad | (b & c) | (a & c & d);
    uint64_t cout = (b & d) | ((b | d) & not_a);
    uint64_t dout = (a | b | c) & ab & (c | d);
    return ((aout & 0x1111111111111111U) << 3) |
           ((bout & 0x1111111111111111U) << 2) |
           ((cout & 0x1111111111111111U) << 1) |
            (dout & 0x1111111111111111U);
}

#else

STATIC_INLINE uint32_t mantis_sbox(uint32_t d)
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
    uint32_t a = (d >> 3);
    uint32_t b = (d >> 2);
    uint32_t c = (d >> 1);
    uint32_t not_a = ~a;
    uint32_t ab = not_a | (~b);
    uint32_t ad = not_a & (~d);
    uint32_t aout = (((~c) & ab) | ad);
    uint32_t bout = ad | (b & c) | (a & c & d);
    uint32_t cout = (b & d) | ((b | d) & not_a);
    uint32_t dout = (a | b | c) & ab & (c | d);
    return ((aout & 0x11111111U) << 3) | ((bout & 0x11111111U) << 2) |
           ((cout & 0x11111111U) << 1) |  (dout & 0x11111111U);
}

#endif

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

STATIC_INLINE void mantis_shift_rows(MantisCells_t *state)
{
    /* P = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2] */
    uint16_t row0 = state->row[0];
    uint16_t row1 = state->row[1];
    uint16_t row2 = state->row[2];
    uint16_t row3 = state->row[3];
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

STATIC_INLINE void mantis_shift_rows_inverse(MantisCells_t *state)
{
    /* P' = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12] */
    uint16_t row0 = state->row[0];
    uint16_t row1 = state->row[1];
    uint16_t row2 = state->row[2];
    uint16_t row3 = state->row[3];
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

STATIC_INLINE void mantis_mix_columns(MantisCells_t *state)
{
    uint16_t t0 = state->row[0];
    uint16_t t1 = state->row[1];
    uint16_t t2 = state->row[2];
    uint16_t t3 = state->row[3];
    state->row[0] = t1 ^ t2 ^ t3;
    state->row[1] = t0 ^ t2 ^ t3;
    state->row[2] = t0 ^ t1 ^ t3;
    state->row[3] = t0 ^ t1 ^ t2;
}

void mantis_ecb_crypt(void *output, const void *input, const MantisKey_t *ks)
{
#if RC_ROW_SIZE == 64
    const uint64_t *r = &(rc[0]);
#elif RC_ROW_SIZE == 32
    const uint32_t *r = rc[0];
#else
    const uint16_t *r = rc[0];
#endif
    MantisCells_t tweak = ks->tweak;
    MantisCells_t k1 = ks->k1;
    MantisCells_t state;
    unsigned index;

    /* Read the input buffer and convert little-endian to host-endian */
#if SKINNY_64BIT && SKINNY_LITTLE_ENDIAN
    state.llrow = READ_WORD64(input, 0);
#elif SKINNY_LITTLE_ENDIAN
    state.lrow[0] = READ_WORD32(input, 0);
    state.lrow[1] = READ_WORD32(input, 4);
#else
    state.row[0] = READ_WORD16(input, 0);
    state.row[1] = READ_WORD16(input, 2);
    state.row[2] = READ_WORD16(input, 4);
    state.row[3] = READ_WORD16(input, 6);
#endif

    /* XOR the initial whitening key k0 with the state,
       together with k1 and the initial tweak value */
#if SKINNY_64BIT
    state.llrow ^= ks->k0.llrow ^ k1.llrow ^ tweak.llrow;
#else
    state.lrow[0] ^= ks->k0.lrow[0] ^ k1.lrow[0] ^ tweak.lrow[0];
    state.lrow[1] ^= ks->k0.lrow[1] ^ k1.lrow[1] ^ tweak.lrow[1];
#endif

    /* Perform all forward rounds */
    for (index = ks->rounds; index > 0; --index) {
        /* Update the tweak with the forward h function */
        mantis_update_tweak(&tweak);

        /* Apply the S-box */
#if SKINNY_64BIT
        state.llrow = mantis_sbox(state.llrow);
#else
        state.lrow[0] = mantis_sbox(state.lrow[0]);
        state.lrow[1] = mantis_sbox(state.lrow[1]);
#endif

        /* Add the round constant */
#if RC_ROW_SIZE == 64
        state.llrow ^= r[0];
        ++r;
#elif RC_ROW_SIZE == 32
        state.lrow[0] ^= r[0];
        state.lrow[1] ^= r[1];
        r += 2;
#else
        state.row[0] ^= r[0];
        state.row[1] ^= r[1];
        state.row[2] ^= r[2];
        state.row[3] ^= r[3];
        r += 4;
#endif

        /* XOR with the key and tweak */
#if SKINNY_64BIT
        state.llrow ^= k1.llrow ^ tweak.llrow;
#else
        state.lrow[0] ^= k1.lrow[0] ^ tweak.lrow[0];
        state.lrow[1] ^= k1.lrow[1] ^ tweak.lrow[1];
#endif

        /* Shift the rows */
        mantis_shift_rows(&state);

        /* Mix the columns */
        mantis_mix_columns(&state);
    }

    /* Half-way there: sbox, mix, sbox */
#if SKINNY_64BIT
    state.llrow = mantis_sbox(state.llrow);
    mantis_mix_columns(&state);
    state.llrow = mantis_sbox(state.llrow);
#else
    state.lrow[0] = mantis_sbox(state.lrow[0]);
    state.lrow[1] = mantis_sbox(state.lrow[1]);
    mantis_mix_columns(&state);
    state.lrow[0] = mantis_sbox(state.lrow[0]);
    state.lrow[1] = mantis_sbox(state.lrow[1]);
#endif

    /* Convert k1 into k1 XOR alpha for the reverse rounds */
#if RC_ROW_SIZE == 64
    k1.llrow ^= ALPHA;
#elif RC_ROW_SIZE == 32
    k1.lrow[0] ^= ALPHA_ROW0;
    k1.lrow[1] ^= ALPHA_ROW1;
#else
    k1.row[0] ^= ALPHA_ROW0;
    k1.row[1] ^= ALPHA_ROW1;
    k1.row[2] ^= ALPHA_ROW2;
    k1.row[3] ^= ALPHA_ROW3;
#endif

    /* Perform all reverse rounds */
    for (index = ks->rounds; index > 0; --index) {
        /* Inverse mix of the columns (same as the forward mix) */
        mantis_mix_columns(&state);

        /* Inverse shift of the rows */
        mantis_shift_rows_inverse(&state);

        /* XOR with the key and tweak */
#if SKINNY_64BIT
        state.llrow ^= k1.llrow ^ tweak.llrow;
#else
        state.lrow[0] ^= k1.lrow[0] ^ tweak.lrow[0];
        state.lrow[1] ^= k1.lrow[1] ^ tweak.lrow[1];
#endif

        /* Add the round constant */
#if RC_ROW_SIZE == 64
        --r;
        state.llrow ^= r[0];
#elif RC_ROW_SIZE == 32
        r -= 2;
        state.lrow[0] ^= r[0];
        state.lrow[1] ^= r[1];
#else
        r -= 4;
        state.row[0] ^= r[0];
        state.row[1] ^= r[1];
        state.row[2] ^= r[2];
        state.row[3] ^= r[3];
#endif

        /* Apply the inverse S-box (which is the same as the forward S-box) */
#if SKINNY_64BIT
        state.llrow = mantis_sbox(state.llrow);
#else
        state.lrow[0] = mantis_sbox(state.lrow[0]);
        state.lrow[1] = mantis_sbox(state.lrow[1]);
#endif

        /* Update the tweak with the reverse h function */
        mantis_update_tweak_inverse(&tweak);
    }

    /* XOR the final whitening key k0prime with the state,
       together with k1alpha and the final tweak value */
#if SKINNY_64BIT
    state.llrow ^= ks->k0prime.llrow ^ k1.llrow ^ tweak.llrow;
#else
    state.lrow[0] ^= ks->k0prime.lrow[0] ^ k1.lrow[0] ^ tweak.lrow[0];
    state.lrow[1] ^= ks->k0prime.lrow[1] ^ k1.lrow[1] ^ tweak.lrow[1];
#endif

    /* Convert host-endian back into little-endian in the output buffer */
#if SKINNY_64BIT && SKINNY_LITTLE_ENDIAN
    WRITE_WORD64(output, 0, state.llrow);
#elif SKINNY_LITTLE_ENDIAN
    WRITE_WORD32(output, 0, state.lrow[0]);
    WRITE_WORD32(output, 4, state.lrow[1]);
#else
    WRITE_WORD16(output, 0, state.row[0]);
    WRITE_WORD16(output, 2, state.row[1]);
    WRITE_WORD16(output, 4, state.row[2]);
    WRITE_WORD16(output, 6, state.row[3]);
#endif
}

void mantis_ecb_crypt_tweaked
    (void *output, const void *input, const void *tweak, const MantisKey_t *ks)
{
#if RC_ROW_SIZE == 64
    const uint64_t *r = &(rc[0]);
#elif RC_ROW_SIZE == 32
    const uint32_t *r = rc[0];
#else
    const uint16_t *r = rc[0];
#endif
    MantisCells_t tk;
    MantisCells_t k1 = ks->k1;
    MantisCells_t state;
    unsigned index;

    /* Read the input and tweak and convert little-endian to host-endian */
#if SKINNY_64BIT && SKINNY_LITTLE_ENDIAN
    state.llrow = READ_WORD64(input, 0);
    tk.llrow = READ_WORD64(tweak, 0);
#elif SKINNY_LITTLE_ENDIAN
    state.lrow[0] = READ_WORD32(input, 0);
    state.lrow[1] = READ_WORD32(input, 4);
    tk.lrow[0] = READ_WORD32(tweak, 0);
    tk.lrow[1] = READ_WORD32(tweak, 4);
#else
    state.row[0] = READ_WORD16(input, 0);
    state.row[1] = READ_WORD16(input, 2);
    state.row[2] = READ_WORD16(input, 4);
    state.row[3] = READ_WORD16(input, 6);
    tk.row[0] = READ_WORD16(tweak, 0);
    tk.row[1] = READ_WORD16(tweak, 2);
    tk.row[2] = READ_WORD16(tweak, 4);
    tk.row[3] = READ_WORD16(tweak, 6);
#endif

    /* XOR the initial whitening key k0 with the state,
       together with k1 and the initial tweak value */
#if SKINNY_64BIT
    state.llrow ^= ks->k0.llrow ^ k1.llrow ^ tk.llrow;
#else
    state.lrow[0] ^= ks->k0.lrow[0] ^ k1.lrow[0] ^ tk.lrow[0];
    state.lrow[1] ^= ks->k0.lrow[1] ^ k1.lrow[1] ^ tk.lrow[1];
#endif

    /* Perform all forward rounds */
    for (index = ks->rounds; index > 0; --index) {
        /* Update the tweak with the forward h function */
        mantis_update_tweak(&tk);

        /* Apply the S-box */
#if SKINNY_64BIT
        state.llrow = mantis_sbox(state.llrow);
#else
        state.lrow[0] = mantis_sbox(state.lrow[0]);
        state.lrow[1] = mantis_sbox(state.lrow[1]);
#endif

        /* Add the round constant */
#if RC_ROW_SIZE == 64
        state.llrow ^= r[0];
        ++r;
#elif RC_ROW_SIZE == 32
        state.lrow[0] ^= r[0];
        state.lrow[1] ^= r[1];
        r += 2;
#else
        state.row[0] ^= r[0];
        state.row[1] ^= r[1];
        state.row[2] ^= r[2];
        state.row[3] ^= r[3];
        r += 4;
#endif

        /* XOR with the key and tweak */
#if SKINNY_64BIT
        state.llrow ^= k1.llrow ^ tk.llrow;
#else
        state.lrow[0] ^= k1.lrow[0] ^ tk.lrow[0];
        state.lrow[1] ^= k1.lrow[1] ^ tk.lrow[1];
#endif

        /* Shift the rows */
        mantis_shift_rows(&state);

        /* Mix the columns */
        mantis_mix_columns(&state);
    }

    /* Half-way there: sbox, mix, sbox */
#if SKINNY_64BIT
    state.llrow = mantis_sbox(state.llrow);
    mantis_mix_columns(&state);
    state.llrow = mantis_sbox(state.llrow);
#else
    state.lrow[0] = mantis_sbox(state.lrow[0]);
    state.lrow[1] = mantis_sbox(state.lrow[1]);
    mantis_mix_columns(&state);
    state.lrow[0] = mantis_sbox(state.lrow[0]);
    state.lrow[1] = mantis_sbox(state.lrow[1]);
#endif

    /* Convert k1 into k1 XOR alpha for the reverse rounds */
#if RC_ROW_SIZE == 64
    k1.llrow ^= ALPHA;
#elif RC_ROW_SIZE == 32
    k1.lrow[0] ^= ALPHA_ROW0;
    k1.lrow[1] ^= ALPHA_ROW1;
#else
    k1.row[0] ^= ALPHA_ROW0;
    k1.row[1] ^= ALPHA_ROW1;
    k1.row[2] ^= ALPHA_ROW2;
    k1.row[3] ^= ALPHA_ROW3;
#endif

    /* Perform all reverse rounds */
    for (index = ks->rounds; index > 0; --index) {
        /* Inverse mix of the columns (same as the forward mix) */
        mantis_mix_columns(&state);

        /* Inverse shift of the rows */
        mantis_shift_rows_inverse(&state);

        /* XOR with the key and tweak */
#if SKINNY_64BIT
        state.llrow ^= k1.llrow ^ tk.llrow;
#else
        state.lrow[0] ^= k1.lrow[0] ^ tk.lrow[0];
        state.lrow[1] ^= k1.lrow[1] ^ tk.lrow[1];
#endif

        /* Add the round constant */
#if RC_ROW_SIZE == 64
        --r;
        state.llrow ^= r[0];
#elif RC_ROW_SIZE == 32
        r -= 2;
        state.lrow[0] ^= r[0];
        state.lrow[1] ^= r[1];
#else
        r -= 4;
        state.row[0] ^= r[0];
        state.row[1] ^= r[1];
        state.row[2] ^= r[2];
        state.row[3] ^= r[3];
#endif

        /* Apply the inverse S-box (which is the same as the forward S-box) */
#if SKINNY_64BIT
        state.llrow = mantis_sbox(state.llrow);
#else
        state.lrow[0] = mantis_sbox(state.lrow[0]);
        state.lrow[1] = mantis_sbox(state.lrow[1]);
#endif

        /* Update the tweak with the reverse h function */
        mantis_update_tweak_inverse(&tk);
    }

    /* XOR the final whitening key k0prime with the state,
       together with k1alpha and the final tweak value */
#if SKINNY_64BIT
    state.llrow ^= ks->k0prime.llrow ^ k1.llrow ^ tk.llrow;
#else
    state.lrow[0] ^= ks->k0prime.lrow[0] ^ k1.lrow[0] ^ tk.lrow[0];
    state.lrow[1] ^= ks->k0prime.lrow[1] ^ k1.lrow[1] ^ tk.lrow[1];
#endif

    /* Convert host-endian back into little-endian in the output buffer */
#if SKINNY_64BIT && SKINNY_LITTLE_ENDIAN
    WRITE_WORD64(output, 0, state.llrow);
#elif SKINNY_LITTLE_ENDIAN
    WRITE_WORD32(output, 0, state.lrow[0]);
    WRITE_WORD32(output, 4, state.lrow[1]);
#else
    WRITE_WORD16(output, 0, state.row[0]);
    WRITE_WORD16(output, 2, state.row[1]);
    WRITE_WORD16(output, 4, state.row[2]);
    WRITE_WORD16(output, 6, state.row[3]);
#endif
}
