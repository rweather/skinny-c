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

#include "skinny64-parallel.h"
#include "skinny-internal.h"

#if SKINNY_VEC128_MATH

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

STATIC_INLINE SkinnyVector8x16_t skinny64_inv_sbox(SkinnyVector8x16_t x)
{
    SkinnyVector8x16_t bit0 = ~x;
    SkinnyVector8x16_t bit1 = bit0 >> 1;
    SkinnyVector8x16_t bit2 = bit0 >> 2;
    SkinnyVector8x16_t bit3 = bit0 >> 3;
    bit0 ^= bit3 & bit2;
    bit1 ^= bit3 & bit0;
    bit2 ^= bit1 & bit0;
    bit3 ^= bit1 & bit2;
    x = ((bit0 << 1) & 0x2222U) |
        ((bit1 << 2) & 0x4444U) |
        ((bit2 << 3) & 0x8888U) |
        ( bit3       & 0x1111U);
    return ~x;
}

void _skinny64_parallel_encrypt_vec128
    (void *output, const void *input, const Skinny64Key_t *ks)
{
    SkinnyVector8x16_t row0;
    SkinnyVector8x16_t row1;
    SkinnyVector8x16_t row2;
    SkinnyVector8x16_t row3;
    const Skinny64HalfCells_t *schedule;
    unsigned index;
    SkinnyVector8x16_t temp;

    /* Read the rows of all eight blocks into memory */
    row0 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  0), READ_WORD16(input,  8),
         READ_WORD16(input, 16), READ_WORD16(input, 24),
         READ_WORD16(input, 32), READ_WORD16(input, 40),
         READ_WORD16(input, 48), READ_WORD16(input, 56)};
    row1 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  2), READ_WORD16(input, 10),
         READ_WORD16(input, 18), READ_WORD16(input, 26),
         READ_WORD16(input, 34), READ_WORD16(input, 42),
         READ_WORD16(input, 50), READ_WORD16(input, 58)};
    row2 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  4), READ_WORD16(input, 12),
         READ_WORD16(input, 20), READ_WORD16(input, 28),
         READ_WORD16(input, 36), READ_WORD16(input, 44),
         READ_WORD16(input, 52), READ_WORD16(input, 60)};
    row3 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  6), READ_WORD16(input, 14),
         READ_WORD16(input, 22), READ_WORD16(input, 30),
         READ_WORD16(input, 38), READ_WORD16(input, 46),
         READ_WORD16(input, 54), READ_WORD16(input, 62)};

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

    /* Write the rows of all eight blocks back to memory */
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
}

void _skinny64_parallel_decrypt_vec128
    (void *output, const void *input, const Skinny64Key_t *ks)
{
    SkinnyVector8x16_t row0;
    SkinnyVector8x16_t row1;
    SkinnyVector8x16_t row2;
    SkinnyVector8x16_t row3;
    const Skinny64HalfCells_t *schedule;
    unsigned index;
    SkinnyVector8x16_t temp;

    /* Read the rows of all eight blocks into memory */
    row0 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  0), READ_WORD16(input,  8),
         READ_WORD16(input, 16), READ_WORD16(input, 24),
         READ_WORD16(input, 32), READ_WORD16(input, 40),
         READ_WORD16(input, 48), READ_WORD16(input, 56)};
    row1 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  2), READ_WORD16(input, 10),
         READ_WORD16(input, 18), READ_WORD16(input, 26),
         READ_WORD16(input, 34), READ_WORD16(input, 42),
         READ_WORD16(input, 50), READ_WORD16(input, 58)};
    row2 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  4), READ_WORD16(input, 12),
         READ_WORD16(input, 20), READ_WORD16(input, 28),
         READ_WORD16(input, 36), READ_WORD16(input, 44),
         READ_WORD16(input, 52), READ_WORD16(input, 60)};
    row3 = (SkinnyVector8x16_t)
        {READ_WORD16(input,  6), READ_WORD16(input, 14),
         READ_WORD16(input, 22), READ_WORD16(input, 30),
         READ_WORD16(input, 38), READ_WORD16(input, 46),
         READ_WORD16(input, 54), READ_WORD16(input, 62)};

    /* Perform all decryption rounds */
    schedule = &(ks->schedule[ks->rounds - 1]);
    for (index = ks->rounds; index > 0; --index, --schedule) {
        /* Inverse mix of the columns */
        temp = row3;
        row3 = row0;
        row0 = row1;
        row1 = row2;
        row3 ^= temp;
        row2 = temp ^ row0;
        row1 ^= row2;

        /* Inverse shift of the rows */
        row1 = skinny64_rotate_right(row1, 12);
        row2 = skinny64_rotate_right(row2, 8);
        row3 = skinny64_rotate_right(row3, 4);

        /* Apply the subkey for this round */
        row0 ^= schedule->row[0];
        row1 ^= schedule->row[1];
        row2 ^= 0x20;

        /* Apply the inverse S-box to all bytes in the state */
        row0 = skinny64_inv_sbox(row0);
        row1 = skinny64_inv_sbox(row1);
        row2 = skinny64_inv_sbox(row2);
        row3 = skinny64_inv_sbox(row3);
    }

    /* Write the rows of all eight blocks back to memory */
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
}

#else /* !SKINNY_VEC128_MATH */

/* Stubbed out */

void _skinny64_parallel_encrypt_vec128
    (void *output, const void *input, const Skinny64Key_t *ks)
{
    (void)output;
    (void)input;
    (void)ks;
}

void _skinny64_parallel_decrypt_vec128
    (void *output, const void *input, const Skinny64Key_t *ks)
{
    (void)output;
    (void)input;
    (void)ks;
}

#endif /* !SKINNY_VEC128_MATH */
