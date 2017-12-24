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

#include "skinny128-parallel.h"
#include "skinny-internal.h"

#if SKINNY_VEC256_MATH

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

STATIC_INLINE void skinny128_inv_sbox_four
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

    y1  = ((~((x1 >> 1) | (x1 >> 3))) & 0x01010101U);
    y2  = ((~((x2 >> 1) | (x2 >> 3))) & 0x01010101U);
    y3  = ((~((x3 >> 1) | (x3 >> 3))) & 0x01010101U);
    y4  = ((~((x4 >> 1) | (x4 >> 3))) & 0x01010101U);

    x1 ^= ((~((x1 >> 2) | (x1 >> 3))) & 0x10101010U) ^ y1;
    x2 ^= ((~((x2 >> 2) | (x2 >> 3))) & 0x10101010U) ^ y2;
    x3 ^= ((~((x3 >> 2) | (x3 >> 3))) & 0x10101010U) ^ y3;
    x4 ^= ((~((x4 >> 2) | (x4 >> 3))) & 0x10101010U) ^ y4;

    y1  = ((~((x1 >> 6) | (x1 >> 1))) & 0x02020202U);
    y2  = ((~((x2 >> 6) | (x2 >> 1))) & 0x02020202U);
    y3  = ((~((x3 >> 6) | (x3 >> 1))) & 0x02020202U);
    y4  = ((~((x4 >> 6) | (x4 >> 1))) & 0x02020202U);

    x1 ^= ((~((x1 >> 1) | (x1 >> 2))) & 0x08080808U) ^ y1;
    x2 ^= ((~((x2 >> 1) | (x2 >> 2))) & 0x08080808U) ^ y2;
    x3 ^= ((~((x3 >> 1) | (x3 >> 2))) & 0x08080808U) ^ y3;
    x4 ^= ((~((x4 >> 1) | (x4 >> 2))) & 0x08080808U) ^ y4;

    y1  = ((~((x1 << 2) | (x1 << 1))) & 0x80808080U);
    y2  = ((~((x2 << 2) | (x2 << 1))) & 0x80808080U);
    y3  = ((~((x3 << 2) | (x3 << 1))) & 0x80808080U);
    y4  = ((~((x4 << 2) | (x4 << 1))) & 0x80808080U);

    x1 ^= ((~((x1 >> 1) | (x1 << 2))) & 0x04040404U) ^ y1;
    x2 ^= ((~((x2 >> 1) | (x2 << 2))) & 0x04040404U) ^ y2;
    x3 ^= ((~((x3 >> 1) | (x3 << 2))) & 0x04040404U) ^ y3;
    x4 ^= ((~((x4 >> 1) | (x4 << 2))) & 0x04040404U) ^ y4;

    y1  = ((~((x1 << 5) | (x1 << 1))) & 0x20202020U);
    y2  = ((~((x2 << 5) | (x2 << 1))) & 0x20202020U);
    y3  = ((~((x3 << 5) | (x3 << 1))) & 0x20202020U);
    y4  = ((~((x4 << 5) | (x4 << 1))) & 0x20202020U);

    x1 ^= ((~((x1 << 4) | (x1 << 5))) & 0x40404040U) ^ y1;
    x2 ^= ((~((x2 << 4) | (x2 << 5))) & 0x40404040U) ^ y2;
    x3 ^= ((~((x3 << 4) | (x3 << 5))) & 0x40404040U) ^ y3;
    x4 ^= ((~((x4 << 4) | (x4 << 5))) & 0x40404040U) ^ y4;

    *u = ((x1 & 0x01010101U) << 2) |
         ((x1 & 0x04040404U) << 4) |
         ((x1 & 0x02020202U) << 6) |
         ((x1 & 0x20202020U) >> 5) |
         ((x1 & 0xC8C8C8C8U) >> 2) |
         ((x1 & 0x10101010U) >> 1);

    *v = ((x2 & 0x01010101U) << 2) |
         ((x2 & 0x04040404U) << 4) |
         ((x2 & 0x02020202U) << 6) |
         ((x2 & 0x20202020U) >> 5) |
         ((x2 & 0xC8C8C8C8U) >> 2) |
         ((x2 & 0x10101010U) >> 1);

    *s = ((x3 & 0x01010101U) << 2) |
         ((x3 & 0x04040404U) << 4) |
         ((x3 & 0x02020202U) << 6) |
         ((x3 & 0x20202020U) >> 5) |
         ((x3 & 0xC8C8C8C8U) >> 2) |
         ((x3 & 0x10101010U) >> 1);

    *t = ((x4 & 0x01010101U) << 2) |
         ((x4 & 0x04040404U) << 4) |
         ((x4 & 0x02020202U) << 6) |
         ((x4 & 0x20202020U) >> 5) |
         ((x4 & 0xC8C8C8C8U) >> 2) |
         ((x4 & 0x10101010U) >> 1);
}

void _skinny128_parallel_encrypt_vec256
    (void *output, const void *input, const Skinny128Key_t *ks)
{
    SkinnyVector8x32_t row0;
    SkinnyVector8x32_t row1;
    SkinnyVector8x32_t row2;
    SkinnyVector8x32_t row3;
    const Skinny128HalfCells_t *schedule;
    unsigned index;
    SkinnyVector8x32_t temp;

    /* Read the rows of all eight blocks into memory */
    row0 = (SkinnyVector8x32_t)
        {READ_WORD32(input,   0), READ_WORD32(input,  16),
         READ_WORD32(input,  32), READ_WORD32(input,  48),
         READ_WORD32(input,  64), READ_WORD32(input,  80),
         READ_WORD32(input,  96), READ_WORD32(input, 112)};
    row1 = (SkinnyVector8x32_t)
        {READ_WORD32(input,   4), READ_WORD32(input,  20),
         READ_WORD32(input,  36), READ_WORD32(input,  52),
         READ_WORD32(input,  68), READ_WORD32(input,  84),
         READ_WORD32(input, 100), READ_WORD32(input, 116)};
    row2 = (SkinnyVector8x32_t)
        {READ_WORD32(input,   8), READ_WORD32(input,  24),
         READ_WORD32(input,  40), READ_WORD32(input,  56),
         READ_WORD32(input,  72), READ_WORD32(input,  88),
         READ_WORD32(input, 104), READ_WORD32(input, 120)};
    row3 = (SkinnyVector8x32_t)
        {READ_WORD32(input,  12), READ_WORD32(input,  28),
         READ_WORD32(input,  44), READ_WORD32(input,  60),
         READ_WORD32(input,  76), READ_WORD32(input,  92),
         READ_WORD32(input, 108), READ_WORD32(input, 124)};

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

void _skinny128_parallel_decrypt_vec256
    (void *output, const void *input, const Skinny128Key_t *ks)
{
    SkinnyVector8x32_t row0;
    SkinnyVector8x32_t row1;
    SkinnyVector8x32_t row2;
    SkinnyVector8x32_t row3;
    const Skinny128HalfCells_t *schedule;
    unsigned index;
    SkinnyVector8x32_t temp;

    /* Read the rows of all eight blocks into memory */
    row0 = (SkinnyVector8x32_t)
        {READ_WORD32(input,   0), READ_WORD32(input,  16),
         READ_WORD32(input,  32), READ_WORD32(input,  48),
         READ_WORD32(input,  64), READ_WORD32(input,  80),
         READ_WORD32(input,  96), READ_WORD32(input, 112)};
    row1 = (SkinnyVector8x32_t)
        {READ_WORD32(input,   4), READ_WORD32(input,  20),
         READ_WORD32(input,  36), READ_WORD32(input,  52),
         READ_WORD32(input,  68), READ_WORD32(input,  84),
         READ_WORD32(input, 100), READ_WORD32(input, 116)};
    row2 = (SkinnyVector8x32_t)
        {READ_WORD32(input,   8), READ_WORD32(input,  24),
         READ_WORD32(input,  40), READ_WORD32(input,  56),
         READ_WORD32(input,  72), READ_WORD32(input,  88),
         READ_WORD32(input, 104), READ_WORD32(input, 120)};
    row3 = (SkinnyVector8x32_t)
        {READ_WORD32(input,  12), READ_WORD32(input,  28),
         READ_WORD32(input,  44), READ_WORD32(input,  60),
         READ_WORD32(input,  76), READ_WORD32(input,  92),
         READ_WORD32(input, 108), READ_WORD32(input, 124)};

    /* Perform all decryption rounds on the eight blocks in parallel */
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
        row1 = skinny128_rotate_right(row1, 24);
        row2 = skinny128_rotate_right(row2, 16);
        row3 = skinny128_rotate_right(row3, 8);

        /* Apply the subkey for this round */
        row0 ^= schedule->row[0];
        row1 ^= schedule->row[1];
        row2 ^= 0x02;

        /* Apply the inverse S-box to all bytes in the state */
        skinny128_inv_sbox_four(&row0, &row1, &row2, &row3);
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

#else /* !SKINNY_VEC256_MATH */

/* Stubbed out */

void _skinny128_parallel_encrypt_vec256
    (void *output, const void *input, const Skinny128Key_t *ks)
{
    (void)output;
    (void)input;
    (void)ks;
}

void _skinny128_parallel_decrypt_vec256
    (void *output, const void *input, const Skinny128Key_t *ks)
{
    (void)output;
    (void)input;
    (void)ks;
}

#endif /* !SKINNY_VEC256_MATH */
