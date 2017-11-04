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
#include <string.h>

/* Figure out how to inline functions using this C compiler */
#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define STATIC_INLINE static inline
#elif defined(__GNUC__)
#define STATIC_INLINE static __inline__
#else
#define STATIC_INLINE static
#endif

/* Define SKINNY128_64BIT to 1 if the CPU is natively 64-bit */
#if defined(__WORDSIZE) && __WORDSIZE == 64
#define SKINNY128_64BIT 1
#else
#define SKINNY128_64BIT 0
#endif

#define READ_BYTE(ptr,offset) \
    ((uint32_t)(((const uint8_t *)(ptr))[(offset)]))

#define READ_WORD32(ptr,offset) \
    (((uint32_t)(((const uint8_t *)(ptr))[(offset)])) | \
    (((uint32_t)(((const uint8_t *)(ptr))[(offset) + 1])) << 8) | \
    (((uint32_t)(((const uint8_t *)(ptr))[(offset) + 2])) << 16) | \
    (((uint32_t)(((const uint8_t *)(ptr))[(offset) + 3])) << 24))

#define WRITE_WORD32(ptr,offset,value) \
    ((((uint8_t *)(ptr))[(offset)] = (uint8_t)(value)), \
     (((uint8_t *)(ptr))[(offset) + 1] = (uint8_t)((value) >> 8)), \
     (((uint8_t *)(ptr))[(offset) + 2] = (uint8_t)((value) >> 16)), \
     (((uint8_t *)(ptr))[(offset) + 3] = (uint8_t)((value) >> 24)))

#if SKINNY128_64BIT

STATIC_INLINE uint64_t skinny128_LFSR2(uint64_t x)
{
    return ((x << 1) & 0xFEFEFEFEFEFEFEFEULL) ^
           ((x >> 7) & 0x0101010101010101ULL) ^
           ((x >> 5) & 0x0101010101010101ULL);
}

STATIC_INLINE uint64_t skinny128_LFSR3(uint64_t x)
{
    return ((x >> 1) & 0x7F7F7F7F7F7F7F7FULL) ^
           ((x << 7) & 0x8080808080808080ULL) ^
           ((x << 1) & 0x8080808080808080ULL);
}

#else

STATIC_INLINE uint32_t skinny128_LFSR2(uint32_t x)
{
    return ((x << 1) & 0xFEFEFEFEU) ^ ((x >> 7) & 0x01010101U) ^
           ((x >> 5) & 0x01010101U);
}

STATIC_INLINE uint32_t skinny128_LFSR3(uint32_t x)
{
    return ((x >> 1) & 0x7F7F7F7FU) ^ ((x << 7) & 0x80808080U) ^
           ((x << 1) & 0x80808080U);
}

#endif

STATIC_INLINE void skinny128_permute_tk(Skinny128Cells_t *tk)
{
    /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */
    uint32_t row2 = tk->row[2];
    uint32_t row3 = tk->row[3];
    tk->row[2] = tk->row[0];
    tk->row[3] = tk->row[1];
    tk->row[0] = ((row2 >>  8) & 0x000000FFU) |
                 ((row2 << 16) & 0x00FF0000U) |
                 ((row3 >> 16) & 0x0000FF00U) |
                 ((row3 << 16) & 0xFF000000U);
    tk->row[1] = ((row2 >> 16) & 0x000000FFU) |
                  (row2        & 0xFF000000U) |
                 ((row3 >>  8) & 0x0000FF00U) |
                 ((row3 << 16) & 0x00FF0000U);
}

static void skinny128_set_key_inner
    (Skinny128Key_t *ks, const void *key, unsigned key_size,
     const Skinny128Cells_t *tweak)
{
    Skinny128Cells_t tk[3];
    unsigned count, index;
    uint32_t word;
    uint8_t rc = 0;

    /* How many tk items do we need and what is the round count? */
    if (key_size == SKINNY128_BLOCK_SIZE) {
        count = 1;
        ks->rounds = 40;
    } else if (key_size <= (2 * SKINNY128_BLOCK_SIZE)) {
        count = 2;
        ks->rounds = 48;
    } else {
        count = 3;
        ks->rounds = 56;
    }

    /* Unpack the key and convert from little-endian to host-endian */
    if (!tweak) {
        /* Key only, no tweak */
        memset(tk, 0, sizeof(tk));
        for (index = 0; index < key_size; index += 4) {
            if ((index + 4) <= key_size) {
                word = READ_WORD32(key, index);
            } else {
                word = READ_BYTE(key, index);
                if ((index + 1) < key_size)
                    word |= (READ_BYTE(key, index + 1) << 8);
                if ((index + 2) < key_size)
                    word |= (READ_BYTE(key, index + 2) << 16);
            }
            tk[index / SKINNY128_BLOCK_SIZE].row[(index / 4) & 0x03] = word;
        }
    } else {
        /* TK1 is set to the tweak, with the key in the remaining cells */
        tk[0] = *tweak;
        memset(&(tk[1]), 0, sizeof(Skinny128Cells_t) * 2);
        for (index = 0; index < key_size; index += 4) {
            if ((index + 4) <= key_size) {
                word = READ_WORD32(key, index);
            } else {
                word = READ_BYTE(key, index);
                if ((index + 1) < key_size)
                    word |= (READ_BYTE(key, index + 1) << 8);
                if ((index + 2) < key_size)
                    word |= (READ_BYTE(key, index + 2) << 16);
            }
            tk[(index / SKINNY128_BLOCK_SIZE) + 1].row[(index / 4) & 0x03] = word;
        }
    }

    /* Compute the key schedule words for each round */
    for (index = 0; index < ks->rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule
           by XOR'ing together the first two rows of each TKi element */
#if SKINNY128_64BIT
        if (count == 1) {
            ks->schedule[index].lrow = tk[0].lrow[0];
        } else if (count == 2) {
            ks->schedule[index].lrow =
                tk[0].lrow[0] ^ tk[1].lrow[0];
        } else {
            ks->schedule[index].lrow =
                tk[0].lrow[0] ^ tk[1].lrow[0] ^ tk[2].lrow[0];
        }
#else
        if (count == 1) {
            ks->schedule[index].row[0] = tk[0].row[0];
            ks->schedule[index].row[1] = tk[0].row[1];
        } else if (count == 2) {
            ks->schedule[index].row[0] =
                tk[0].row[0] ^ tk[1].row[0];
            ks->schedule[index].row[1] =
                tk[0].row[1] ^ tk[1].row[1];
        } else {
            ks->schedule[index].row[0] =
                tk[0].row[0] ^ tk[1].row[0] ^ tk[2].row[0];
            ks->schedule[index].row[1] =
                tk[0].row[1] ^ tk[1].row[1] ^ tk[2].row[1];
        }
#endif

        /* XOR in the round constants for the first two rows.
           The round constants for the 3rd and 4th rows are
           fixed and will be applied during encrypt/decrypt */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        ks->schedule[index].row[0] ^= (rc & 0x0F);
        ks->schedule[index].row[1] ^= (rc >> 4);

        /* If we have a tweak, then we need to XOR a 1 bit into the
           second bit of the top cell of the third column as recommended
           by the SKINNY specification */
        if (tweak)
            ks->schedule[index].row[0] ^= 0x00020000;

        /* If this is the last round, then there is no point permuting
           the TKi values to create another key schedule entry */
        if (index == (ks->rounds - 1))
            break;

        /* Permute the TKi states */
        skinny128_permute_tk(&(tk[0]));
        if (count == 1)
            continue;
        skinny128_permute_tk(&(tk[1]));
        if (count == 3) {
            skinny128_permute_tk(&(tk[2]));
        }

        /* Update the TK2 and TK3 states with the LFSR's */
#if SKINNY128_64BIT
        tk[1].lrow[0] = skinny128_LFSR2(tk[1].lrow[0]);
        if (count == 3) {
            tk[2].lrow[0] = skinny128_LFSR3(tk[2].lrow[0]);
        }
#else
        tk[1].row[0] = skinny128_LFSR2(tk[1].row[0]);
        tk[1].row[1] = skinny128_LFSR2(tk[1].row[1]);
        if (count == 3) {
            tk[2].row[0] = skinny128_LFSR3(tk[2].row[0]);
            tk[2].row[1] = skinny128_LFSR3(tk[2].row[1]);
        }
#endif
    }
}

int skinny128_set_key(Skinny128Key_t *ks, const void *key, unsigned size)
{
    /* Validate the parameters */
    if (!ks || !key || size < SKINNY128_BLOCK_SIZE ||
            size > (SKINNY128_BLOCK_SIZE * 3)) {
        return 0;
    }

    /* Set the key directly with no tweak */
    skinny128_set_key_inner(ks, key, size, 0);
    return 1;
}

static void skinny128_read_tweak
    (Skinny128Cells_t *tk, const void *tweak, unsigned tweak_size)
{
    unsigned index;
    uint32_t word;
    memset(tk, 0, sizeof(Skinny128Cells_t));
    if (tweak) {
        for (index = 0; index < tweak_size; index += 4) {
            if ((index + 4) <= tweak_size) {
                word = READ_WORD32(tweak, index);
            } else {
                word = READ_BYTE(tweak, index);
                if ((index + 1) < tweak_size)
                    word |= (READ_BYTE(tweak, index + 1) << 8);
                if ((index + 2) < tweak_size)
                    word |= (READ_BYTE(tweak, index + 2) << 16);
            }
            tk->row[(index / 4) & 0x03] = word;
        }
    }
}

int skinny128_set_key_and_tweak
    (Skinny128TweakedKey_t *ks, const void *key, unsigned key_size,
     const void *tweak, unsigned tweak_size)
{
    /* Validate the parameters */
    if (!ks || !key || key_size < SKINNY128_BLOCK_SIZE ||
            key_size > (SKINNY128_BLOCK_SIZE * 2) ||
            tweak_size < 1 || tweak_size > SKINNY128_BLOCK_SIZE) {
        return 0;
    }

    /* Read the initial tweak and convert from little-endian to host-endian */
    skinny128_read_tweak(&(ks->tweak), tweak, tweak_size);

    /* Set the initial key and tweak value */
    skinny128_set_key_inner(&(ks->ks), key, key_size, &(ks->tweak));
    return 1;
}

int skinny128_change_tweak
    (Skinny128TweakedKey_t *ks, const void *tweak, unsigned tweak_size)
{
    Skinny128Cells_t tk_prev;
    Skinny128Cells_t tk_next;
    unsigned index;

    /* Validate the parameters */
    if (!ks || tweak_size < 1 || tweak_size > SKINNY128_BLOCK_SIZE) {
        return 0;
    }

    /* Read the tweak value and convert little-endian to host-endian */
    skinny128_read_tweak(&tk_next, tweak, tweak_size);

    /* We iterate through every round and XOR the previous and new tweaks
       with the key schedule entries.  This will have the effect of removing
       the previous tweak and then applying the new tweak */
    tk_prev = ks->tweak;
    ks->tweak = tk_next;
    for (index = 0; index < ks->ks.rounds; ++index) {
        /* Remove the previous tweak from the key schedule entry */
#if SKINNY128_64BIT
        ks->ks.schedule[index].lrow ^= tk_prev.lrow[0];
#else
        ks->ks.schedule[index].row[0] ^= tk_prev.row[0];
        ks->ks.schedule[index].row[1] ^= tk_prev.row[1];
#endif

        /* Apply the new tweak to the key schedule entry */
#if SKINNY128_64BIT
        ks->ks.schedule[index].lrow ^= tk_next.lrow[0];
#else
        ks->ks.schedule[index].row[0] ^= tk_next.row[0];
        ks->ks.schedule[index].row[1] ^= tk_next.row[1];
#endif

        /* Permute the TK1 states for all rounds except the last */
        if (index < (ks->ks.rounds - 1)) {
            skinny128_permute_tk(&tk_prev);
            skinny128_permute_tk(&tk_next);
        }
    }

    /* Ready to go */
    return 1;
}

STATIC_INLINE uint32_t skinny128_rotate_right(uint32_t x, unsigned count)
{
    /* Note: we are rotating the cells right, which actually moves
       the values up closer to the MSB.  That is, we do a left shift
       on the word to rotate the cells in the word right */
    return (x << count) | (x >> (32 - count));
}

#if SKINNY128_64BIT

#define SBOX_MIX(x)  \
    (((~((((x) >> 1) | (x)) >> 2)) & 0x1111111111111111ULL) ^ (x))
#define SBOX_SWAP(x)  \
    (((x) & 0xF9F9F9F9F9F9F9F9ULL) | \
     (((x) >> 1) & 0x0202020202020202ULL) | \
     (((x) << 1) & 0x0404040404040404ULL))

/* Permutation generated by http://programming.sirrida.de/calcperm.php */
#define SBOX_PERMUTE(x)  \
        ((((x) & 0x0101010101010101ULL) << 2) | \
         (((x) & 0x0606060606060606ULL) << 5) | \
         (((x) & 0x2020202020202020ULL) >> 5) | \
         (((x) & 0xC8C8C8C8C8C8C8C8ULL) >> 2) | \
         (((x) & 0x1010101010101010ULL) >> 1))
#define SBOX_PERMUTE_INV(x)  \
        ((((x) & 0x0808080808080808ULL) << 1) | \
         (((x) & 0x3232323232323232ULL) << 2) | \
         (((x) & 0x0101010101010101ULL) << 5) | \
         (((x) & 0xC0C0C0C0C0C0C0C0ULL) >> 5) | \
         (((x) & 0x0404040404040404ULL) >> 2))

STATIC_INLINE uint64_t skinny128_sbox(uint64_t x)
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

STATIC_INLINE uint64_t skinny128_inv_sbox(uint64_t x)
{
    x = SBOX_SWAP(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE_INV(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE_INV(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE_INV(x);
    return SBOX_MIX(x);
}

#else

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

STATIC_INLINE uint32_t skinny128_sbox(uint32_t x)
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

STATIC_INLINE uint32_t skinny128_inv_sbox(uint32_t x)
{
    x = SBOX_SWAP(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE_INV(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE_INV(x);
    x = SBOX_MIX(x);
    x = SBOX_PERMUTE_INV(x);
    return SBOX_MIX(x);
}

#endif

void skinny128_encrypt(void *output, const void *input, const Skinny128Key_t *ks)
{
    Skinny128Cells_t state;
    const Skinny128HalfCells_t *schedule;
    unsigned index;
    uint32_t temp;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD32(input, 0);
    state.row[1] = READ_WORD32(input, 4);
    state.row[2] = READ_WORD32(input, 8);
    state.row[3] = READ_WORD32(input, 12);

    /* Perform all encryption rounds */
    schedule = ks->schedule;
    for (index = ks->rounds; index > 0; --index, ++schedule) {
        /* Apply the S-box to all bytes in the state */
#if SKINNY128_64BIT
        state.lrow[0] = skinny128_sbox(state.lrow[0]);
        state.lrow[1] = skinny128_sbox(state.lrow[1]);
#else
        state.row[0] = skinny128_sbox(state.row[0]);
        state.row[1] = skinny128_sbox(state.row[1]);
        state.row[2] = skinny128_sbox(state.row[2]);
        state.row[3] = skinny128_sbox(state.row[3]);
#endif

        /* Apply the subkey for this round */
#if SKINNY128_64BIT
        state.lrow[0] ^= schedule->lrow;
        state.lrow[1] ^= 0x02;
#else
        state.row[0] ^= schedule->row[0];
        state.row[1] ^= schedule->row[1];
        state.row[2] ^= 0x02;
#endif

        /* Shift the rows */
        state.row[1] = skinny128_rotate_right(state.row[1], 8);
        state.row[2] = skinny128_rotate_right(state.row[2], 16);
        state.row[3] = skinny128_rotate_right(state.row[3], 24);

        /* Mix the columns */
        state.row[1] ^= state.row[2];
        state.row[2] ^= state.row[0];
        temp = state.row[3] ^ state.row[2];
        state.row[3] = state.row[2];
        state.row[2] = state.row[1];
        state.row[1] = state.row[0];
        state.row[0] = temp;
    }

    /* Convert host-endian back into little-endian in the output buffer */
    WRITE_WORD32(output, 0, state.row[0]);
    WRITE_WORD32(output, 4, state.row[1]);
    WRITE_WORD32(output, 8, state.row[2]);
    WRITE_WORD32(output, 12, state.row[3]);
}

void skinny128_decrypt(void *output, const void *input, const Skinny128Key_t *ks)
{
    Skinny128Cells_t state;
    const Skinny128HalfCells_t *schedule;
    unsigned index;
    uint32_t temp;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD32(input, 0);
    state.row[1] = READ_WORD32(input, 4);
    state.row[2] = READ_WORD32(input, 8);
    state.row[3] = READ_WORD32(input, 12);

    /* Perform all decryption rounds */
    schedule = &(ks->schedule[ks->rounds - 1]);
    for (index = ks->rounds; index > 0; --index, --schedule) {
        /* Inverse mix of the columns */
        temp = state.row[3];
        state.row[3] = state.row[0];
        state.row[0] = state.row[1];
        state.row[1] = state.row[2];
        state.row[3] ^= temp;
        state.row[2] = temp ^ state.row[0];
        state.row[1] ^= state.row[2];

        /* Inverse shift of the rows */
        state.row[1] = skinny128_rotate_right(state.row[1], 24);
        state.row[2] = skinny128_rotate_right(state.row[2], 16);
        state.row[3] = skinny128_rotate_right(state.row[3], 8);

        /* Apply the subkey for this round */
#if SKINNY128_64BIT
        state.lrow[0] ^= schedule->lrow;
#else
        state.row[0] ^= schedule->row[0];
        state.row[1] ^= schedule->row[1];
#endif
        state.row[2] ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
#if SKINNY128_64BIT
        state.lrow[0] = skinny128_inv_sbox(state.lrow[0]);
        state.lrow[1] = skinny128_inv_sbox(state.lrow[1]);
#else
        state.row[0] = skinny128_inv_sbox(state.row[0]);
        state.row[1] = skinny128_inv_sbox(state.row[1]);
        state.row[2] = skinny128_inv_sbox(state.row[2]);
        state.row[3] = skinny128_inv_sbox(state.row[3]);
#endif
    }

    /* Convert host-endian back into little-endian in the output buffer */
    WRITE_WORD32(output, 0, state.row[0]);
    WRITE_WORD32(output, 4, state.row[1]);
    WRITE_WORD32(output, 8, state.row[2]);
    WRITE_WORD32(output, 12, state.row[3]);
}
