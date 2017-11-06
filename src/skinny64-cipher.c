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
#include <string.h>

/* Figure out how to inline functions using this C compiler */
#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define STATIC_INLINE static inline
#elif defined(__GNUC__)
#define STATIC_INLINE static __inline__
#else
#define STATIC_INLINE static
#endif

/* Note: The four cells in a 16-bit row are stored as 0x3210 in memory
   where the least significant nibble is cell 0.  However, the nibbles
   in the serialized representation are stored reversed as 0x01 0x23.
   We correct for this when reading and writing the serialized form. */

STATIC_INLINE uint8_t skinny64_read_byte(const uint8_t *ptr)
{
    uint8_t value = *ptr;
    return (value >> 4) | (value << 4);
}

STATIC_INLINE uint16_t skinny64_read_word16(const uint8_t *ptr)
{
    uint16_t value = ((uint16_t)(ptr[0])) | (((uint16_t)(ptr[1])) << 8);
    return ((value >> 4) & 0x0F0FU) | ((value << 4) & 0xF0F0U);
}

STATIC_INLINE void skinny64_write_word16(uint8_t *ptr, uint16_t value)
{
    value = ((value >> 4) & 0x0F0FU) | ((value << 4) & 0xF0F0U);
    ptr[0] = (uint8_t)value;
    ptr[1] = (uint8_t)(value >> 8);
}

#define READ_BYTE(ptr,offset) \
    (skinny64_read_byte(((const uint8_t *)(ptr)) + (offset)))

#define READ_WORD16(ptr,offset) \
    (skinny64_read_word16(((const uint8_t *)(ptr)) + (offset)))

#define WRITE_WORD16(ptr,offset,value) \
    (skinny64_write_word16(((uint8_t *)(ptr)) + (offset), (value)))

STATIC_INLINE uint32_t skinny64_LFSR2(uint32_t x)
{
    return ((x << 1) & 0xEEEEEEEEU) ^ ((x >> 3) & 0x11111111U) ^
           ((x >> 2) & 0x11111111U);
}

STATIC_INLINE uint32_t skinny64_LFSR3(uint32_t x)
{
    return ((x >> 1) & 0x77777777U) ^ (x & 0x88888888U) ^
           ((x << 3) & 0x88888888U);
}

STATIC_INLINE void skinny64_permute_tk(Skinny64Cells_t *tk)
{
    /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */
    uint16_t row2 = tk->row[2];
    uint16_t row3 = tk->row[3];
    tk->row[2] = tk->row[0];
    tk->row[3] = tk->row[1];
    tk->row[0] = ((row2 >> 4) & 0x000FU) |
                 ((row2 << 8) & 0x0F00U) |
                 ((row3 >> 8) & 0x00F0U) |
                 ((row3 << 8) & 0xF000U);
    tk->row[1] = ((row2 >> 8) & 0x000FU) |
                  (row2       & 0xF000U) |
                 ((row3 >> 4) & 0x00F0U) |
                 ((row3 << 8) & 0x0F00U);
}

static void skinny64_set_key_inner
    (Skinny64Key_t *ks, const void *key, unsigned key_size,
     const Skinny64Cells_t *tweak)
{
    Skinny64Cells_t tk[3];
    unsigned count, index;
    uint16_t word;
    uint8_t rc = 0;

    /* How many tk items do we need and what is the round count? */
    if (key_size == SKINNY64_BLOCK_SIZE) {
        count = 1;
        ks->rounds = 32;
    } else if (key_size <= (2 * SKINNY64_BLOCK_SIZE)) {
        count = 2;
        ks->rounds = 36;
    } else {
        count = 3;
        ks->rounds = 40;
    }

    /* Unpack the key and convert from little-endian to host-endian */
    if (!tweak) {
        /* Key only, no tweak */
        memset(tk, 0, sizeof(tk));
        for (index = 0; index < key_size; index += 2) {
            if ((index + 2) <= key_size) {
                word = READ_WORD16(key, index);
            } else {
                word = READ_BYTE(key, index);
            }
            tk[index / SKINNY64_BLOCK_SIZE].row[(index / 2) & 0x03] = word;
        }
    } else {
        /* TK1 is set to the tweak, with the key in the remaining cells */
        tk[0] = *tweak;
        memset(&(tk[1]), 0, sizeof(Skinny64Cells_t) * 2);
        for (index = 0; index < key_size; index += 2) {
            if ((index + 2) <= key_size) {
                word = READ_WORD16(key, index);
            } else {
                word = READ_BYTE(key, index);
            }
            tk[(index / SKINNY64_BLOCK_SIZE) + 1].row[(index / 2) & 0x03] = word;
        }
    }

    /* Compute the key schedule words for each round */
    for (index = 0; index < ks->rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule
           by XOR'ing together the first two rows of each TKi element */
        if (count == 1) {
            ks->schedule[index].lrow = tk[0].lrow[0];
        } else if (count == 2) {
            ks->schedule[index].lrow =
                tk[0].lrow[0] ^ tk[1].lrow[0];
        } else {
            ks->schedule[index].lrow =
                tk[0].lrow[0] ^ tk[1].lrow[0] ^ tk[2].lrow[0];
        }

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
            ks->schedule[index].row[0] ^= 0x0200;

        /* If this is the last round, then there is no point permuting
           the TKi values to create another key schedule entry */
        if (index == (ks->rounds - 1))
            break;

        /* Permute the TKi states */
        skinny64_permute_tk(&(tk[0]));
        if (count == 1)
            continue;
        skinny64_permute_tk(&(tk[1]));
        if (count == 3) {
            skinny64_permute_tk(&(tk[2]));
        }

        /* Update the TK2 and TK3 states with the LFSR's */
        tk[1].lrow[0] = skinny64_LFSR2(tk[1].lrow[0]);
        if (count == 3) {
            tk[2].lrow[0] = skinny64_LFSR3(tk[2].lrow[0]);
        }
    }
}

int skinny64_set_key(Skinny64Key_t *ks, const void *key, unsigned size)
{
    /* Validate the parameters */
    if (!ks || !key || size < SKINNY64_BLOCK_SIZE ||
            size > (SKINNY64_BLOCK_SIZE * 3)) {
        return 0;
    }

    /* Set the key directly with no tweak */
    skinny64_set_key_inner(ks, key, size, 0);
    return 1;
}

static void skinny64_read_tweak
    (Skinny64Cells_t *tk, const void *tweak, unsigned tweak_size)
{
    unsigned index;
    uint16_t word;
    memset(tk, 0, sizeof(Skinny64Cells_t));
    if (tweak) {
        for (index = 0; index < tweak_size; index += 2) {
            if ((index + 2) <= tweak_size) {
                word = READ_WORD16(tweak, index);
            } else {
                word = READ_BYTE(tweak, index);
            }
            tk->row[(index / 2) & 0x03] = word;
        }
    }
}

int skinny64_set_key_and_tweak
    (Skinny64TweakedKey_t *ks, const void *key, unsigned key_size,
     const void *tweak, unsigned tweak_size)
{
    /* Validate the parameters */
    if (!ks || !key || key_size < SKINNY64_BLOCK_SIZE ||
            key_size > (SKINNY64_BLOCK_SIZE * 2) ||
            tweak_size < 1 || tweak_size > SKINNY64_BLOCK_SIZE) {
        return 0;
    }

    /* Read the initial tweak and convert from little-endian to host-endian */
    skinny64_read_tweak(&(ks->tweak), tweak, tweak_size);

    /* Set the initial key and tweak value */
    skinny64_set_key_inner(&(ks->ks), key, key_size, &(ks->tweak));
    return 1;
}

int skinny64_change_tweak
    (Skinny64TweakedKey_t *ks, const void *tweak, unsigned tweak_size)
{
    Skinny64Cells_t tk_prev;
    Skinny64Cells_t tk_next;
    unsigned index;

    /* Validate the parameters */
    if (!ks || tweak_size < 1 || tweak_size > SKINNY64_BLOCK_SIZE) {
        return 0;
    }

    /* Read the tweak value and convert little-endian to host-endian */
    skinny64_read_tweak(&tk_next, tweak, tweak_size);

    /* We iterate through every round and XOR the previous and new tweaks
       with the key schedule entries.  This will have the effect of removing
       the previous tweak and then applying the new tweak */
    tk_prev = ks->tweak;
    ks->tweak = tk_next;
    for (index = 0; index < ks->ks.rounds; ++index) {
        /* Remove the previous tweak from the key schedule entry */
        ks->ks.schedule[index].lrow ^= tk_prev.lrow[0];

        /* Apply the new tweak to the key schedule entry */
        ks->ks.schedule[index].lrow ^= tk_next.lrow[0];

        /* Permute the TK1 states for all rounds except the last */
        if (index < (ks->ks.rounds - 1)) {
            skinny64_permute_tk(&tk_prev);
            skinny64_permute_tk(&tk_next);
        }
    }

    /* Ready to go */
    return 1;
}

STATIC_INLINE uint16_t skinny64_rotate_right(uint16_t x, unsigned count)
{
    /* Note: we are rotating the cells right, which actually moves
       the values up closer to the MSB.  That is, we do a left shift
       on the word to rotate the cells in the word right */
    return (x << count) | (x >> (16 - count));
}

#define SBOX_MIX(x)  \
    (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
#define SBOX_SHIFT(x)  \
    ((((x) << 1) & 0xEEEEEEEEU) | (((x) >> 3) & 0x11111111U))
#define SBOX_SHIFT_INV(x)  \
    ((((x) >> 1) & 0x77777777U) | (((x) << 3) & 0x88888888U))

STATIC_INLINE uint32_t skinny64_sbox(uint32_t x)
{
    x = SBOX_MIX(x);
    x = SBOX_SHIFT(x);
    x = SBOX_MIX(x);
    x = SBOX_SHIFT(x);
    x = SBOX_MIX(x);
    x = SBOX_SHIFT(x);
    return SBOX_MIX(x);
}

STATIC_INLINE uint32_t skinny64_inv_sbox(uint32_t x)
{
    x = SBOX_MIX(x);
    x = SBOX_SHIFT_INV(x);
    x = SBOX_MIX(x);
    x = SBOX_SHIFT_INV(x);
    x = SBOX_MIX(x);
    x = SBOX_SHIFT_INV(x);
    return SBOX_MIX(x);
}

void skinny64_ecb_encrypt
    (void *output, const void *input, const Skinny64Key_t *ks)
{
    Skinny64Cells_t state;
    const Skinny64HalfCells_t *schedule;
    unsigned index;
    uint32_t temp;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD16(input, 0);
    state.row[1] = READ_WORD16(input, 2);
    state.row[2] = READ_WORD16(input, 4);
    state.row[3] = READ_WORD16(input, 6);

    /* Perform all encryption rounds */
    schedule = ks->schedule;
    for (index = ks->rounds; index > 0; --index, ++schedule) {
        /* Apply the S-box to all bytes in the state */
        state.lrow[0] = skinny64_sbox(state.lrow[0]);
        state.lrow[1] = skinny64_sbox(state.lrow[1]);

        /* Apply the subkey for this round */
        state.lrow[0] ^= schedule->lrow;
        state.row[2] ^= 0x02;

        /* Shift the rows */
        state.row[1] = skinny64_rotate_right(state.row[1], 4);
        state.row[2] = skinny64_rotate_right(state.row[2], 8);
        state.row[3] = skinny64_rotate_right(state.row[3], 12);

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
    WRITE_WORD16(output, 0, state.row[0]);
    WRITE_WORD16(output, 2, state.row[1]);
    WRITE_WORD16(output, 4, state.row[2]);
    WRITE_WORD16(output, 6, state.row[3]);
}

void skinny64_ecb_decrypt
    (void *output, const void *input, const Skinny64Key_t *ks)
{
    Skinny64Cells_t state;
    const Skinny64HalfCells_t *schedule;
    unsigned index;
    uint32_t temp;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD16(input, 0);
    state.row[1] = READ_WORD16(input, 2);
    state.row[2] = READ_WORD16(input, 4);
    state.row[3] = READ_WORD16(input, 6);

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
        state.row[1] = skinny64_rotate_right(state.row[1], 12);
        state.row[2] = skinny64_rotate_right(state.row[2], 8);
        state.row[3] = skinny64_rotate_right(state.row[3], 4);

        /* Apply the subkey for this round */
        state.lrow[0] ^= schedule->lrow;
        state.row[2] ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        state.lrow[0] = skinny64_inv_sbox(state.lrow[0]);
        state.lrow[1] = skinny64_inv_sbox(state.lrow[1]);
    }

    /* Convert host-endian back into little-endian in the output buffer */
    WRITE_WORD16(output, 0, state.row[0]);
    WRITE_WORD16(output, 2, state.row[1]);
    WRITE_WORD16(output, 4, state.row[2]);
    WRITE_WORD16(output, 6, state.row[3]);
}
