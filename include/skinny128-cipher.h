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

#ifndef SKINNY128_CIPHER_h
#define SKINNY128_CIPHER_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \defgroup skinny128 Skinny-128 API
 * \brief SKINNY tweakable block cipher with 128-bit blocks.
 *
 * Skinny-128 is a block cipher with 128-bit blocks and a choice of key
 * sizes between 128-bit and 384-bit.  Alternatively, Skinny-128 can be
 * used as a tweakable block cipher with a 128-bit tweak and between
 * 128-bit and 256-bit keys.
 */
/**@{*/

/**
 * \brief Size of a block for Skinny128 block ciphers.
 */
#define SKINNY128_BLOCK_SIZE 16

/**
 * \brief Maximum number of rounds for Skinny128 block ciphers.
 */
#define SKINNY128_MAX_ROUNDS 56

/**
 * \brief Union that describes a 128-bit 4x4 array of cells.
 */
typedef union
{
    uint32_t row[4];        /**< Cell rows in 32-bit units */
    uint64_t lrow[2];       /**< Cell rows in 64-bit units */

} Skinny128Cells_t;

/**
 * \brief Union that describes a 64-bit 2x4 array of cells.
 */
typedef union
{
    uint32_t row[2];        /**< Cell rows in 32-bit units */
    uint64_t lrow;          /**< Cell rows in 64-bit units */

} Skinny128HalfCells_t;

/**
 * \brief Key schedule for Skinny128 block ciphers.
 */
typedef struct
{
    /** Number of encryption/decryption rounds */
    unsigned rounds;

    /** All words of the key schedule */
    Skinny128HalfCells_t schedule[SKINNY128_MAX_ROUNDS];

} Skinny128Key_t;

/**
 * \brief Key schedule for Skinny128 block ciphers when a tweak is in use.
 */
typedef struct
{
    /** Basic key schedule, including the current tweak */
    Skinny128Key_t ks;

    /** Current tweak value, to assist with changing it */
    Skinny128Cells_t tweak;

} Skinny128TweakedKey_t;

/**
 * \brief Sets the key schedule for a Skinny128 block cipher.
 *
 * \param ks The key schedule structure to populate.
 * \param key Points to the key.
 * \param size Size of the key, between 16 and 48 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.
 *
 * The primary key sizes are 16, 32, and 48.  In-between sizes will be
 * padded with zero bytes to the next primary key size.
 */ 
int skinny128_set_key(Skinny128Key_t *ks, const void *key, unsigned size);

/**
 * \brief Sets the key schedule for a Skinny128 block cipher, plus an
 * initial tweak value.
 *
 * \param ks The key schedule structure to populate.
 * \param key Points to the key.
 * \param key_size Size of the key, between 16 and 32 bytes.
 * \param tweak Points to the initial tweak value, or NULL if zero.
 * \param tweak_size Size of the tweak value, between 1 and 16 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key and tweak were set.
 *
 * The primary key sizes are 16 and 32.  In-between sizes will be
 * padded with zero bytes to the next primary key size.  If the tweak
 * is less than 16 bytes in size, it will be padded with zeroes.
 *
 * Once the initial key and tweak have been set, the tweak can be changed
 * later by calling skinny128_change_tweak().
 *
 * \sa skinny128_change_tweak()
 */
int skinny128_set_key_and_tweak
    (Skinny128TweakedKey_t *ks, const void *key, unsigned key_size,
     const void *tweak, unsigned tweak_size);

/**
 * \brief Changes the tweak value for a previously-initialized key schedule.
 *
 * \param ks The key schedule to change.
 * \param tweak The new tweak value, or NULL for a zero tweak.
 * \param tweak_size Size of the new tweak value; between 1 and 16 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the tweak was changed.
 *
 * This function modifies the key schedule to change the tweak from its
 * previous value to the new value given by \a tweak.
 *
 * \sa skinny128_set_key_and_tweak()
 */
int skinny128_change_tweak
    (Skinny128TweakedKey_t *ks, const void *tweak, unsigned tweak_size);

/**
 * \brief Encrypts a single block using the Skinny128 block cipher.
 *
 * \param output The output block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of space for the ciphertext.
 * \param input The input block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of plaintext data.
 * \param ks The key schedule that was set up by skinny128_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 */
void skinny128_encrypt(void *output, const void *input, const Skinny128Key_t *ks);

/**
 * \brief Decrypts a single block using the Skinny128 block cipher.
 *
 * \param output The output block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of space for the plaintext.
 * \param input The input block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of ciphertext data.
 * \param ks The key schedule that was set up by skinny128_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 */
void skinny128_decrypt(void *output, const void *input, const Skinny128Key_t *ks);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
