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

#ifndef MANTIS_CIPHER_h
#define MANTIS_CIPHER_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \defgroup mantis Mantis API
 * \brief MANTIS tweakable block cipher with 64-bit blocks.
 *
 * Mantis is a tweakable block cipher with 64-bit blocks, a 128-bit
 * key, and a 64-bit tweak.  It is a variant of SKINNY that is designed
 * for memory encryption.  Typically, memory is encrypted in 8-byte blocks
 * in ECB mode with the memory address of each block supplied to the
 * cipher as the tweak.
 *
 * Mantis comes in variants with round counts between 5 and 8.
 * The authors advise that there is a known efficient attack
 * against Mantis-5.  They recommend using at least Mantis-7.
 * For an even larger security margin, use \ref skinny64 "Skinny-64"
 * or \ref skinny128 "Skinny-128" instead of Mantis.
 *
 * In Mantis, ECB encryption and decryption are provided by the
 * same function mantis_ecb_crypt().  The initial mode is selected by
 * an argument to mantis_set_key() and can be changed to the other mode
 * on the fly without a new key setup by calling mantis_swap_modes().
 */
/**@{*/

/**
 * \brief Size of a block for Mantis block ciphers.
 */
#define MANTIS_BLOCK_SIZE 8

/**
 * \brief Size of a Mantis block cipher key.
 */
#define MANTIS_KEY_SIZE 16

/**
 * \brief Size of a Mantis block cipher tweak.
 */
#define MANTIS_TWEAK_SIZE 8

/**
 * \brief Minimum number of rounds for Mantis block ciphers.
 *
 * \note The authors advise that there is a known efficient attack
 * against Mantis-5.  They recommend using at least Mantis-7.
 */
#define MANTIS_MIN_ROUNDS 5

/**
 * \brief Maximum number of rounds for Mantis block ciphers.
 */
#define MANTIS_MAX_ROUNDS 8

/**
 * \brief Mode that selects Mantis encryption when the key schedule is setup.
 */
#define MANTIS_ENCRYPT 1

/**
 * \brief Mode that selects Mantis decryption when the key schedule is setup.
 */
#define MANTIS_DECRYPT 0

/**
 * \brief Union that describes a 64-bit 4x4 array of cells.
 */
typedef union
{
    uint16_t row[4];        /**< Cell rows in 16-bit units */
    uint32_t lrow[2];       /**< Cell rows in 32-bit units */

} MantisCells_t;

/**
 * \brief Key schedule for Mantis block ciphers.
 */
typedef struct
{
    /** First 64 bits of the incoming key */
    MantisCells_t k0;

    /** Transformed version of the first 64 bits of the incoming key */
    MantisCells_t k0prime;

    /** Second 64 bits of the incoming key */
    MantisCells_t k1;

    /** Current tweak value */
    MantisCells_t tweak;

    /** Number of encryption/decryption rounds (half the full amount) */
    unsigned rounds;

} MantisKey_t;

/**
 * \brief Sets the key schedule for a Mantis block cipher.
 *
 * \param ks The key schedule structure to populate.
 * \param key Points to the key.
 * \param size Size of the key, which must be MANTIS_KEY_SIZE.
 * \param rounds The number of rounds to use, between MANTIS_MIN_ROUNDS and
 * MANTIS_MAX_ROUNDS.
 * \param mode MANTIS_ENCRYPT or MANTIS_DECRYPT to select the mode the
 * use when mantis_ecb_crypt() is called.  The mode can be altered later
 * by calling mantis_swap_modes().
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.
 *
 * The initial tweak value will be all-zeroes.  Call mantis_set_tweak()
 * after this function to set a different tweak.
 *
 * \note The \a rounds value will be doubled to get the actual round count.
 * Mantis consists of a set of forward rounds followed by an equal number
 * of reverse rounds.
 *
 * \sa mantis_set_tweak(), mantis_swap_modes()
 */ 
int mantis_set_key
    (MantisKey_t *ks, const void *key, unsigned size,
     unsigned rounds, int mode);

/**
 * \brief Sets the tweak value for a previously-initialized key schedule.
 *
 * \param ks The key schedule to change.
 * \param tweak The new tweak value, or NULL for a zero tweak.
 * \param size Size of the tweak value; must be MANTIS_TWEAK_SIZE.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the tweak was changed.
 *
 * \sa mantis_set_key()
 */
int mantis_set_tweak(MantisKey_t *ks, const void *tweak, unsigned size);

/**
 * \brief Swaps the encryption and decryption modes on a Mantis key schedule.
 *
 * \param ks The key schedule to change.
 */
void mantis_swap_modes(MantisKey_t *ks);

/**
 * \brief Encrypts or decrypts a single block using the Mantis block
 * cipher in ECB mode.
 *
 * \param output The output block, which must contain at least
 * MANTIS_BLOCK_SIZE bytes of space for the ciphertext.
 * \param input The input block, which must contain at least
 * MANTIS_BLOCK_SIZE bytes of plaintext data.
 * \param ks The key schedule that was set up by mantis_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 *
 * The encryption or decryption mode is selected when the key schedule
 * is setup by mantis_set_key() or mantis_set_key_and_tweak().
 * The mode can also be altered on the fly by calling mantis_swap_modes().
 */
void mantis_ecb_crypt(void *output, const void *input, const MantisKey_t *ks);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
