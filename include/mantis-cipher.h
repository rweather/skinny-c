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
#include <stddef.h>

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
    uint64_t llrow;         /**< Cell rows in 64-bit units */

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
 * \brief State information for Mantis in CTR mode.
 */
typedef struct
{
    /** Vtable pointer for the actual CTR implementation */
    const void *vtable;

    /** Dynamically-allocated context information */
    void *ctx;

} MantisCTR_t;

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
 * is setup by mantis_set_key().  The mode can also be altered on the
 * fly by calling mantis_swap_modes().
 *
 * \sa mantis_ecb_crypt_tweaked()
 */
void mantis_ecb_crypt(void *output, const void *input, const MantisKey_t *ks);

/**
 * \brief Encrypts or decrypts a single block using the Mantis block
 * cipher in ECB mode, with the tweak supplied explicitly.
 *
 * \param output The output block, which must contain at least
 * MANTIS_BLOCK_SIZE bytes of space for the ciphertext.
 * \param input The input block, which must contain at least
 * MANTIS_BLOCK_SIZE bytes of plaintext data.
 * \param tweak The tweak block, which must contain at least
 * MANTIS_BLOCK_SIZE bytes of tweak data.
 * \param ks The key schedule that was set up by mantis_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 *
 * The encryption or decryption mode is selected when the key schedule
 * is setup by mantis_set_key().  The mode can also be altered on the
 * fly by calling mantis_swap_modes().
 *
 * This function differs from mantis_ecb_crypt() in that the tweak is
 * supplied explicitly to the function rather than via mantis_set_tweak().
 * This can be useful if every block that is encrypted or decrypted
 * has its own block-specific tweak.
 *
 * \sa mantis_ecb_crypt()
 */
void mantis_ecb_crypt_tweaked
    (void *output, const void *input, const void *tweak, const MantisKey_t *ks);

/**
 * \brief Initializes Mantis in CTR mode.
 *
 * \param ctr Points to the CTR control block to initialize.
 *
 * \return Zero if \a ctr is NULL or there is insufficient memory to
 * create internal data structures, or non-zero if everything is OK.
 *
 * The counter block is initially set to all-zeroes.
 *
 * \sa mantis_ctr_set_counter(), mantis_ctr_encrypt()
 */
int mantis_ctr_init(MantisCTR_t *ctr);

/**
 * \brief Cleans up a CTR control block for Mantis.
 *
 * \param ctr Points to the CTR control block to clean up.
 */
void mantis_ctr_cleanup(MantisCTR_t *ctr);

/**
 * \brief Sets the key schedule for a Mantis block cipher in CTR mode.
 *
 * \param ctr The CTR control block to set the key on.
 * \param key Points to the key.
 * \param size Size of the key, which must be MANTIS_KEY_SIZE.
 * \param rounds The number of rounds to use, between MANTIS_MIN_ROUNDS and
 * MANTIS_MAX_ROUNDS.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.  The tweak will be set to zero.
 *
 * Calling this function will also reset the keystream position so
 * that the next call to mantis_ctr_encrypt() will start with the
 * new key.  Usually this occurs at the start of a packet.
 *
 * \sa mantis_ctr_set_tweak()
 */
int mantis_ctr_set_key
    (MantisCTR_t *ctr, const void *key, unsigned size, unsigned rounds);

/**
 * \brief Changes the tweak value for a previously-initialized key schedule.
 *
 * \param ctr The CTR control block to set the tweak on.
 * \param tweak The new tweak value, or NULL for a zero tweak.
 * \param tweak_size Size of the new tweak value; between 1 and 16 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the tweak was changed.
 *
 * This function modifies the key schedule to change the tweak from its
 * previous value to the new value given by \a tweak.
 *
 * Calling this function will also reset the keystream position so
 * that the next call to mantis_ctr_encrypt() will start with the
 * new counter value.  Usually this occurs at the start of a packet.
 *
 * \sa mantis_ctr_set_key()
 */
int mantis_ctr_set_tweak
    (MantisCTR_t *ctr, const void *tweak, unsigned tweak_size);

/**
 * \brief Sets the counter value in a Mantis CTR control block.
 *
 * \param ctr The CTR control block to modify.
 * \param counter The counter value to set, which may be NULL
 * to specify an all-zeroes counter.
 * \param size The size of the counter in bytes, between 0 and
 * MANTIS_BLOCK_SIZE.  Short counter blocks are padded on the
 * left with zeroes to make up a full MANTIS_BLOCK_SIZE bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the counter has been set.
 *
 * The counter is assumed to be in big-endian order, incremented
 * from the right-most byte forward, as in the standard AES-CTR mode.
 * Often the counter block will contain a packet sequence number or
 * equivalent in the left-most bytes with the right-most bytes used
 * to count blocks within the specified packet.
 *
 * Calling this function will also reset the keystream position so
 * that the next call to mantis_ctr_encrypt() will start with the
 * new counter value.  Usually this occurs at the start of a packet.
 */
int mantis_ctr_set_counter
    (MantisCTR_t *ctr, const void *counter, unsigned size);

/**
 * \brief Encrypt a block of data using Mantis in CTR mode.
 *
 * \param output The output buffer for the ciphertext.
 * \param input The input buffer containing the plaintext.
 * \param size The number of bytes to be encrypted.
 * \param ctr The CTR control block to use and update.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the data was encrypted.
 *
 * This function can also be used for CTR mode decryption.
 */
int mantis_ctr_encrypt
    (void *output, const void *input, size_t size, MantisCTR_t *ctr);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
