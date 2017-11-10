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

#ifndef SKINNY64_CIPHER_h
#define SKINNY64_CIPHER_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \defgroup skinny64 Skinny-64 API
 * \brief SKINNY tweakable block cipher with 64-bit blocks.
 *
 * Skinny-64 is a block cipher with 64-bit blocks and a choice of key
 * sizes between 64-bit and 192-bit.  Alternatively, Skinny-64 can be
 * used as a tweakable block cipher with a 64-bit tweak and between
 * 64-bit and 128-bit keys.
 */
/**@{*/

/**
 * \brief Size of a block for Skinny64 block ciphers.
 */
#define SKINNY64_BLOCK_SIZE 8

/**
 * \brief Maximum number of rounds for Skinny64 block ciphers.
 */
#define SKINNY64_MAX_ROUNDS 40

/**
 * \brief Union that describes a 64-bit 4x4 array of cells.
 */
typedef union
{
    uint16_t row[4];        /**< Cell rows in 16-bit units */
    uint32_t lrow[2];       /**< Cell rows in 32-bit units */

} Skinny64Cells_t;

/**
 * \brief Union that describes a 32-bit 2x4 array of cells.
 */
typedef union
{
    uint16_t row[2];        /**< Cell rows in 16-bit units */
    uint32_t lrow;          /**< Cell rows in 32-bit units */

} Skinny64HalfCells_t;

/**
 * \brief Key schedule for Skinny64 block ciphers.
 */
typedef struct
{
    /** Number of encryption/decryption rounds */
    unsigned rounds;

    /** All words of the key schedule */
    Skinny64HalfCells_t schedule[SKINNY64_MAX_ROUNDS];

} Skinny64Key_t;

/**
 * \brief Key schedule for Skinny64 block ciphers when a tweak is in use.
 */
typedef struct
{
    /** Basic key schedule, including the current tweak */
    Skinny64Key_t ks;

    /** Current tweak value, to assist with changing it */
    Skinny64Cells_t tweak;

} Skinny64TweakedKey_t;

/**
 * \brief State information for Skinny-64 in CTR mode.
 *
 * This structure should be treated as opaque.  The names and meaning
 * of the fields below may not have identical behaviour between regular
 * and vector-based implementations of CTR mode.
 */
typedef struct
{
    /** Counter value for the next block */
    unsigned char counter[SKINNY64_BLOCK_SIZE];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[SKINNY64_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

    /** Extension data.  May be used by vector-based implementations
        to store multiple counter blocks for parallel encryption */
    void *ext;

} Skinny64CTR_t;

/**
 * \brief Sets the key schedule for a Skinny64 block cipher.
 *
 * \param ks The key schedule structure to populate.
 * \param key Points to the key.
 * \param size Size of the key, between 8 and 24 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.
 *
 * The primary key sizes are 8, 16, and 24.  In-between sizes will be
 * padded with zero bytes to the next primary key size.
 */ 
int skinny64_set_key(Skinny64Key_t *ks, const void *key, unsigned size);

/**
 * \brief Sets the key schedule for a Skinny64 block cipher, plus an
 * initial tweak value of zero.
 *
 * \param ks The key schedule structure to populate.
 * \param key Points to the key.
 * \param key_size Size of the key, between 8 and 16 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key and tweak were set.
 *
 * The primary key sizes are 8 and 16.  In-between sizes will be
 * padded with zero bytes to the next primary key size.  If the tweak
 * is less than 8 bytes in size, it will be padded with zeroes.
 *
 * Once the initial key and tweak have been set, the tweak can be changed
 * later by calling skinny64_set_tweak().
 *
 * \sa skinny64_set_tweak()
 */
int skinny64_set_tweaked_key
    (Skinny64TweakedKey_t *ks, const void *key, unsigned key_size);

/**
 * \brief Changes the tweak value for a previously-initialized key schedule.
 *
 * \param ks The key schedule to change.
 * \param tweak The new tweak value, or NULL for a zero tweak.
 * \param tweak_size Size of the new tweak value; between 1 and 8 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the tweak was changed.
 *
 * This function modifies the key schedule to change the tweak from its
 * previous value to the new value given by \a tweak.
 *
 * \sa skinny64_set_tweaked_key()
 */
int skinny64_set_tweak
    (Skinny64TweakedKey_t *ks, const void *tweak, unsigned tweak_size);

/**
 * \brief Encrypts a single block using the Skinny64 block cipher in ECB mode.
 *
 * \param output The output block, which must contain at least
 * SKINNY64_BLOCK_SIZE bytes of space for the ciphertext.
 * \param input The input block, which must contain at least
 * SKINNY64_BLOCK_SIZE bytes of plaintext data.
 * \param ks The key schedule that was set up by skinny64_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 */
void skinny64_ecb_encrypt
    (void *output, const void *input, const Skinny64Key_t *ks);

/**
 * \brief Decrypts a single block using the Skinny64 block cipher in ECB mode.
 *
 * \param output The output block, which must contain at least
 * SKINNY64_BLOCK_SIZE bytes of space for the plaintext.
 * \param input The input block, which must contain at least
 * SKINNY64_BLOCK_SIZE bytes of ciphertext data.
 * \param ks The key schedule that was set up by skinny64_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 */
void skinny64_ecb_decrypt
    (void *output, const void *input, const Skinny64Key_t *ks);

/**
 * \brief Initializes Skinny-64 in CTR mode.
 *
 * \param ctr Points to the CTR control block to initialize.
 *
 * \return Zero if \a ctr is NULL or there is insufficient memory to
 * create internal data structures, or non-zero if everything is OK.
 *
 * The counter block is initially set to all-zeroes.
 *
 * \sa skinny64_ctr_set_counter(), skinny64_ctr_encrypt()
 */
int skinny64_ctr_init(Skinny64CTR_t *ctr);

/**
 * \brief Cleans up a CTR control block for Skinny-64.
 *
 * \param ctr Points to the CTR control block to clean up.
 */
void skinny64_ctr_cleanup(Skinny64CTR_t *ctr);

/**
 * \brief Sets the counter value in a Skinny-64 CTR control block.
 *
 * \param ctr The CTR control block to modify.
 * \param counter The counter value to set, which may be NULL
 * to specify an all-zeroes counter.
 * \param size The size of the counter in bytes, between 0 and
 * SKINNY64_BLOCK_SIZE.  Short counter blocks are padded on the
 * left with zeroes to make up a full SKINNY64_BLOCK_SIZE bytes.
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
 * that the next call to skinny64_ctr_encrypt() will start with the
 * new counter value.  Usually this occurs at the start of a packet.
 */
int skinny64_ctr_set_counter
    (Skinny64CTR_t *ctr, const void *counter, unsigned size);

/**
 * \brief Encrypt a block of data using Skinny-64 in CTR mode.
 *
 * \param output The output buffer for the ciphertext.
 * \param input The input buffer containing the plaintext.
 * \param size The number of bytes to be encrypted.
 * \param ks The key schedule to use to encrypt the counter values.
 * \param ctr The CTR control block to use and update.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the data was encrypted.
 *
 * This function can also be used for CTR mode decryption.
 */
int skinny64_ctr_encrypt
    (void *output, const void *input, size_t size,
     const Skinny64Key_t *ks, Skinny64CTR_t *ctr);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
