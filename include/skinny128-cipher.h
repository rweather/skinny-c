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
#include <stddef.h>

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
    uint8_t tweak[SKINNY128_BLOCK_SIZE];

} Skinny128TweakedKey_t;

/**
 * \brief State information for Skinny-128 in CTR mode.
 */
typedef struct
{
    /** Vtable pointer for the actual CTR implementation */
    const void *vtable;

    /** Dynamically-allocated context information */
    void *ctx;

} Skinny128CTR_t;

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
 * \brief Sets the key schedule for a Skinny128 block cipher,
 * and prepare for tweaked encryption.
 *
 * \param ks The key schedule structure to populate.
 * \param key Points to the key.
 * \param key_size Size of the key, between 16 and 32 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key and tweak were set.
 *
 * The primary key sizes are 16 and 32.  In-between sizes will be
 * padded with zero bytes to the next primary key size.  The initial
 * tweak will be all-zeroes.
 *
 * Once the initial key and tweak have been set, the tweak can be changed
 * later by calling skinny128_set_tweak().
 *
 * \sa skinny128_set_tweak()
 */
int skinny128_set_tweaked_key
    (Skinny128TweakedKey_t *ks, const void *key, unsigned key_size);

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
 * \sa skinny128_set_tweaked_key()
 */
int skinny128_set_tweak
    (Skinny128TweakedKey_t *ks, const void *tweak, unsigned tweak_size);

/**
 * \brief Encrypts a single block using the Skinny128 block cipher in ECB mode.
 *
 * \param output The output block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of space for the ciphertext.
 * \param input The input block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of plaintext data.
 * \param ks The key schedule that was set up by skinny128_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 */
void skinny128_ecb_encrypt
    (void *output, const void *input, const Skinny128Key_t *ks);

/**
 * \brief Decrypts a single block using the Skinny128 block cipher in ECB mode.
 *
 * \param output The output block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of space for the plaintext.
 * \param input The input block, which must contain at least
 * SKINNY128_BLOCK_SIZE bytes of ciphertext data.
 * \param ks The key schedule that was set up by skinny128_set_key().
 *
 * The \a input and \a output blocks are allowed to overlap.
 */
void skinny128_ecb_decrypt
    (void *output, const void *input, const Skinny128Key_t *ks);

/**
 * \brief Initializes Skinny-128 in CTR mode.
 *
 * \param ctr Points to the CTR control block to initialize.
 *
 * \return Zero if \a ctr is NULL or there is insufficient memory to
 * create internal data structures, or non-zero if everything is OK.
 *
 * The counter block is initially set to all-zeroes.
 *
 * \sa skinny128_ctr_set_counter(), skinny128_ctr_encrypt()
 */
int skinny128_ctr_init(Skinny128CTR_t *ctr);

/**
 * \brief Cleans up a CTR control block for Skinny-128.
 *
 * \param ctr Points to the CTR control block to clean up.
 */
void skinny128_ctr_cleanup(Skinny128CTR_t *ctr);

/**
 * \brief Sets the key schedule for a Skinny128 block cipher in CTR mode.
 *
 * \param ctr The CTR control block to set the key on.
 * \param key Points to the key.
 * \param size Size of the key, between 16 and 48 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.
 *
 * The primary key sizes are 16, 32, and 48.  In-between sizes will be
 * padded with zero bytes to the next primary key size.
 *
 * Calling this function will also reset the keystream position so
 * that the next call to skinny128_ctr_encrypt() will start with the
 * new key.  Usually this occurs at the start of a packet.
 */
int skinny128_ctr_set_key(Skinny128CTR_t *ctr, const void *key, unsigned size);

/**
 * \brief Sets the key schedule for a Skinny128 block cipher in CTR mode,
 * and prepare for tweaked encryption.
 *
 * \param ctr The CTR control block to set the key on.
 * \param key Points to the key.
 * \param key_size Size of the key, between 16 and 32 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key and tweak were set.
 *
 * The primary key sizes are 16 and 32.  In-between sizes will be
 * padded with zero bytes to the next primary key size.  The initial
 * tweak will be all-zeroes.
 *
 * Once the initial key and tweak have been set, the tweak can be changed
 * later by calling skinny128_ctr_set_tweak().
 *
 * Calling this function will also reset the keystream position so
 * that the next call to skinny128_ctr_encrypt() will start with the
 * new tweak.  Usually this occurs at the start of a packet.
 *
 * \sa skinny128_ctr_set_tweak()
 */
int skinny128_ctr_set_tweaked_key
    (Skinny128CTR_t *ctr, const void *key, unsigned key_size);

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
 * that the next call to skinny128_ctr_encrypt() will start with the
 * new counter value.  Usually this occurs at the start of a packet.
 *
 * \sa skinny128_ctr_set_tweaked_key()
 */
int skinny128_ctr_set_tweak
    (Skinny128CTR_t *ctr, const void *tweak, unsigned tweak_size);

/**
 * \brief Sets the counter value in a Skinny-128 CTR control block.
 *
 * \param ctr The CTR control block to modify.
 * \param counter The counter value to set, which may be NULL
 * to specify an all-zeroes counter.
 * \param size The size of the counter in bytes, between 0 and
 * SKINNY128_BLOCK_SIZE.  Short counter blocks are padded on the
 * left with zeroes to make up a full SKINNY128_BLOCK_SIZE bytes.
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
 * that the next call to skinny128_ctr_encrypt() will start with the
 * new counter value.  Usually this occurs at the start of a packet.
 */
int skinny128_ctr_set_counter
    (Skinny128CTR_t *ctr, const void *counter, unsigned size);

/**
 * \brief Encrypt a block of data using Skinny-128 in CTR mode.
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
int skinny128_ctr_encrypt
    (void *output, const void *input, size_t size, Skinny128CTR_t *ctr);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
