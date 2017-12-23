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

#ifndef MANTIS_PARALLEL_h
#define MANTIS_PARALLEL_h

#include "mantis-cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup mantis
 */
/**@{*/

/**
 * \brief State information for Mantis in parallel ECB mode.
 */
typedef struct
{
    /** Vtable pointer for the actual parallel ECB implementation */
    const void *vtable;

    /** Dynamically-allocated context information */
    void *ctx;

    /** Recommended block size for encrypting data in parallel.
        Best performance is obtained when data is supplied in
        multiples of this size; e.g. 64 bytes for 8 blocks at a time */
    size_t parallel_size;

} MantisParallelECB_t;

/**
 * \brief Initializes Mantis in parallel ECB mode.
 *
 * \param ecb Points to the parallel ECB control block to initialize.
 *
 * \return Zero if \a ecb is NULL or there is insufficient memory to
 * create internal data structures, or non-zero if everything is OK.
 *
 * \sa mantis_ecb_set_key(), mantis_ecb_encrypt()
 */
int mantis_parallel_ecb_init(MantisParallelECB_t *ecb);

/**
 * \brief Cleans up a parallel ECB control block for Mantis.
 *
 * \param ecb Points to the parallel ECB control block to clean up.
 */
void mantis_parallel_ecb_cleanup(MantisParallelECB_t *ecb);

/**
 * \brief Sets the key schedule for a Mantis block cipher in
 * parallel ECB mode.
 *
 * \param ecb The parallel ECB control block to set the key on.
 * \param key Points to the key.
 * \param size Size of the key, which must be MANTIS_KEY_SIZE.
 * \param rounds The number of rounds to use, between MANTIS_MIN_ROUNDS and
 * MANTIS_MAX_ROUNDS.
 * \param mode MANTIS_ENCRYPT or MANTIS_DECRYPT to select the mode the
 * use when mantis_ecb_crypt() is called.  The mode can be altered later
 * by calling mantis_parallel_ecb_swap_modes().
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.
 */
int mantis_parallel_ecb_set_key
    (MantisParallelECB_t *ecb, const void *key, unsigned size,
     unsigned rounds, int mode);

/**
 * \brief Swaps the encryption and decryption modes on a parallel Mantis
 * key schedule.
 *
 * \param ecb The parallel ECB control block to modify.
 */
void mantis_parallel_ecb_swap_modes(MantisParallelECB_t *ecb);

/**
 * \brief Encrypts or decrypts a block of data using Mantis in
 * parallel ECB mode.
 *
 * \param output The output buffer for the ciphertext.
 * \param input The input buffer containing the plaintext.
 * \param tweak A buffer containing the tweak values to use for each
 * block in the input.
 * \param size The number of bytes to be encrypted, which must be a
 * multiple of MANTIS_BLOCK_SIZE.
 * \param ecb The parallel ECB control block to use and update.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the data was encrypted.
 *
 * For best performance, \a size should be a multiple of the
 * parallel_size value in to the \a ecb structure.
 *
 * The encryption or decryption mode is selected when the key schedule
 * is setup by mantis_set_key().  The mode can also be altered on the
 * fly by calling mantis_parallel_ecb_swap_modes().
 */
int mantis_parallel_ecb_crypt
    (void *output, const void *input, const void *tweak, size_t size,
     const MantisParallelECB_t *ecb);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
