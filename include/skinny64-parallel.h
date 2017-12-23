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

#ifndef SKINNY64_PARALLEL_h
#define SKINNY64_PARALLEL_h

#include "skinny64-cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup skinny64
 */
/**@{*/

/**
 * \brief State information for Skinny-64 in parallel ECB mode.
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

} Skinny64ParallelECB_t;

/**
 * \brief Initializes Skinny-64 in parallel ECB mode.
 *
 * \param ecb Points to the parallel ECB control block to initialize.
 *
 * \return Zero if \a ecb is NULL or there is insufficient memory to
 * create internal data structures, or non-zero if everything is OK.
 *
 * \sa skinny64_ecb_set_key(), skinny64_ecb_encrypt()
 */
int skinny64_parallel_ecb_init(Skinny64ParallelECB_t *ecb);

/**
 * \brief Cleans up a parallel ECB control block for Skinny-64.
 *
 * \param ecb Points to the parallel ECB control block to clean up.
 */
void skinny64_parallel_ecb_cleanup(Skinny64ParallelECB_t *ecb);

/**
 * \brief Sets the key schedule for a Skinny64 block cipher in
 * parallel ECB mode.
 *
 * \param ecb The parallel ECB control block to set the key on.
 * \param key Points to the key.
 * \param size Size of the key, between 8 and 24 bytes.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the key has been set.
 *
 * The primary key sizes are 8, 16, and 24.  In-between sizes will be
 * padded with zero bytes to the next primary key size.
 */
int skinny64_parallel_ecb_set_key
    (Skinny64ParallelECB_t *ecb, const void *key, unsigned size);

/**
 * \brief Encrypt a block of data using Skinny-64 in parallel ECB mode.
 *
 * \param output The output buffer for the ciphertext.
 * \param input The input buffer containing the plaintext.
 * \param size The number of bytes to be encrypted, which must be a
 * multiple of SKINNY64_BLOCK_SIZE.
 * \param ecb The parallel ECB control block to use and update.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the data was encrypted.
 *
 * For best performance, \a size should be a multiple of the
 * parallel_size value in to the \a ecb structure.
 *
 * \sa skinny64_parallel_ecb_decrypt()
 */
int skinny64_parallel_ecb_encrypt
    (void *output, const void *input, size_t size,
     const Skinny64ParallelECB_t *ecb);

/**
 * \brief Decrypt a block of data using Skinny-64 in parallel ECB mode.
 *
 * \param output The output buffer for the plaintext.
 * \param input The input buffer containing the ciphertext.
 * \param size The number of bytes to be decrypted, which must be a
 * multiple of SKINNY64_BLOCK_SIZE.
 * \param ecb The parallel ECB control block to use and update.
 *
 * \return Zero if there is something wrong with the parameters,
 * or 1 if the data was encrypted.
 *
 * For best performance, \a size should be a multiple of the
 * parallel_size value in to the \a ecb structure.
 *
 * \sa skinny64_parallel_ecb_encrypt()
 */
int skinny64_parallel_ecb_decrypt
    (void *output, const void *input, size_t size,
     const Skinny64ParallelECB_t *ecb);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif
