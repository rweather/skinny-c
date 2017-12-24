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
#include <stdlib.h>

/** @cond */

/**
 * \brief Internal vtable for redirecting the parallel Skinny-128-ECB
 * implementation to different vectorized back ends.
 */
typedef struct
{
    void (*encrypt)(void *output, const void *input, const Skinny128Key_t *ks);
    void (*decrypt)(void *output, const void *input, const Skinny128Key_t *ks);

} Skinny128ParallelECBVtable_t;

void _skinny128_parallel_encrypt_vec128
    (void *output, const void *input, const Skinny128Key_t *ks);
void _skinny128_parallel_decrypt_vec128
    (void *output, const void *input, const Skinny128Key_t *ks);

static Skinny128ParallelECBVtable_t const skinny128_parallel_ecb_vec128 = {
    _skinny128_parallel_encrypt_vec128,
    _skinny128_parallel_decrypt_vec128
};

void _skinny128_parallel_encrypt_vec256
    (void *output, const void *input, const Skinny128Key_t *ks);
void _skinny128_parallel_decrypt_vec256
    (void *output, const void *input, const Skinny128Key_t *ks);

static Skinny128ParallelECBVtable_t const skinny128_parallel_ecb_vec256 = {
    _skinny128_parallel_encrypt_vec256,
    _skinny128_parallel_decrypt_vec256
};

/** @endcond */

int skinny128_parallel_ecb_init(Skinny128ParallelECB_t *ecb)
{
    Skinny128Key_t *ctx;
    if ((ctx = calloc(1, sizeof(Skinny128Key_t))) == NULL)
        return 0;
    ecb->vtable = 0;
    ecb->ctx = ctx;
    ecb->parallel_size = 4 * SKINNY128_BLOCK_SIZE;
    if (_skinny_has_vec128())
        ecb->vtable = &skinny128_parallel_ecb_vec128;
    if (_skinny_has_vec256()) {
        ecb->vtable = &skinny128_parallel_ecb_vec256;
        ecb->parallel_size = 8 * SKINNY128_BLOCK_SIZE;
    }
    return 1;
}

void skinny128_parallel_ecb_cleanup(Skinny128ParallelECB_t *ecb)
{
    if (ecb && ecb->ctx) {
        skinny_cleanse(ecb->ctx, sizeof(Skinny128Key_t));
        free(ecb->ctx);
        ecb->ctx = 0;
    }
}

int skinny128_parallel_ecb_set_key
    (Skinny128ParallelECB_t *ecb, const void *key, unsigned size)
{
    Skinny128Key_t *ks;
    if (!ecb || !ecb->ctx)
        return 0;
    ks = ecb->ctx;
    return skinny128_set_key(ks, key, size);
}

int skinny128_parallel_ecb_encrypt
    (void *output, const void *input, size_t size,
     const Skinny128ParallelECB_t *ecb)
{
    const Skinny128Key_t *ks;
    const Skinny128ParallelECBVtable_t *vtable;

    /* Validate the parameters */
    if (!ecb || !ecb->ctx || (size % SKINNY128_BLOCK_SIZE) != 0)
        return 0;
    ks = ecb->ctx;

    /* Process major blocks with the vectorized back end */
    vtable = ecb->vtable;
    if (vtable) {
        size_t psize = ecb->parallel_size;
        while (size >= psize) {
            (*(vtable->encrypt))(output, input, ks);
            output += psize;
            input += psize;
            size -= psize;
        }
    }

    /* Process any left-over blocks with the non-parallel implementation */
    while (size >= SKINNY128_BLOCK_SIZE) {
        skinny128_ecb_encrypt(output, input, ks);
        output += SKINNY128_BLOCK_SIZE;
        input += SKINNY128_BLOCK_SIZE;
        size -= SKINNY128_BLOCK_SIZE;
    }
    return 1;
}

int skinny128_parallel_ecb_decrypt
    (void *output, const void *input, size_t size,
     const Skinny128ParallelECB_t *ecb)
{
    const Skinny128Key_t *ks;
    const Skinny128ParallelECBVtable_t *vtable;

    /* Validate the parameters */
    if (!ecb || !ecb->ctx || (size % SKINNY128_BLOCK_SIZE) != 0)
        return 0;
    ks = ecb->ctx;

    /* Process major blocks with the vectorized back end */
    vtable = ecb->vtable;
    if (vtable) {
        size_t psize = ecb->parallel_size;
        while (size >= psize) {
            (*(vtable->decrypt))(output, input, ks);
            output += psize;
            input += psize;
            size -= psize;
        }
    }

    /* Process any left-over blocks with the non-parallel implementation */
    while (size >= SKINNY128_BLOCK_SIZE) {
        skinny128_ecb_decrypt(output, input, ks);
        output += SKINNY128_BLOCK_SIZE;
        input += SKINNY128_BLOCK_SIZE;
        size -= SKINNY128_BLOCK_SIZE;
    }
    return 1;
}
