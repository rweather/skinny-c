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

#include "skinny64-parallel.h"
#include "skinny-internal.h"
#include <stdlib.h>

/** @cond */

/**
 * \brief Internal vtable for redirecting the parallel Skinny-64-ECB
 * implementation to different vectorized back ends.
 */
typedef struct
{
    void (*encrypt)(void *output, const void *input, const Skinny64Key_t *ks);
    void (*decrypt)(void *output, const void *input, const Skinny64Key_t *ks);

} Skinny64ParallelECBVtable_t;

void _skinny64_parallel_encrypt_vec128
    (void *output, const void *input, const Skinny64Key_t *ks);
void _skinny64_parallel_decrypt_vec128
    (void *output, const void *input, const Skinny64Key_t *ks);

static Skinny64ParallelECBVtable_t const skinny64_parallel_ecb_vec128 = {
    _skinny64_parallel_encrypt_vec128,
    _skinny64_parallel_decrypt_vec128
};

/** @endcond */

int skinny64_parallel_ecb_init(Skinny64ParallelECB_t *ecb)
{
    Skinny64Key_t *ctx;
    if ((ctx = calloc(1, sizeof(Skinny64Key_t))) == NULL)
        return 0;
    ecb->vtable = 0;
    ecb->ctx = ctx;
    ecb->parallel_size = 8 * SKINNY64_BLOCK_SIZE;
    if (_skinny_has_vec128())
        ecb->vtable = &skinny64_parallel_ecb_vec128;
    return 1;
}

void skinny64_parallel_ecb_cleanup(Skinny64ParallelECB_t *ecb)
{
    if (ecb && ecb->ctx) {
        skinny_cleanse(ecb->ctx, sizeof(Skinny64Key_t));
        free(ecb->ctx);
        ecb->ctx = 0;
    }
}

int skinny64_parallel_ecb_set_key
    (Skinny64ParallelECB_t *ecb, const void *key, unsigned size)
{
    Skinny64Key_t *ks;
    if (!ecb || !ecb->ctx)
        return 0;
    ks = ecb->ctx;
    return skinny64_set_key(ks, key, size);
}

int skinny64_parallel_ecb_encrypt
    (void *output, const void *input, size_t size,
     const Skinny64ParallelECB_t *ecb)
{
    const Skinny64Key_t *ks;
    const Skinny64ParallelECBVtable_t *vtable;

    /* Validate the parameters */
    if (!ecb || !ecb->ctx || (size % SKINNY64_BLOCK_SIZE) != 0)
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
    while (size >= SKINNY64_BLOCK_SIZE) {
        skinny64_ecb_encrypt(output, input, ks);
        output += SKINNY64_BLOCK_SIZE;
        input += SKINNY64_BLOCK_SIZE;
        size -= SKINNY64_BLOCK_SIZE;
    }
    return 1;
}

int skinny64_parallel_ecb_decrypt
    (void *output, const void *input, size_t size,
     const Skinny64ParallelECB_t *ecb)
{
    const Skinny64Key_t *ks;
    const Skinny64ParallelECBVtable_t *vtable;

    /* Validate the parameters */
    if (!ecb || !ecb->ctx || (size % SKINNY64_BLOCK_SIZE) != 0)
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
    while (size >= SKINNY64_BLOCK_SIZE) {
        skinny64_ecb_decrypt(output, input, ks);
        output += SKINNY64_BLOCK_SIZE;
        input += SKINNY64_BLOCK_SIZE;
        size -= SKINNY64_BLOCK_SIZE;
    }
    return 1;
}
