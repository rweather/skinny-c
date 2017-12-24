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

#include "mantis-parallel.h"
#include "skinny-internal.h"
#include <stdlib.h>

/** @cond */

/**
 * \brief Internal vtable for redirecting the parallel Mantis-ECB
 * implementation to different vectorized back ends.
 */
typedef struct
{
    void (*crypt)(void *output, const void *input, const void *tweak,
                  const MantisKey_t *ks);

} MantisParallelECBVtable_t;

void _mantis_parallel_crypt_vec128
    (void *output, const void *input, const void *tweak, const MantisKey_t *ks);

static MantisParallelECBVtable_t const mantis_parallel_ecb_vec128 = {
    _mantis_parallel_crypt_vec128
};

/** @endcond */

int mantis_parallel_ecb_init(MantisParallelECB_t *ecb)
{
    MantisKey_t *ctx;
    if ((ctx = calloc(1, sizeof(MantisKey_t))) == NULL)
        return 0;
    ecb->vtable = 0;
    ecb->ctx = ctx;
    ecb->parallel_size = 8 * MANTIS_BLOCK_SIZE;
    if (_skinny_has_vec128())
        ecb->vtable = &mantis_parallel_ecb_vec128;
    return 1;
}

void mantis_parallel_ecb_cleanup(MantisParallelECB_t *ecb)
{
    if (ecb && ecb->ctx) {
        skinny_cleanse(ecb->ctx, sizeof(MantisKey_t));
        free(ecb->ctx);
        ecb->ctx = 0;
    }
}

int mantis_parallel_ecb_set_key
    (MantisParallelECB_t *ecb, const void *key, unsigned size,
     unsigned rounds, int mode)
{
    MantisKey_t *ks;
    if (!ecb || !ecb->ctx)
        return 0;
    ks = ecb->ctx;
    return mantis_set_key(ks, key, size, rounds, mode);
}

void mantis_parallel_ecb_swap_modes(MantisParallelECB_t *ecb)
{
    MantisKey_t *ks;
    if (!ecb || !ecb->ctx)
        return;
    ks = ecb->ctx;
    mantis_swap_modes(ks);
}

int mantis_parallel_ecb_crypt
    (void *output, const void *input, const void *tweak, size_t size,
     const MantisParallelECB_t *ecb)
{
    const MantisKey_t *ks;
    const MantisParallelECBVtable_t *vtable;

    /* Validate the parameters */
    if (!ecb || !ecb->ctx || (size % MANTIS_BLOCK_SIZE) != 0)
        return 0;
    ks = ecb->ctx;

    /* Process major blocks with the vectorized back end */
    vtable = ecb->vtable;
    if (vtable) {
        size_t psize = ecb->parallel_size;
        while (size >= psize) {
            (*(vtable->crypt))(output, input, tweak, ks);
            output += psize;
            input += psize;
            tweak += psize;
            size -= psize;
        }
    }

    /* Process any left-over blocks with the non-parallel implementation */
    while (size >= MANTIS_BLOCK_SIZE) {
        mantis_ecb_crypt_tweaked(output, input, tweak, ks);
        output += MANTIS_BLOCK_SIZE;
        input += MANTIS_BLOCK_SIZE;
        tweak += MANTIS_BLOCK_SIZE;
        size -= MANTIS_BLOCK_SIZE;
    }
    return 1;
}
