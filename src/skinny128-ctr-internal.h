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

#ifndef SKINNY128_CTR_INTERNAL_H
#define SKINNY128_CTR_INTERNAL_H

#include "skinny128-cipher.h"

/**
 * \brief Internal vtable for redirecting the Skinny-128-CTR
 * implementation to different vectorized back ends.
 */
typedef struct
{
    int (*init)(Skinny128CTR_t *ctr);
    void (*cleanup)(Skinny128CTR_t *ctr);
    int (*set_key)(Skinny128CTR_t *ctr, const void *key, unsigned size);
    int (*set_tweaked_key)
        (Skinny128CTR_t *ctr, const void *key, unsigned key_size);
    int (*set_tweak)
        (Skinny128CTR_t *ctr, const void *tweak, unsigned tweak_size);
    int (*set_counter)
        (Skinny128CTR_t *ctr, const void *counter, unsigned size);
    int (*encrypt)
        (void *output, const void *input, size_t size, Skinny128CTR_t *ctr);

} Skinny128CTRVtable_t;

extern Skinny128CTRVtable_t const _skinny128_ctr_vec128;
extern Skinny128CTRVtable_t const _skinny128_ctr_vec256;

#endif /* SKINNY128_CTR_INTERNAL_H */
