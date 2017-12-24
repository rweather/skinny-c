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

#include "skinny128-cipher.h"
#include "skinny128-ctr-internal.h"
#include "skinny-internal.h"
#include <stdlib.h>

/** Internal state information for Skinny-128 in CTR mode */
typedef struct
{
    /** Key schedule for Skinny-128, with an optional tweak */
    Skinny128TweakedKey_t kt;

    /** Counter value for the next block */
    unsigned char counter[SKINNY128_BLOCK_SIZE];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[SKINNY128_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

} Skinny128CTRCtx_t;

static int skinny128_ctr_def_init(Skinny128CTR_t *ctr)
{
    Skinny128CTRCtx_t *ctx;
    if ((ctx = calloc(1, sizeof(Skinny128CTRCtx_t))) == NULL)
        return 0;
    ctx->offset = SKINNY128_BLOCK_SIZE;
    ctr->ctx = ctx;
    return 1;
}

static void skinny128_ctr_def_cleanup(Skinny128CTR_t *ctr)
{
    if (ctr->ctx) {
        skinny_cleanse(ctr->ctx, sizeof(Skinny128CTRCtx_t));
        free(ctr->ctx);
        ctr->ctx = 0;
    }
}

static int skinny128_ctr_def_set_key(Skinny128CTR_t *ctr, const void *key, unsigned size)
{
    Skinny128CTRCtx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!skinny128_set_key(&(ctx->kt.ks), key, size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY128_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_def_set_tweaked_key
    (Skinny128CTR_t *ctr, const void *key, unsigned key_size)
{
    Skinny128CTRCtx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!skinny128_set_tweaked_key(&(ctx->kt), key, key_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY128_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_def_set_tweak
    (Skinny128CTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    Skinny128CTRCtx_t *ctx;

    /* Validate the parameters */
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying tweak */
    if (!skinny128_set_tweak(&(ctx->kt), tweak, tweak_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = SKINNY128_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_def_set_counter
    (Skinny128CTR_t *ctr, const void *counter, unsigned size)
{
    Skinny128CTRCtx_t *ctx;

    /* Validate the parameters */
    if (size > SKINNY128_BLOCK_SIZE)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(ctx->counter, 0, SKINNY128_BLOCK_SIZE - size);
        memcpy(ctx->counter + SKINNY128_BLOCK_SIZE - size, counter, size);
    } else {
        memset(ctx->counter, 0, SKINNY128_BLOCK_SIZE);
    }
    ctx->offset = SKINNY128_BLOCK_SIZE;
    return 1;
}

static int skinny128_ctr_def_encrypt
    (void *output, const void *input, size_t size, Skinny128CTR_t *ctr)
{
    Skinny128CTRCtx_t *ctx;
    uint8_t *out = (uint8_t *)output;
    const uint8_t *in = (const uint8_t *)input;

    /* Validate the parameters */
    if (!output || !input)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Encrypt the input in CTR mode to create the output */
    while (size > 0) {
        if (ctx->offset >= SKINNY128_BLOCK_SIZE) {
            /* We need a new keystream block */
            skinny128_ecb_encrypt(ctx->ecounter, ctx->counter, &(ctx->kt.ks));
            skinny128_inc_counter(ctx->counter, 1);

            /* XOR an entire keystream block in one go if possible */
            if (size >= SKINNY128_BLOCK_SIZE) {
                skinny128_xor(out, in, ctx->ecounter);
                out += SKINNY128_BLOCK_SIZE;
                in += SKINNY128_BLOCK_SIZE;
                size -= SKINNY128_BLOCK_SIZE;
            } else {
                /* Last partial block in the request */
                skinny_xor(out, in, ctx->ecounter, size);
                ctx->offset = size;
                break;
            }
        } else {
            /* Left-over keystream data from the last request */
            size_t temp = SKINNY128_BLOCK_SIZE - ctx->offset;
            if (temp > size)
                temp = size;
            skinny_xor(out, in, ctx->ecounter + ctx->offset, temp);
            ctx->offset += temp;
            out += temp;
            in += temp;
            size -= temp;
        }
    }
    return 1;
}

/** Vtable for the default Skinny-128-CTR implementation */
static Skinny128CTRVtable_t const skinny128_ctr_def = {
    skinny128_ctr_def_init,
    skinny128_ctr_def_cleanup,
    skinny128_ctr_def_set_key,
    skinny128_ctr_def_set_tweaked_key,
    skinny128_ctr_def_set_tweak,
    skinny128_ctr_def_set_counter,
    skinny128_ctr_def_encrypt
};

/* Public API, which redirects to the specific backend implementation */

int skinny128_ctr_init(Skinny128CTR_t *ctr)
{
    const Skinny128CTRVtable_t *vtable;

    /* Validate the parameter */
    if (!ctr)
        return 0;

    /* Choose a backend implementation */
    vtable = &skinny128_ctr_def;
    if (_skinny_has_vec128())
        vtable = &_skinny128_ctr_vec128;
    if (_skinny_has_vec256())
        vtable = &_skinny128_ctr_vec256;
    ctr->vtable = vtable;

    /* Initialize the CTR mode context */
    return (*(vtable->init))(ctr);
}

void skinny128_ctr_cleanup(Skinny128CTR_t *ctr)
{
    if (ctr && ctr->vtable) {
        const Skinny128CTRVtable_t *vtable = ctr->vtable;
        (*(vtable->cleanup))(ctr);
        ctr->vtable = 0;
    }
}

int skinny128_ctr_set_key(Skinny128CTR_t *ctr, const void *key, unsigned size)
{
    if (ctr && ctr->vtable) {
        const Skinny128CTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_key))(ctr, key, size);
    }
    return 0;
}

int skinny128_ctr_set_tweaked_key
    (Skinny128CTR_t *ctr, const void *key, unsigned key_size)
{
    if (ctr && ctr->vtable) {
        const Skinny128CTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_tweaked_key))(ctr, key, key_size);
    }
    return 0;
}

int skinny128_ctr_set_tweak
    (Skinny128CTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    if (ctr && ctr->vtable) {
        const Skinny128CTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_tweak))(ctr, tweak, tweak_size);
    }
    return 0;
}

int skinny128_ctr_set_counter
    (Skinny128CTR_t *ctr, const void *counter, unsigned size)
{
    if (ctr && ctr->vtable) {
        const Skinny128CTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_counter))(ctr, counter, size);
    }
    return 0;
}

int skinny128_ctr_encrypt
    (void *output, const void *input, size_t size, Skinny128CTR_t *ctr)
{
    if (ctr && ctr->vtable) {
        const Skinny128CTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->encrypt))(output, input, size, ctr);
    }
    return 0;
}
