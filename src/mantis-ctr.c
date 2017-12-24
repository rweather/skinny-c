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

#include "mantis-cipher.h"
#include "mantis-ctr-internal.h"
#include "skinny-internal.h"
#include <stdlib.h>

/** Internal state information for Mantis in CTR mode */
typedef struct
{
    /** Key schedule for Mantis */
    MantisKey_t ks;

    /** Counter value for the next block */
    unsigned char counter[MANTIS_BLOCK_SIZE];

    /** Encrypted counter value for encrypting the current block */
    unsigned char ecounter[MANTIS_BLOCK_SIZE];

    /** Offset into ecounter where the previous request left off */
    unsigned offset;

} MantisCTRCtx_t;

static int mantis_ctr_def_init(MantisCTR_t *ctr)
{
    MantisCTRCtx_t *ctx;
    if ((ctx = calloc(1, sizeof(MantisCTRCtx_t))) == NULL)
        return 0;
    ctx->offset = MANTIS_BLOCK_SIZE;
    ctr->ctx = ctx;
    return 1;
}

static void mantis_ctr_def_cleanup(MantisCTR_t *ctr)
{
    if (ctr->ctx) {
        skinny_cleanse(ctr->ctx, sizeof(MantisCTRCtx_t));
        free(ctr->ctx);
        ctr->ctx = 0;
    }
}

static int mantis_ctr_def_set_key
    (MantisCTR_t *ctr, const void *key, unsigned size, unsigned rounds)
{
    MantisCTRCtx_t *ctx;

    /* Validate the parameters */
    if (!key)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying key schedule */
    if (!mantis_set_key(&(ctx->ks), key, size, rounds, MANTIS_ENCRYPT))
        return 0;

    /* Reset the keystream */
    ctx->offset = MANTIS_BLOCK_SIZE;
    return 1;
}

static int mantis_ctr_def_set_tweak
    (MantisCTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    MantisCTRCtx_t *ctx;

    /* Validate the parameters */
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Populate the underlying tweak */
    if (!mantis_set_tweak(&(ctx->ks), tweak, tweak_size))
        return 0;

    /* Reset the keystream */
    ctx->offset = MANTIS_BLOCK_SIZE;
    return 1;
}

static int mantis_ctr_def_set_counter
    (MantisCTR_t *ctr, const void *counter, unsigned size)
{
    MantisCTRCtx_t *ctx;

    /* Validate the parameters */
    if (size > MANTIS_BLOCK_SIZE)
        return 0;
    ctx = ctr->ctx;
    if (!ctx)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(ctx->counter, 0, MANTIS_BLOCK_SIZE - size);
        memcpy(ctx->counter + MANTIS_BLOCK_SIZE - size, counter, size);
    } else {
        memset(ctx->counter, 0, MANTIS_BLOCK_SIZE);
    }
    ctx->offset = MANTIS_BLOCK_SIZE;
    return 1;
}

static int mantis_ctr_def_encrypt
    (void *output, const void *input, size_t size, MantisCTR_t *ctr)
{
    MantisCTRCtx_t *ctx;
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
        if (ctx->offset >= MANTIS_BLOCK_SIZE) {
            /* We need a new keystream block */
            mantis_ecb_crypt(ctx->ecounter, ctx->counter, &(ctx->ks));
            skinny64_inc_counter(ctx->counter, 1);

            /* XOR an entire keystream block in one go if possible */
            if (size >= MANTIS_BLOCK_SIZE) {
                skinny64_xor(out, in, ctx->ecounter);
                out += MANTIS_BLOCK_SIZE;
                in += MANTIS_BLOCK_SIZE;
                size -= MANTIS_BLOCK_SIZE;
            } else {
                /* Last partial block in the request */
                skinny_xor(out, in, ctx->ecounter, size);
                ctx->offset = size;
                break;
            }
        } else {
            /* Left-over keystream data from the last request */
            size_t temp = MANTIS_BLOCK_SIZE - ctx->offset;
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

/** Vtable for the default Mantis-CTR implementation */
static MantisCTRVtable_t const mantis_ctr_def = {
    mantis_ctr_def_init,
    mantis_ctr_def_cleanup,
    mantis_ctr_def_set_key,
    mantis_ctr_def_set_tweak,
    mantis_ctr_def_set_counter,
    mantis_ctr_def_encrypt
};

/* Public API, which redirects to the specific backend implementation */

int mantis_ctr_init(MantisCTR_t *ctr)
{
    const MantisCTRVtable_t *vtable;

    /* Validate the parameter */
    if (!ctr)
        return 0;

    /* Choose a backend implementation */
    vtable = &mantis_ctr_def;
    if (_skinny_has_vec128())
        vtable = &_mantis_ctr_vec128;
    ctr->vtable = vtable;

    /* Initialize the CTR mode context */
    return (*(vtable->init))(ctr);
}

void mantis_ctr_cleanup(MantisCTR_t *ctr)
{
    if (ctr && ctr->vtable) {
        const MantisCTRVtable_t *vtable = ctr->vtable;
        (*(vtable->cleanup))(ctr);
        ctr->vtable = 0;
    }
}

int mantis_ctr_set_key
    (MantisCTR_t *ctr, const void *key, unsigned size, unsigned rounds)
{
    if (ctr && ctr->vtable) {
        const MantisCTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_key))(ctr, key, size, rounds);
    }
    return 0;
}

int mantis_ctr_set_tweak
    (MantisCTR_t *ctr, const void *tweak, unsigned tweak_size)
{
    if (ctr && ctr->vtable) {
        const MantisCTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_tweak))(ctr, tweak, tweak_size);
    }
    return 0;
}

int mantis_ctr_set_counter
    (MantisCTR_t *ctr, const void *counter, unsigned size)
{
    if (ctr && ctr->vtable) {
        const MantisCTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->set_counter))(ctr, counter, size);
    }
    return 0;
}

int mantis_ctr_encrypt
    (void *output, const void *input, size_t size, MantisCTR_t *ctr)
{
    if (ctr && ctr->vtable) {
        const MantisCTRVtable_t *vtable = ctr->vtable;
        return (*(vtable->encrypt))(output, input, size, ctr);
    }
    return 0;
}
