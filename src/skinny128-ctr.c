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
#include "skinny-internal.h"
#include <string.h>

int skinny128_ctr_init(Skinny128CTR_t *ctr)
{
    if (!ctr)
        return 0;
    memset(ctr, 0, sizeof(Skinny128CTR_t));
    ctr->offset = SKINNY128_BLOCK_SIZE;
    return 1;
}

void skinny128_ctr_cleanup(Skinny128CTR_t *ctr)
{
    if (ctr)
        memset(ctr, 0, sizeof(Skinny128CTR_t));
}

int skinny128_ctr_set_counter
    (Skinny128CTR_t *ctr, const void *counter, unsigned size)
{
    /* Validate the parameters */
    if (!ctr || size > SKINNY128_BLOCK_SIZE)
        return 0;

    /* Set the counter and reset the keystream to a block boundary */
    if (counter) {
        memset(ctr->counter, 0, SKINNY128_BLOCK_SIZE - size);
        memcpy(ctr->counter + SKINNY128_BLOCK_SIZE - size, counter, size);
    } else {
        memset(ctr->counter, 0, SKINNY128_BLOCK_SIZE);
    }
    ctr->offset = SKINNY128_BLOCK_SIZE;
    return 1;
}

int skinny128_ctr_encrypt
    (void *output, const void *input, size_t size,
     const Skinny128Key_t *ks, Skinny128CTR_t *ctr)
{
    uint8_t *out = (uint8_t *)output;
    const uint8_t *in = (const uint8_t *)input;

    /* Validate the parameters */
    if (!output || !input || !ks || !ctr)
        return 0;

    /* Encrypt the input in CTR mode to create the output */
    while (size > 0) {
        if (ctr->offset >= SKINNY128_BLOCK_SIZE) {
            /* We need a new keystream block */
            skinny128_ecb_encrypt(ctr->ecounter, ctr->counter, ks);
            skinny128_inc_counter(ctr->counter, 1);

            /* XOR an entire keystream block in one go if possible */
            if (size >= SKINNY128_BLOCK_SIZE) {
                skinny128_xor(out, in, ctr->ecounter);
                out += SKINNY128_BLOCK_SIZE;
                in += SKINNY128_BLOCK_SIZE;
                size -= SKINNY128_BLOCK_SIZE;
            } else {
                /* Last partial block in the request */
                skinny_xor(out, in, ctr->ecounter, size);
                ctr->offset = size;
                break;
            }
        } else {
            /* Left-over keystream data from the last request */
            size_t temp = SKINNY128_BLOCK_SIZE - ctr->offset;
            if (temp > size)
                temp = size;
            skinny_xor(out, in, ctr->ecounter + ctr->offset, temp);
            ctr->offset += temp;
            out += temp;
            in += temp;
            size -= temp;
        }
    }
    return 1;
}
