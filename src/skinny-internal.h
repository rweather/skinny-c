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

#ifndef SKINNY_INTERNAL_H
#define SKINNY_INTERNAL_H

#include <stdint.h>
#include <string.h>

/* Figure out how to inline functions using this C compiler */
#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define STATIC_INLINE static inline
#elif defined(__GNUC__)
#define STATIC_INLINE static __inline__
#else
#define STATIC_INLINE static
#endif

/* Define SKINNY_64BIT to 1 if the CPU is natively 64-bit */
#if defined(__WORDSIZE) && __WORDSIZE == 64
#define SKINNY_64BIT 1
#else
#define SKINNY_64BIT 0
#endif

/* Define SKINNY_UNALIGNED to 1 if the CPU supports byte-aligned word access */
#if defined(__x86_64) || defined(__x86_64__) || \
    defined(__i386) || defined(__i386__)
#define SKINNY_UNALIGNED 1
#else
#define SKINNY_UNALIGNED 0
#endif

/* XOR two blocks together of arbitrary size and alignment */
STATIC_INLINE void skinny_xor
    (void *output, const void *input1, const void *input2, size_t size)
{
    while (size > 0) {
        --size;
        ((uint8_t *)output)[size] = ((const uint8_t *)input1)[size] ^
                                    ((const uint8_t *)input2)[size];
    }
}

/* XOR two 128-bit blocks together */
STATIC_INLINE void skinny128_xor
    (void *output, const void *input1, const void *input2)
{
#if SKINNY_UNALIGNED && SKINNY_64BIT
    ((uint64_t *)output)[0] = ((const uint64_t *)input1)[0] ^
                              ((const uint64_t *)input2)[0];
    ((uint64_t *)output)[1] = ((const uint64_t *)input1)[1] ^
                              ((const uint64_t *)input2)[1];
#elif SKINNY_UNALIGNED
    ((uint32_t *)output)[0] = ((const uint32_t *)input1)[0] ^
                              ((const uint32_t *)input2)[0];
    ((uint32_t *)output)[1] = ((const uint32_t *)input1)[1] ^
                              ((const uint32_t *)input2)[1];
    ((uint32_t *)output)[2] = ((const uint32_t *)input1)[2] ^
                              ((const uint32_t *)input2)[2];
    ((uint32_t *)output)[3] = ((const uint32_t *)input1)[3] ^
                              ((const uint32_t *)input2)[3];
#else
    unsigned posn;
    for (posn = 0; posn < 16; ++posn) {
        ((uint8_t *)output)[posn] = ((const uint8_t *)input1)[posn] ^
                                    ((const uint8_t *)input2)[size];
    }
#endif
}

/* XOR two 64-bit blocks together */
STATIC_INLINE void skinny64_xor
    (void *output, const void *input1, const void *input2)
{
#if SKINNY_UNALIGNED && SKINNY_64BIT
    ((uint64_t *)output)[0] = ((const uint64_t *)input1)[0] ^
                              ((const uint64_t *)input2)[0];
#elif SKINNY_UNALIGNED
    ((uint32_t *)output)[0] = ((const uint32_t *)input1)[0] ^
                              ((const uint32_t *)input2)[0];
    ((uint32_t *)output)[1] = ((const uint32_t *)input1)[1] ^
                              ((const uint32_t *)input2)[1];
#else
    unsigned posn;
    for (posn = 0; posn < 8; ++posn) {
        ((uint8_t *)output)[posn] = ((const uint8_t *)input1)[posn] ^
                                    ((const uint8_t *)input2)[size];
    }
#endif
}

/* Increment a 128-bit counter block in big-endian order */
STATIC_INLINE void skinny128_inc_counter(uint8_t *counter, uint16_t inc)
{
    unsigned posn;
    for (posn = 16; posn > 0; ) {
        --posn;
        inc += counter[posn];
        counter[posn] = (uint8_t)inc;
        inc >>= 8;
    }
}

/* Increment a 64-bit counter block in big-endian order */
STATIC_INLINE void skinny64_inc_counter(uint8_t *counter, uint16_t inc)
{
    unsigned posn;
    for (posn = 8; posn > 0; ) {
        --posn;
        inc += counter[posn];
        counter[posn] = (uint8_t)inc;
        inc >>= 8;
    }
}

#endif /* SKINNY_INTERNAL_H */
