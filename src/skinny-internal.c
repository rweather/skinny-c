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

#include "skinny-internal.h"
#include <stdlib.h>

#if defined(__x86_64) || defined(__x86_64__) || \
    defined(__i386) || defined(__i386__)
#define SKINNY_X86 1
#else
#define SKINNY_X86 0
#endif
#if SKINNY_X86 && (defined(__GNUC__) || defined(__clang__))
#define SKINNY_X86_CPUID 1
#else
#define SKINNY_X86_CPUID 0
#endif
#if SKINNY_X86_CPUID
#include <cpuid.h>
#endif

int _skinny_has_vec128(void)
{
    int detected = 0;
#if SKINNY_VEC128_MATH
#if SKINNY_X86_CPUID && defined(__SSE2__)
    /* 128-bit SIMD vectors are available on x86 if we have SSE2 */
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    detected = (edx & (1 << 26)) != 0;
#elif defined(__arm) || defined(__arm__)
#if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__ARM_NEON_FP)
    /* Don't know how to do a runtime check so assume that if the user
       compiled with NEON instructions enabled, they wanted to use them */
    detected = 1;
#endif
#endif
#endif
    return detected;
}

int _skinny_has_vec256(void)
{
    int detected = 0;
#if SKINNY_VEC256_MATH
#if SKINNY_X86_CPUID && defined(__AVX2__)
    /* 256-bit SIMD vectors are available on x86 if we have AVX2 */
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    __cpuid(7, eax, ebx, ecx, edx);
    detected = (ebx & (1 << 5)) != 0;
#endif
#endif
    return detected;
}

void *skinny_calloc(size_t size, void **base_ptr)
{
    /* We use 256-bit aligned structures in some of the back ends but
       calloc() may align to less than that.  This wrapper fixes things */
    void *ptr = calloc(1, size + 31);
    if (ptr) {
        *base_ptr = ptr;
        ptr = (void *)((((uintptr_t)ptr) + 31) & ~((uintptr_t)31));
    }
    return ptr;
}
