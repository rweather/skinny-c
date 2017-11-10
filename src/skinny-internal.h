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

#endif /* SKINNY_INTERNAL_H */
