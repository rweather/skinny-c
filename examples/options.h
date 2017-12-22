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

#ifndef SKINNY_OPTIONS_H
#define SKINNY_OPTIONS_H

#include "skinny128-cipher.h"
#include "skinny64-cipher.h"

#define MAX_KEY_SIZE    (SKINNY128_BLOCK_SIZE * 3)
#define MAX_TWEAK_SIZE  SKINNY128_BLOCK_SIZE

extern char *input_filename;
extern char *output_filename;
extern unsigned block_size;
extern uint8_t key[MAX_KEY_SIZE];
extern unsigned key_size;
extern uint8_t tweak[MAX_TWEAK_SIZE];
extern unsigned tweak_size;
extern int encrypt;

#define OPT_NEED_TWEAK 1
#define OPT_NO_COUNTER 2
#define OPT_DECRYPT    4

int parse_options(int argc, char *argv[], int flags);

#endif
