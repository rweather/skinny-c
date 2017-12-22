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

#include "options.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>

char *input_filename = NULL;
char *output_filename = NULL;
unsigned block_size = 16;
uint8_t key[MAX_KEY_SIZE];
unsigned key_size = 0;
uint8_t tweak[MAX_TWEAK_SIZE];
unsigned tweak_size = 0;
int encrypt = 1;

static void usage(const char *progname, int flags)
{
    const char *extra_opts1 = "";
    const char *extra_opts2 = "";
    if (flags & OPT_NEED_TWEAK)
        extra_opts1 = "[-t tweak] ";
    else if ((flags & OPT_NO_COUNTER) == 0)
        extra_opts1 = "[-c counter] ";
    if (flags & OPT_DECRYPT)
        extra_opts1 = "[-d] ";
    fprintf(stderr, "Usage: %s [-b block-size] -k key %s%sinput-filename output-filename\n\n",
            progname, extra_opts1, extra_opts2);
    fprintf(stderr, "-b block-size\n");
    fprintf(stderr, "    Specify the cipher block size: 64 or 128, default is 128.\n");
    fprintf(stderr, "-k key\n");
    fprintf(stderr, "    Specify the encryption key in hexadecimal (required).\n");
    if (flags & OPT_NEED_TWEAK) {
        fprintf(stderr, "-t tweak\n");
        fprintf(stderr, "    Specify the initial tweak value in hexadecimal, default is all-zeroes.\n");
    } else if ((flags & OPT_NO_COUNTER) == 0) {
        fprintf(stderr, "-c counter\n");
        fprintf(stderr, "    Specify the initial counter block in hexadecimal, default is all-zeroes.\n");
    }
    if (flags & OPT_DECRYPT) {
        fprintf(stderr, "-d\n");
        fprintf(stderr, "    Decrypt the input data, default is encrypt.\n");
    }
}

static unsigned parse_hex(uint8_t *buf, unsigned max_len, const char *str)
{
    unsigned len = 0;
    int value = 0;
    int nibble = 0;
    while (*str != '\0') {
        char ch = *str++;
        if (ch >= '0' && ch <= '9') {
            value = value * 16 + (ch - '0');
        } else if (ch >= 'A' && ch <= 'F') {
            value = value * 16 + (ch - 'A' + 10);
        } else if (ch >= 'a' && ch <= 'f') {
            value = value * 16 + (ch - 'a' + 10);
        } else if (ch == ' ' || ch == ':' || ch == '.') {
            if (!nibble)
                continue;
        } else {
            fprintf(stderr, "invalid hex data\n");
            return 0;
        }
        nibble = !nibble;
        if (!nibble) {
            if (len >= max_len) {
                fprintf(stderr, "too many hex bytes, maximum is %u\n", max_len);
                return 0;
            }
            buf[len++] = (uint8_t)value;
            value = 0;
        }
    }
    return len;
}

static void invalid_key_size(int from, int to)
{
    fprintf(stderr, "invalid key size, must be between %d and %d bytes\n",
            from, to);
}

int parse_options(int argc, char *argv[], int flags)
{
    const char *progname = argv[0];
    int opt;
    int have_key = 0;

    /* Parse the options from the command-line */
    while ((opt = getopt(argc, argv, "b:k:t:c:d")) != -1) {
        switch (opt) {
        case 'b':
            if (!strcmp(optarg, "64")) {
                block_size = 8;
            } else if (!strcmp(optarg, "128")) {
                block_size = 16;
            } else {
                usage(progname, flags);
                return 0;
            }
            break;

        case 'k':
            key_size = parse_hex(key, sizeof(key), optarg);
            if (!key_size) {
                usage(progname, flags);
                return 0;
            }
            have_key = 1;
            break;

        case 'c':
        case 't':
            tweak_size = parse_hex(tweak, sizeof(tweak), optarg);
            if (!tweak_size) {
                usage(progname, flags);
                return 0;
            }
            break;

        case 'd':
            encrypt = 0;
            break;

        default:
            usage(progname, flags);
            return 0;
        }
    }

    /* Check that we have input and output filenames */
    if ((optind + 2) > argc) {
        usage(progname, flags);
        return 0;
    }
    input_filename = argv[optind];
    output_filename = argv[optind + 1];

    /* Validate the options */
    if (!have_key) {
        fprintf(stderr, "missing key, supply -k parameter\n");
        return 0;
    }
    if (block_size == 8) {
        if (flags & OPT_NEED_TWEAK) {
            if (key_size < 8 || key_size > 16) {
                invalid_key_size(8, 16);
                return 0;
            }
        } else {
            if (key_size < 8 || key_size > 24) {
                invalid_key_size(8, 24);
                return 0;
            }
        }
    } else {
        if (flags & OPT_NEED_TWEAK) {
            if (key_size < 16 || key_size > 32) {
                invalid_key_size(16, 32);
                return 0;
            }
        } else {
            if (key_size < 16 || key_size > 48) {
                invalid_key_size(16, 48);
                return 0;
            }
        }
    }
    if (tweak_size > block_size) {
        fprintf(stderr, "invalid %s size, must be between 1 and %u bytes\n",
                (flags & OPT_NEED_TWEAK) ? "tweak" : "counter", block_size);
        return 0;
    }

    /* Create a default tweak/counter if necessary */
    if (!tweak_size) {
        memset(tweak, 0, sizeof(tweak));
        tweak_size = block_size;
    }

    /* Ready to go */
    return 1;
}
