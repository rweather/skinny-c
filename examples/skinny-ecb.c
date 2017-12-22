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
#include "skinny64-cipher.h"
#include "options.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    FILE *infile;
    FILE *outfile;
    uint8_t buffer[1024];
    size_t read_size;
    size_t posn;
    Skinny128Key_t ks128;
    Skinny64Key_t ks64;

    /* Parse the command-line options */
    if (!parse_options(argc, argv, OPT_NO_COUNTER | OPT_DECRYPT)) {
        return 1;
    }

    /* Open the files */
    if ((infile = fopen(input_filename, "rb")) == NULL) {
        perror(input_filename);
        return 1;
    }
    if ((outfile = fopen(output_filename, "wb")) == NULL) {
        perror(output_filename);
        fclose(infile);
        return 1;
    }

    /* Initialize the key schedule */
    if (block_size == 8) {
        skinny64_set_key(&ks64, key, key_size);
    } else {
        skinny128_set_key(&ks128, key, key_size);
    }

    /* Read and encrypt/decrypt blocks from the file */
    while (!feof(infile) && (read_size = fread(buffer, 1, sizeof(buffer), infile)) > 0) {
        for (posn = 0; (posn + block_size) <= read_size; posn += block_size) {
            if (encrypt) {
                if (block_size == 8)
                    skinny64_ecb_encrypt(buffer + posn, buffer + posn, &ks64);
                else
                    skinny128_ecb_encrypt(buffer + posn, buffer + posn, &ks128);
            } else {
                if (block_size == 8)
                    skinny64_ecb_decrypt(buffer + posn, buffer + posn, &ks64);
                else
                    skinny128_ecb_decrypt(buffer + posn, buffer + posn, &ks128);
            }
        }
        fwrite(buffer, 1, posn, outfile);
    }

    /* Clean up and exit */
    fclose(infile);
    fclose(outfile);
    return 0;
}
