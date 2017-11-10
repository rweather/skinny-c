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
#include "mantis-cipher.h"
#include <stdio.h>
#include <string.h>

typedef struct
{
    const char *name;
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    uint8_t key[48];
    unsigned key_size;

} SkinnyTestVector;

typedef struct
{
    const char *name;
    uint8_t plaintext[8];
    uint8_t ciphertext[8];
    uint8_t key[16];
    uint8_t tweak[8];
    unsigned rounds;

} MantisTestVector;

/* Test vectors from the SKINNY specification paper */
static SkinnyTestVector const testVector64_64 = {
    "Skinny-64-64",
    {0x06, 0x03, 0x4f, 0x95, 0x77, 0x24, 0xd1, 0x9d},
    {0xbb, 0x39, 0xdf, 0xb2, 0x42, 0x9b, 0x8a, 0xc7},
    {0xf5, 0x26, 0x98, 0x26, 0xfc, 0x68, 0x12, 0x38},
    8
};
static SkinnyTestVector const testVector64_128 = {
    "Skinny-64-128",
    {0xcf, 0x16, 0xcf, 0xe8, 0xfd, 0x0f, 0x98, 0xaa},
    {0x6c, 0xed, 0xa1, 0xf4, 0x3d, 0xe9, 0x2b, 0x9e},
    {0x9e, 0xb9, 0x36, 0x40, 0xd0, 0x88, 0xda, 0x63,
     0x76, 0xa3, 0x9d, 0x1c, 0x8b, 0xea, 0x71, 0xe1},
    16
};
static SkinnyTestVector const testVector64_192 = {
    "Skinny-64-192",
    {0x53, 0x0c, 0x61, 0xd3, 0x5e, 0x86, 0x63, 0xc3},
    {0xdd, 0x2c, 0xf1, 0xa8, 0xf3, 0x30, 0x30, 0x3c},
    {0xed, 0x00, 0xc8, 0x5b, 0x12, 0x0d, 0x68, 0x61,
     0x87, 0x53, 0xe2, 0x4b, 0xfd, 0x90, 0x8f, 0x60,
     0xb2, 0xdb, 0xb4, 0x1b, 0x42, 0x2d, 0xfc, 0xd0},
    24
};
static SkinnyTestVector const testVector128_128 = {
    "Skinny-128-128",
    {0xf2, 0x0a, 0xdb, 0x0e, 0xb0, 0x8b, 0x64, 0x8a,
     0x3b, 0x2e, 0xee, 0xd1, 0xf0, 0xad, 0xda, 0x14},
    {0x22, 0xff, 0x30, 0xd4, 0x98, 0xea, 0x62, 0xd7,
     0xe4, 0x5b, 0x47, 0x6e, 0x33, 0x67, 0x5b, 0x74},
    {0x4f, 0x55, 0xcf, 0xb0, 0x52, 0x0c, 0xac, 0x52,
     0xfd, 0x92, 0xc1, 0x5f, 0x37, 0x07, 0x3e, 0x93},
    16
};
static SkinnyTestVector const testVector128_256 = {
    "Skinny-128-256",
    {0x3a, 0x0c, 0x47, 0x76, 0x7a, 0x26, 0xa6, 0x8d,
     0xd3, 0x82, 0xa6, 0x95, 0xe7, 0x02, 0x2e, 0x25},
    {0xb7, 0x31, 0xd9, 0x8a, 0x4b, 0xde, 0x14, 0x7a,
     0x7e, 0xd4, 0xa6, 0xf1, 0x6b, 0x9b, 0x58, 0x7f},
    {0x00, 0x9c, 0xec, 0x81, 0x60, 0x5d, 0x4a, 0xc1,
     0xd2, 0xae, 0x9e, 0x30, 0x85, 0xd7, 0xa1, 0xf3,
     0x1a, 0xc1, 0x23, 0xeb, 0xfc, 0x00, 0xfd, 0xdc,
     0xf0, 0x10, 0x46, 0xce, 0xed, 0xdf, 0xca, 0xb3},
    32
};
static SkinnyTestVector const testVector128_384 = {
    "Skinny-128-384",
    {0xa3, 0x99, 0x4b, 0x66, 0xad, 0x85, 0xa3, 0x45,
     0x9f, 0x44, 0xe9, 0x2b, 0x08, 0xf5, 0x50, 0xcb},
    {0x94, 0xec, 0xf5, 0x89, 0xe2, 0x01, 0x7c, 0x60,
     0x1b, 0x38, 0xc6, 0x34, 0x6a, 0x10, 0xdc, 0xfa},
    {0xdf, 0x88, 0x95, 0x48, 0xcf, 0xc7, 0xea, 0x52,
     0xd2, 0x96, 0x33, 0x93, 0x01, 0x79, 0x74, 0x49,
     0xab, 0x58, 0x8a, 0x34, 0xa4, 0x7f, 0x1a, 0xb2,
     0xdf, 0xe9, 0xc8, 0x29, 0x3f, 0xbe, 0xa9, 0xa5,
     0xab, 0x1a, 0xfa, 0xc2, 0x61, 0x10, 0x12, 0xcd,
     0x8c, 0xef, 0x95, 0x26, 0x18, 0xc3, 0xeb, 0xe8},
    48
};
static MantisTestVector const testMantis5 = {
    "Mantis5",
    {0x3b, 0x5c, 0x77, 0xa4, 0x92, 0x1f, 0x97, 0x18},
    {0xd6, 0x52, 0x20, 0x35, 0xc1, 0xc0, 0xc6, 0xc1},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    5
};
static MantisTestVector const testMantis6 = {
    "Mantis6",
    {0xd6, 0x52, 0x20, 0x35, 0xc1, 0xc0, 0xc6, 0xc1},
    {0x60, 0xe4, 0x34, 0x57, 0x31, 0x19, 0x36, 0xfd},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    6
};
static MantisTestVector const testMantis7 = {
    "Mantis7",
    {0x60, 0xe4, 0x34, 0x57, 0x31, 0x19, 0x36, 0xfd},
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    7
};
static MantisTestVector const testMantis8 = {
    "Mantis8",
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x97, 0x1e, 0xa0, 0x1a, 0x86, 0xb4, 0x10, 0xbb},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    8
};

static int error = 0;

static void skinny64Test(const SkinnyTestVector *test)
{
    Skinny64Key_t ks;
    uint8_t plaintext[SKINNY64_BLOCK_SIZE];
    uint8_t ciphertext[SKINNY64_BLOCK_SIZE];

    skinny64_set_key(&ks, test->key, test->key_size);
    skinny64_ecb_encrypt(ciphertext, test->plaintext, &ks);
    skinny64_ecb_decrypt(plaintext, test->ciphertext, &ks);

    printf("%s: ", test->name);
    if (memcmp(plaintext, test->plaintext, SKINNY64_BLOCK_SIZE) == 0) {
        printf("plaintext ok");
    } else {
        printf("plaintext INCORRECT");
        error = 1;
    }
    if (memcmp(ciphertext, test->ciphertext, SKINNY64_BLOCK_SIZE) == 0) {
        printf(", ciphertext ok");
    } else {
        printf(", ciphertext INCORRECT");
        error = 1;
    }
    printf("\n");
}

static void skinny128Test(const SkinnyTestVector *test)
{
    Skinny128Key_t ks;
    uint8_t plaintext[SKINNY128_BLOCK_SIZE];
    uint8_t ciphertext[SKINNY128_BLOCK_SIZE];

    skinny128_set_key(&ks, test->key, test->key_size);
    skinny128_ecb_encrypt(ciphertext, test->plaintext, &ks);
    skinny128_ecb_decrypt(plaintext, test->ciphertext, &ks);

    printf("%s: ", test->name);
    if (memcmp(plaintext, test->plaintext, SKINNY128_BLOCK_SIZE) == 0) {
        printf("plaintext ok");
    } else {
        printf("plaintext INCORRECT");
        error = 1;
    }
    if (memcmp(ciphertext, test->ciphertext, SKINNY128_BLOCK_SIZE) == 0) {
        printf(", ciphertext ok");
    } else {
        printf(", ciphertext INCORRECT");
        error = 1;
    }
    printf("\n");
}

static void mantisTest(const MantisTestVector *test)
{
    MantisKey_t ks;
    uint8_t plaintext1[MANTIS_BLOCK_SIZE];
    uint8_t ciphertext1[MANTIS_BLOCK_SIZE];
    uint8_t plaintext2[MANTIS_BLOCK_SIZE];
    uint8_t ciphertext2[MANTIS_BLOCK_SIZE];

    /* Start with the mode set to encrypt first */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ecb_crypt(ciphertext1, test->plaintext, &ks);
    mantis_swap_modes(&ks); /* Switch to decryption */
    mantis_ecb_crypt(plaintext1, test->ciphertext, &ks);

    /* Perform the test again with the mode set to decrypt first */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_DECRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ecb_crypt(plaintext2, test->ciphertext, &ks);
    mantis_swap_modes(&ks); /* Switch to encryption */
    mantis_ecb_crypt(ciphertext2, test->plaintext, &ks);

    /* Check the results */
    printf("%s: ", test->name);
    if (memcmp(plaintext1, test->plaintext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(plaintext2, test->plaintext, MANTIS_BLOCK_SIZE) == 0) {
        printf("plaintext ok");
    } else {
        printf("plaintext INCORRECT");
        error = 1;
    }
    if (memcmp(ciphertext1, test->ciphertext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(ciphertext2, test->ciphertext, MANTIS_BLOCK_SIZE) == 0) {
        printf(", ciphertext ok");
    } else {
        printf(", ciphertext INCORRECT");
        error = 1;
    }
    printf("\n");
}

/* Define to 1 to include the sbox generator */
#define GEN_SBOX 0

#if GEN_SBOX
void generate_sboxes(void);
#endif

int main(int argc, char **argv)
{
    skinny64Test(&testVector64_64);
    skinny64Test(&testVector64_128);
    skinny64Test(&testVector64_192);

    skinny128Test(&testVector128_128);
    skinny128Test(&testVector128_256);
    skinny128Test(&testVector128_384);

    mantisTest(&testMantis5);
    mantisTest(&testMantis6);
    mantisTest(&testMantis7);
    mantisTest(&testMantis8);

#if GEN_SBOX
    generate_sboxes();
#endif
    return error;
}

#if GEN_SBOX

/* This sbox generator is used to verify the bit-sliced implementation.
   We do not use this in the actual implementation because table lookups
   do not have constant-cache behaviour. */

int permute1(int y)
{
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    return ((y & 0x01) << 2) |
           ((y & 0x06) << 5) |
           ((y & 0x20) >> 5) |
           ((y & 0xC8) >> 2) |
           ((y & 0x10) >> 1);
}

int permute1_inv(int y)
{
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    return ((y & 0x08) << 1) |
           ((y & 0x32) << 2) |
           ((y & 0x01) << 5) |
           ((y & 0xC0) >> 5) |
           ((y & 0x04) >> 2);
}

int permute2(int y)
{
    return (y & 0xF9) | ((y >> 1) & 0x02) | ((y << 1) & 0x04);
}

void generate_sbox(void)
{
    int x, y;
    printf("static unsigned char const sbox[256] = {\n");
    for (x = 0; x <= 255; ++x) {
        y = x;
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute2(y);
        printf("0x%02x, ", y);
        if ((x % 12) == 11)
            printf("\n");
    }
    printf("\n};\n\n");
}

void generate_inv_sbox(void)
{
    int x, y;
    printf("static unsigned char const sbox_inv[256] = {\n");
    for (x = 0; x <= 255; ++x) {
        y = x;
        y = permute2(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        printf("0x%02x, ", y);
        if ((x % 12) == 11)
            printf("\n");
    }
    printf("\n};\n\n");
}

#define NAND(x, y)  (~((x) & (y)))
#define NOR(x, y)   (~((x) | (y)))

void generate_mantis_sbox(void)
{
    int x, y, a, b, c, d;
    int aout, bout, cout, dout;
    printf("static unsigned char const mantis_sbox[14] = {\n");
    for (x = 0; x <= 15; ++x) {
        a = x >> 3;
        b = x >> 2;
        c = x >> 1;
        d = x;
        /* aout = NAND(NAND(~c, NAND(a, b)), (a | d)); */
        aout = ~((c | (a & b)) & (a | d));

        /* bout = NAND(NOR(NOR(a, d), (b & c)), NAND((a & c), d)); */
        bout = (~(a | d)) | (b & c) | (a & c & d);

        /* cout = NAND(NAND(b, d), (NOR(b, d) | a)); */
        cout = (b & d) | ((b | d) & ~a);

        /* dout = NOR(NOR(a, (b | c)), NAND(NAND(a, b), (c | d))); */
        dout = (a | b | c) & (~(a & b)) & (c | d);

        y = ((aout & 0x01) << 3) | ((bout & 0x01) << 2) |
            ((cout & 0x01) << 1) | (dout & 0x01);
        printf("%x, ", y);
    }
    printf("\n};\n\n");
}

void generate_sboxes(void)
{
    generate_sbox();
    generate_inv_sbox();
    generate_mantis_sbox();
}

#endif /* GEN_SBOX */
