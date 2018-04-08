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

#include "Skinny128.h"
#include "Crypto.h"
#include "utility/EndianUtil.h"
#include "utility/RotateUtil.h"
#include "utility/ProgMemUtil.h"
#include <string.h>

/**
 * \class Skinny128 Skinny128.h <Skinny128.h>
 * \brief Abstract base class for SKINNY block ciphers with 128-bit blocks.
 *
 * This class is abstract.  The caller should instantiate Skinny128_128,
 * Skinny128_256, or Skinny128_384 to create a SKINNY block cipher with a
 * specific key size.  Or instantiate Skinny128_256_Tweaked or
 * Skinny128_384_Tweaked for a tweakable version of the SKINNY block cipher.
 *
 * Reference: https://sites.google.com/site/skinnycipher/
 *
 * \sa Skinny128_128, Skinny128_256, Skinny128_384, Skinny128_Tweaked
 */

/**
 * \class Skinny128_Tweaked Skinny128.h <Skinny128.h>
 * \brief Abstract base class for SKINNY tweakable block ciphers with
 * 128-bit blocks.
 *
 * This class is abstract.  The caller should instantiate
 * Skinny128_256_Tweaked or Skinny128_384_Tweaked to create a
 * SKINNY block cipher with a tweak and a specific key size.
 *
 * Reference: https://sites.google.com/site/skinnycipher/
 *
 * \sa Skinny128_256_Tweaked, Skinny128_384_Tweaked
 */

/**
 * \class Skinny128_128 Skinny128.h <Skinny128.h>
 * \brief SKINNY block cipher with a 128-bit block and a 128-bit key.
 *
 * \sa Skinny128_256, Skinny128_384, Skinny128, Skinny128_256_Tweaked
 */

/**
 * \class Skinny128_256 Skinny128.h <Skinny128.h>
 * \brief SKINNY block cipher with a 128-bit block and a 256-bit key.
 *
 * \sa Skinny128_128, Skinny128_384, Skinny128, Skinny128_384_Tweaked
 */

/**
 * \class Skinny128_384 Skinny128.h <Skinny128.h>
 * \brief SKINNY block cipher with a 128-bit block and a 384-bit key.
 *
 * \sa Skinny128_128, Skinny128_256, Skinny128, Skinny128_384_Tweaked
 */

/**
 * \class Skinny128_256_Tweaked Skinny128.h <Skinny128.h>
 * \brief SKINNY block cipher with a 128-bit block, a 128-bit key, and a
 * 128-bit tweak.
 *
 * \sa Skinny128_256, Skinny128_Tweaked, Skinny128_384_Tweaked
 */

/**
 * \class Skinny128_384_Tweaked Skinny128.h <Skinny128.h>
 * \brief SKINNY block cipher with a 128-bit block, a 256-bit key, and a
 * 128-bit tweak.
 *
 * \sa Skinny128_384, Skinny128_Tweaked, Skinny128_256_Tweaked
 */

#if defined(__AVR__)
#define USE_AVR_INLINE_ASM 1
#endif

#ifndef CRYPTO_LITTLE_ENDIAN
#error "Arduino platforms are assumed to be little-endian"
#endif

/**
 * \brief Constructs a Skinny-128 block cipher object.
 *
 * \param schedule Points to the schedule data structure in the subclass.
 * \param rounds The number of rounds to perform during encryption/decryption.
 */
Skinny128::Skinny128(uint32_t *schedule, uint8_t rounds)
    : s(schedule), r(rounds)
{
}

/**
 * \brief Destroys this Skinny-128 block cipher object after clearing
 * sensitive information.
 */
Skinny128::~Skinny128()
{
}

/**
 * \brief Size of a Skinny-128 block in bytes.
 * \return Always returns 16.
 */
size_t Skinny128::blockSize() const
{
    return 16;
}

#if USE_AVR_INLINE_ASM

// Force the sboxes to be aligned on a 256-byte boundary.
// This makes sbox lookups more efficient.
#define ALIGN256 __attribute__((aligned(256)))

// S-box tables for Skinny-128.  We only use this for AVR platforms,
// as there will be issues with constant cache behaviour on ARM.
// It would be nice to avoid this for AVR as well, but the S-box
// operations are simply too slow using bit operations on AVR.
static uint8_t const sbox[256] PROGMEM ALIGN256 = {
    0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 
    0x53, 0x73, 0x5b, 0x7b, 0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 
    0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b, 0xe5, 0xcc, 0xe8, 0xc1, 
    0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9, 
    0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 
    0x03, 0xb0, 0x0b, 0xb9, 0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 
    0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d, 0x62, 0x4a, 0x6c, 0x45, 
    0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d, 
    0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 
    0x04, 0xb4, 0x0d, 0xbd, 0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 
    0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd, 0x36, 0x8e, 0x38, 0x82, 
    0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29, 
    0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 
    0x50, 0x70, 0x59, 0x79, 0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 
    0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb, 0xe6, 0xce, 0xea, 0xc2, 
    0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb, 
    0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 
    0x97, 0x27, 0x9f, 0x2f, 0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 
    0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f, 0xa2, 0x18, 0xae, 0x16, 
    0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf, 
    0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 
    0xd7, 0xf7, 0xdf, 0xff, 
};
static uint8_t const sbox_inv[256] PROGMEM ALIGN256 = {
    0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e, 
    0x6a, 0x6e, 0xea, 0xee, 0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6, 
    0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4, 0x8d, 0xc9, 0x49, 0x1d, 
    0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf, 
    0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17, 
    0x42, 0x47, 0xc2, 0xc7, 0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6, 
    0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4, 0x9c, 0xd8, 0x58, 0x0c, 
    0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde, 
    0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07, 
    0x52, 0x57, 0xd2, 0xd7, 0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd, 
    0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf, 0x16, 0x13, 0x83, 0x86, 
    0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4, 
    0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e, 
    0x4a, 0x4e, 0xca, 0xce, 0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5, 
    0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7, 0x3d, 0x69, 0xe9, 0xad, 
    0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef, 
    0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4, 
    0x21, 0x74, 0xb1, 0xf4, 0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc, 
    0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe, 0x25, 0x70, 0xf0, 0xb5, 
    0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7, 
    0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf, 
    0x7b, 0x7f, 0xfb, 0xff, 
};

// Figure out how to do lookups from a pgmspace sbox table on this platform.
#if defined(RAMPZ)
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "elpm " reg ",Z\n"
#elif defined(__AVR_HAVE_LPMX__)
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "lpm " reg ",Z\n"
#elif defined(__AVR_TINY__)
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "ld " reg ",Z\n"
#else
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "lpm\n" \
    "mov " reg ",r0\n"
#endif

// Mix the columns during an encryption round.
#define MIX_COLUMNS(row0, row1, row2, row3) \
    "eor " row1 "," row2 "\n" \
    "eor " row2 "," row0 "\n" \
    "mov __tmp_reg__," row3 "\n" \
    "eor __tmp_reg__," row2 "\n" \
    "mov " row3 "," row2 "\n" \
    "mov " row2 "," row1 "\n" \
    "mov " row1 "," row0 "\n" \
    "mov " row0 ",__tmp_reg__\n"

// Inverse mix of the columns during a decryption round.
#define MIX_COLUMNS_INV(row0, row1, row2, row3) \
    "mov __tmp_reg__," row3 "\n" \
    "mov " row3 "," row0 "\n" \
    "mov " row0 "," row1 "\n" \
    "mov " row1 "," row2 "\n" \
    "eor " row3 ",__tmp_reg__\n" \
    "eor __tmp_reg__," row0 "\n" \
    "mov " row2 ",__tmp_reg__\n" \
    "eor " row1 "," row2 "\n"

#else // !USE_AVR_INLINE_ASM

inline uint32_t skinny128_sbox(uint32_t x)
{
    /* Original version from the specification is equivalent to:
     *
     * #define SBOX_MIX(x)
     *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
     * #define SBOX_SWAP(x)
     *     (((x) & 0xF9F9F9F9U) |
     *     (((x) >> 1) & 0x02020202U) |
     *     (((x) << 1) & 0x04040404U))
     * #define SBOX_PERMUTE(x)
     *     ((((x) & 0x01010101U) << 2) |
     *      (((x) & 0x06060606U) << 5) |
     *      (((x) & 0x20202020U) >> 5) |
     *      (((x) & 0xC8C8C8C8U) >> 2) |
     *      (((x) & 0x10101010U) >> 1))
     *
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * return SBOX_SWAP(x);
     *
     * However, we can mix the bits in their original positions and then
     * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
     * final permuatation.  This reduces the number of shift operations.
     */
    uint32_t y;

    /* Mix the bits */
    x = ~x;
    x ^= (((x >> 2) & (x >> 3)) & 0x11111111U);
    y  = (((x << 5) & (x << 1)) & 0x20202020U);
    x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x80808080U);
    x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y;
    y  = (((x >> 5) & (x << 1)) & 0x04040404U);
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
    x = ~x;

    /* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [2 7 6 1 3 0 4 5] */
    return ((x & 0x08080808U) << 1) |
           ((x & 0x32323232U) << 2) |
           ((x & 0x01010101U) << 5) |
           ((x & 0x80808080U) >> 6) |
           ((x & 0x40404040U) >> 4) |
           ((x & 0x04040404U) >> 2);
}

inline uint32_t skinny128_inv_sbox(uint32_t x)
{
    /* Original version from the specification is equivalent to:
     *
     * #define SBOX_MIX(x)
     *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
     * #define SBOX_SWAP(x)
     *     (((x) & 0xF9F9F9F9U) |
     *     (((x) >> 1) & 0x02020202U) |
     *     (((x) << 1) & 0x04040404U))
     * #define SBOX_PERMUTE_INV(x)
     *     ((((x) & 0x08080808U) << 1) |
     *      (((x) & 0x32323232U) << 2) |
     *      (((x) & 0x01010101U) << 5) |
     *      (((x) & 0xC0C0C0C0U) >> 5) |
     *      (((x) & 0x04040404U) >> 2))
     *
     * x = SBOX_SWAP(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * return SBOX_MIX(x);
     *
     * However, we can mix the bits in their original positions and then
     * delay the SBOX_PERMUTE_INV and SBOX_SWAP steps to be performed with one
     * final permuatation.  This reduces the number of shift operations.
     */
    uint32_t y;

    /* Mix the bits */
    x = ~x;
    y  = (((x >> 1) & (x >> 3)) & 0x01010101U);
    x ^= (((x >> 2) & (x >> 3)) & 0x10101010U) ^ y;
    y  = (((x >> 6) & (x >> 1)) & 0x02020202U);
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x80808080U);
    x ^= (((x >> 1) & (x << 2)) & 0x04040404U) ^ y;
    y  = (((x << 5) & (x << 1)) & 0x20202020U);
    x ^= (((x << 4) & (x << 5)) & 0x40404040U) ^ y;
    x = ~x;

    /* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [5 3 0 4 6 7 2 1] */
    return ((x & 0x01010101U) << 2) |
           ((x & 0x04040404U) << 4) |
           ((x & 0x02020202U) << 6) |
           ((x & 0x20202020U) >> 5) |
           ((x & 0xC8C8C8C8U) >> 2) |
           ((x & 0x10101010U) >> 1);
}

#endif // !USE_AVR_INLINE_ASM

void Skinny128::encryptBlock(uint8_t *output, const uint8_t *input)
{
#if USE_AVR_INLINE_ASM
#if defined(RAMPZ)
    uint32_t sbox_addr = (uint32_t)sbox;
#else
    uint16_t sbox_addr = (uint16_t)sbox;
#endif
    __asm__ __volatile__ (
        // Load the input block from Z[0..15] into r8..r23.
        "ld r8,Z\n"
        "ldd r9,Z+1\n"
        "ldd r10,Z+2\n"
        "ldd r11,Z+3\n"
        "ldd r12,Z+4\n"
        "ldd r13,Z+5\n"
        "ldd r14,Z+6\n"
        "ldd r15,Z+7\n"
        "ldd r16,Z+8\n"
        "ldd r17,Z+9\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+11\n"
        "ldd r20,Z+12\n"
        "ldd r21,Z+13\n"
        "ldd r22,Z+14\n"
        "ldd r23,Z+15\n"

        // Set up Z to point to the start of the sbox table.
        "ldd r30,%A3\n"
        "ldd r31,%B3\n"
#if defined(RAMPZ)
        "in __tmp_reg__,%5\n"
        "push __tmp_reg__\n"
        "ldd __tmp_reg__,%C3\n"
        "out %5,__tmp_reg__\n"
#endif

        // Top of the loop.
        "1:\n"

        // Transform the state using the sbox.
        SBOX("r8")
        SBOX("r9")
        SBOX("r10")
        SBOX("r11")
        SBOX("r12")
        SBOX("r13")
        SBOX("r14")
        SBOX("r15")
        SBOX("r16")
        SBOX("r17")
        SBOX("r18")
        SBOX("r19")
        SBOX("r20")
        SBOX("r21")
        SBOX("r22")
        SBOX("r23")

        // XOR the state with the key schedule.
        "ld __tmp_reg__,X+\n"
        "eor r8,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r9,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r10,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r11,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r12,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r13,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r14,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "eor r15,__tmp_reg__\n"
        "ldi r24,0x02\n"
        "eor r16,r24\n"

        // Shift the rows.
        "mov __tmp_reg__,r15\n"
        "mov r15,r14\n"
        "mov r14,r13\n"
        "mov r13,r12\n"
        "mov r12,__tmp_reg__\n"
        "mov __tmp_reg__,r19\n"
        "mov r19,r17\n"
        "mov r17,__tmp_reg__\n"
        "mov __tmp_reg__,r18\n"
        "mov r18,r16\n"
        "mov r16,__tmp_reg__\n"
        "mov __tmp_reg__,r20\n"
        "mov r20,r21\n"
        "mov r21,r22\n"
        "mov r22,r23\n"
        "mov r23,__tmp_reg__\n"

        // Mix the columns.
        MIX_COLUMNS( "r8", "r12", "r16", "r20")
        MIX_COLUMNS( "r9", "r13", "r17", "r21")
        MIX_COLUMNS("r10", "r14", "r18", "r22")
        MIX_COLUMNS("r11", "r15", "r19", "r23")

        // Bottom of the loop.
        "dec %4\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        // Restore the original RAMPZ value.
#if defined(RAMPZ)
        "pop __tmp_reg__\n"
        "out %5,__tmp_reg__\n"
#endif

        // Store the final state into the output buffer.
        "ldd r30,%A2\n"
        "ldd r31,%B2\n"
        "st Z,r8\n"
        "std Z+1,r9\n"
        "std Z+2,r10\n"
        "std Z+3,r11\n"
        "std Z+4,r12\n"
        "std Z+5,r13\n"
        "std Z+6,r14\n"
        "std Z+7,r15\n"
        "std Z+8,r16\n"
        "std Z+9,r17\n"
        "std Z+10,r18\n"
        "std Z+11,r19\n"
        "std Z+12,r20\n"
        "std Z+13,r21\n"
        "std Z+14,r22\n"
        "std Z+15,r23\n"

        : : "x"(s), "z"(input), "Q"(output), "Q"(sbox_addr),
            "r"((uint8_t)r)
#if defined(RAMPZ)
            , "I" (_SFR_IO_ADDR(RAMPZ))
#endif
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    uint32_t state[4];
    const uint32_t *schedule;
    uint32_t temp;

    // Unpack the input block into the state array.
    // Easy since we assume the platform is little-endian.
    memcpy(state, input, sizeof(state));

    // Perform all encryption rounds.
    schedule = s;
    for (uint8_t index = r; index > 0; --index, schedule += 2) {
        // Apply the S-box to all bytes in the state.
        state[0] = skinny128_sbox(state[0]);
        state[1] = skinny128_sbox(state[1]);
        state[2] = skinny128_sbox(state[2]);
        state[3] = skinny128_sbox(state[3]);

        // Apply the subkey for this round.
        state[0] ^= schedule[0];
        state[1] ^= schedule[1];
        state[2] ^= 0x02;

        // Shift the cells in the rows right, which moves the cell
        // values up closer to the MSB.  That is, we do a left rotate
        // on the word to rotate the cells in the word right.
        state[1] = leftRotate8(state[1]);
        state[2] = leftRotate16(state[2]);
        state[3] = leftRotate24(state[3]);

        // Mix the columns.
        state[1] ^= state[2];
        state[2] ^= state[0];
        temp = state[3] ^ state[2];
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = temp;
    }

    // Pack the result into the output buffer.
    memcpy(output, state, sizeof(state));
#endif // !USE_AVR_INLINE_ASM
}

void Skinny128::decryptBlock(uint8_t *output, const uint8_t *input)
{
#if USE_AVR_INLINE_ASM
#if defined(RAMPZ)
    uint32_t sbox_addr = (uint32_t)sbox_inv;
#else
    uint16_t sbox_addr = (uint16_t)sbox_inv;
#endif
    __asm__ __volatile__ (
        // Load the input block from Z[0..15] into r8..r23.
        "ld r8,Z\n"
        "ldd r9,Z+1\n"
        "ldd r10,Z+2\n"
        "ldd r11,Z+3\n"
        "ldd r12,Z+4\n"
        "ldd r13,Z+5\n"
        "ldd r14,Z+6\n"
        "ldd r15,Z+7\n"
        "ldd r16,Z+8\n"
        "ldd r17,Z+9\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+11\n"
        "ldd r20,Z+12\n"
        "ldd r21,Z+13\n"
        "ldd r22,Z+14\n"
        "ldd r23,Z+15\n"

        // Set up Z to point to the start of the sbox table.
        "ldd r30,%A3\n"
        "ldd r31,%B3\n"
#if defined(RAMPZ)
        "in __tmp_reg__,%5\n"
        "push __tmp_reg__\n"
        "ldd __tmp_reg__,%C3\n"
        "out %5,__tmp_reg__\n"
#endif

        // Top of the loop.
        "1:\n"

        // Inverse mix of the columns.
        MIX_COLUMNS_INV( "r8", "r12", "r16", "r20")
        MIX_COLUMNS_INV( "r9", "r13", "r17", "r21")
        MIX_COLUMNS_INV("r10", "r14", "r18", "r22")
        MIX_COLUMNS_INV("r11", "r15", "r19", "r23")

        // Inverse shift of the rows.
        "mov __tmp_reg__,r12\n"
        "mov r12,r13\n"
        "mov r13,r14\n"
        "mov r14,r15\n"
        "mov r15,__tmp_reg__\n"
        "mov __tmp_reg__,r19\n"
        "mov r19,r17\n"
        "mov r17,__tmp_reg__\n"
        "mov __tmp_reg__,r18\n"
        "mov r18,r16\n"
        "mov r16,__tmp_reg__\n"
        "mov __tmp_reg__,r23\n"
        "mov r23,r22\n"
        "mov r22,r21\n"
        "mov r21,r20\n"
        "mov r20,__tmp_reg__\n"

        // XOR the state with the key schedule.
        "ld __tmp_reg__,-X\n"
        "eor r15,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r14,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r13,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r12,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r11,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r10,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r9,__tmp_reg__\n"
        "ld __tmp_reg__,-X\n"
        "eor r8,__tmp_reg__\n"
        "ldi r24,0x02\n"
        "eor r16,r24\n"

        // Transform the state using the inverse sbox.
        SBOX("r8")
        SBOX("r9")
        SBOX("r10")
        SBOX("r11")
        SBOX("r12")
        SBOX("r13")
        SBOX("r14")
        SBOX("r15")
        SBOX("r16")
        SBOX("r17")
        SBOX("r18")
        SBOX("r19")
        SBOX("r20")
        SBOX("r21")
        SBOX("r22")
        SBOX("r23")

        // Bottom of the loop.
        "dec %4\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        // Restore the original RAMPZ value.
#if defined(RAMPZ)
        "pop __tmp_reg__\n"
        "out %5,__tmp_reg__\n"
#endif

        // Store the final state into the output buffer.
        "ldd r30,%A2\n"
        "ldd r31,%B2\n"
        "st Z,r8\n"
        "std Z+1,r9\n"
        "std Z+2,r10\n"
        "std Z+3,r11\n"
        "std Z+4,r12\n"
        "std Z+5,r13\n"
        "std Z+6,r14\n"
        "std Z+7,r15\n"
        "std Z+8,r16\n"
        "std Z+9,r17\n"
        "std Z+10,r18\n"
        "std Z+11,r19\n"
        "std Z+12,r20\n"
        "std Z+13,r21\n"
        "std Z+14,r22\n"
        "std Z+15,r23\n"

        : : "x"(s + r * 2), "z"(input), "Q"(output), "Q"(sbox_addr),
            "r"((uint8_t)r)
#if defined(RAMPZ)
            , "I" (_SFR_IO_ADDR(RAMPZ))
#endif
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    uint32_t state[4];
    const uint32_t *schedule;
    uint32_t temp;

    // Unpack the input block into the state array.
    // Easy since we assume the platform is little-endian.
    memcpy(state, input, sizeof(state));

    /* Perform all decryption rounds */
    schedule = &(s[r * 2 - 2]);
    for (uint8_t index = r; index > 0; --index, schedule -= 2) {
        // Inverse mix of the columns.
        temp = state[3];
        state[3] = state[0];
        state[0] = state[1];
        state[1] = state[2];
        state[3] ^= temp;
        state[2] = temp ^ state[0];
        state[1] ^= state[2];

        // Inverse shift of the rows.
        state[1] = leftRotate24(state[1]);
        state[2] = leftRotate16(state[2]);
        state[3] = leftRotate8(state[3]);

        // Apply the subkey for this round.
        state[0] ^= schedule[0];
        state[1] ^= schedule[1];
        state[2] ^= 0x02;

        // Apply the inverse of the S-box to all bytes in the state.
        state[0] = skinny128_inv_sbox(state[0]);
        state[1] = skinny128_inv_sbox(state[1]);
        state[2] = skinny128_inv_sbox(state[2]);
        state[3] = skinny128_inv_sbox(state[3]);
    }

    // Pack the result into the output buffer.
    memcpy(output, state, sizeof(state));
#endif // !USE_AVR_INLINE_ASM
}

void Skinny128::clear()
{
    clean(s, r * 2 * sizeof(uint32_t));
}

#if USE_AVR_INLINE_ASM

// Permutes the bytes within a TKn value while expanding the key schedule.
// PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
#define PERMUTE_TKn() \
    "mov __tmp_reg__,r8\n"      /* tmp = TK[0] */ \
    "mov r8,r17\n"              /* TK[0] = TK[9] */ \
    "mov r17,r9\n"              /* TK[9] = TK[1] */ \
    "mov r9,r23\n"              /* TK[1] = TK[15] */ \
    "mov r23,r15\n"             /* TK[15] = TK[7] */ \
    "mov r15,r19\n"             /* TK[7] = TK[11] */ \
    "mov r19,r11\n"             /* TK[11] = TK[3] */ \
    "mov r11,r21\n"             /* TK[3] = TK[13] */ \
    "mov r21,r13\n"             /* TK[13] = TK[5] */ \
    "mov r13,r22\n"             /* TK[5] = TK[14] */ \
    "mov r22,r14\n"             /* TK[14] = TK[6] */ \
    "mov r14,r20\n"             /* TK[6] = TK[12] */ \
    "mov r20,r12\n"             /* TK[12] = TK[4]) */ \
    "mov r12,r18\n"             /* TK[4] = TK[10] */ \
    "mov r18,r10\n"             /* TK[10] = TK[2] */ \
    "mov r10,r16\n"             /* TK[2] = TK[8] */ \
    "mov r16,__tmp_reg__\n"     /* TK[8] = tmp (original TK[0]) */

#else // !USE_AVR_INLINE_ASM

// Permutes the bytes within a TKn value while expanding the key schedule.
// PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
#define skinny128_permute_tk(tk) \
    do { \
        uint32_t row2 = tk[2]; \
        uint32_t row3 = tk[3]; \
        tk[2] = tk[0]; \
        tk[3] = tk[1]; \
        row3 = (row3 << 16) | (row3 >> 16); \
        tk[0] = ((row2 >>  8) & 0x000000FFU) | \
                ((row2 << 16) & 0x00FF0000U) | \
                ( row3        & 0xFF00FF00U); \
        tk[1] = ((row2 >> 16) & 0x000000FFU) | \
                 (row2        & 0xFF000000U) | \
                ((row3 <<  8) & 0x0000FF00U) | \
                ( row3        & 0x00FF0000U); \
    } while (0)

#endif // !USE_AVR_INLINE_ASM

/**
 * \brief Clears the key schedule and sets it to the schedule for TK1.
 *
 * \param key Points to the 16 bytes of TK1.
 * \param tweaked Set to true if the subclass uses tweaks.
 */
void Skinny128::setTK1(const uint8_t *key, bool tweaked)
{
#if USE_AVR_INLINE_ASM
    __asm__ __volatile__ (
        // Load the TK1 bytes into r8..r23.
        "ld r8,Z\n"
        "ldd r9,Z+1\n"
        "ldd r10,Z+2\n"
        "ldd r11,Z+3\n"
        "ldd r12,Z+4\n"
        "ldd r13,Z+5\n"
        "ldd r14,Z+6\n"
        "ldd r15,Z+7\n"
        "ldd r16,Z+8\n"
        "ldd r17,Z+9\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+11\n"
        "ldd r20,Z+12\n"
        "ldd r21,Z+13\n"
        "ldd r22,Z+14\n"
        "ldd r23,Z+15\n"

        // Set rc to zero (stored in r25).
        "clr r25\n"

        // Top of the loop.
        "1:\n"

        // Generate the rc value for the next round.
        // rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        // We don't need to do "rc &= 0x3F" because it is effectively
        // done for us by "andi" instructions in the following step.
        "clr r24\n"
        "lsl r25\n"
        "bst r25,6\n"
        "bld r24,0\n"
        "eor r25,r24\n"
        "bst r25,5\n"
        "bld r24,0\n"
        "eor r25,r24\n"
        "ldi r24,1\n"
        "eor r25,r24\n"

        // Store the first 8 bytes of TK1 into the key schedule and XOR with rc.
        "mov r24,r25\n"
        "andi r24,0x0F\n"
        "eor r24,r8\n"
        "st X+,r24\n"
        "st X+,r9\n"
        "mov __tmp_reg__,%3\n"
        "eor __tmp_reg__,r10\n"
        "st X+,__tmp_reg__\n"
        "st X+,r11\n"
        "mov r24,r25\n"
        "swap r24\n"
        "andi r24,0x03\n"
        "eor r24,r12\n"
        "st X+,r24\n"
        "st X+,r13\n"
        "st X+,r14\n"
        "st X+,r15\n"

        // Permute TK1 for the next round.
        PERMUTE_TKn()

        // Bottom of the loop.
        "dec %2\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        : : "x"(s), "z"(key), "r"(r), "r"((uint8_t)(tweaked ? 0x02 : 0x00))
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "r25", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    uint32_t TK1[4];
    uint32_t *schedule = s;
    uint8_t rc = 0;

    // Unpack the incoming key value into the TK1 array.
    // Easy since we assume the platform is little-endian.
    memcpy(TK1, key, sizeof(TK1));

    // Generate the key schedule words for all rounds.
    for (uint8_t index = r; index > 0; --index, schedule += 2) {
        // XOR the round constants with the current schedule words.
        // The round constants for the 3rd and 4th rows are
        // fixed and will be applied during encrypt/decrypt.
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK1[0] ^ (rc & 0x0F);
        schedule[1] = TK1[1] ^ (rc >> 4);

        // If we have a tweak, then we need to XOR a 1 bit into the
        // second bit of the top cell of the third column as recommended
        // by the SKINNY specification.
        if (tweaked)
            schedule[0] ^= 0x00020000;

        // Permute TK1 for the next round.
        skinny128_permute_tk(TK1);
    }

    // Clean up and exit.
    clean(TK1);
#endif // !USE_AVR_INLINE_ASM
}

/**
 * \brief XOR's the key schedule with the schedule for TK1.
 *
 * \param key Points to the 16 bytes of TK1.
 *
 * This function is used to adjust the tweak for the tweakable versions
 * of the SKINNY block cipher.
 */
void Skinny128::xorTK1(const uint8_t *key)
{
#if USE_AVR_INLINE_ASM
    __asm__ __volatile__ (
        // Load the TK1 bytes into r8..r23.
        "ld r8,Z\n"
        "ldd r9,Z+1\n"
        "ldd r10,Z+2\n"
        "ldd r11,Z+3\n"
        "ldd r12,Z+4\n"
        "ldd r13,Z+5\n"
        "ldd r14,Z+6\n"
        "ldd r15,Z+7\n"
        "ldd r16,Z+8\n"
        "ldd r17,Z+9\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+11\n"
        "ldd r20,Z+12\n"
        "ldd r21,Z+13\n"
        "ldd r22,Z+14\n"
        "ldd r23,Z+15\n"

        // Top of the loop.
        "1:\n"

        // XOR the first two rows of TK1 with the key schedule.
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r8\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r9\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r10\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r11\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r12\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r13\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r14\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r15\n"
        "st X+,__tmp_reg__\n"

        // Permute TK1 for the next round.
        PERMUTE_TKn()

        // Bottom of the loop.
        "dec %2\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        : : "x"(s), "z"(key), "r"(r)
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    uint32_t TK1[4];
    uint32_t *schedule = s;

    // Unpack the incoming key value into the TK1 array.
    // Easy since we assume the platform is little-endian.
    memcpy(TK1, key, sizeof(TK1));

    // XOR against the key schedule words for all rounds.
    for (uint8_t index = r; index > 0; --index, schedule += 2) {
        schedule[0] ^= TK1[0];
        schedule[1] ^= TK1[1];
        skinny128_permute_tk(TK1);
    }

    // Clean up and exit.
    clean(TK1);
#endif // !USE_AVR_INLINE_ASM
}

#if USE_AVR_INLINE_ASM

// Transform the contents of a register using LFSR2 (r24 assumed to be zero).
#define LFSR2(reg) \
    "lsl " reg "\n" \
    "adc " reg ",__zero_reg__\n" \
    "bst " reg ",6\n" \
    "bld r24,0\n" \
    "eor " reg ",r24\n"

// Transform the contents of a register using LFSR3 (r24 assumed to be zero).
#define LFSR3(reg) \
    "bst " reg ",0\n" \
    "lsr " reg "\n" \
    "bld " reg ",7\n" \
    "bst " reg ",5\n" \
    "bld r24,7\n" \
    "eor " reg ",r24\n"

#else // !USE_AVR_INLINE_ASM

inline uint32_t skinny128_LFSR2(uint32_t x)
{
    return ((x << 1) & 0xFEFEFEFEU) ^ (((x >> 7) ^ (x >> 5)) & 0x01010101U);
}

inline uint32_t skinny128_LFSR3(uint32_t x)
{
    return ((x >> 1) & 0x7F7F7F7FU) ^ (((x << 7) ^ (x << 1)) & 0x80808080U);
}

#endif // !USE_AVR_INLINE_ASM

/**
 * \brief XOR's the key schedule with the schedule for TK2.
 *
 * \param key Points to the 16 bytes of TK2.
 */
void Skinny128::setTK2(const uint8_t *key)
{
#if USE_AVR_INLINE_ASM
    __asm__ __volatile__ (
        // Load the TK2 bytes into r8..r23.
        "ld r8,Z\n"
        "ldd r9,Z+1\n"
        "ldd r10,Z+2\n"
        "ldd r11,Z+3\n"
        "ldd r12,Z+4\n"
        "ldd r13,Z+5\n"
        "ldd r14,Z+6\n"
        "ldd r15,Z+7\n"
        "ldd r16,Z+8\n"
        "ldd r17,Z+9\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+11\n"
        "ldd r20,Z+12\n"
        "ldd r21,Z+13\n"
        "ldd r22,Z+14\n"
        "ldd r23,Z+15\n"

        // Top of the loop.
        "1:\n"

        // XOR the first two rows of TK2 with the key schedule.
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r8\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r9\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r10\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r11\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r12\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r13\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r14\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r15\n"
        "st X+,__tmp_reg__\n"

        // Permute TK2 for the next round.
        PERMUTE_TKn()

        // Apply LFSR2 to the first two rows of TK2.
        "clr r24\n"
        LFSR2("r8")
        LFSR2("r9")
        LFSR2("r10")
        LFSR2("r11")
        LFSR2("r12")
        LFSR2("r13")
        LFSR2("r14")
        LFSR2("r15")

        // Bottom of the loop.
        "dec %2\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        : : "x"(s), "z"(key), "r"(r)
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    uint32_t TK2[4];
    uint32_t *schedule = s;

    // Unpack the incoming key value into the TK2 array.
    // Easy since we assume the platform is little-endian.
    memcpy(TK2, key, sizeof(TK2));

    // XOR against the key schedule words for all rounds.
    for (uint8_t index = r; index > 0; --index, schedule += 2) {
        // XOR TK2 against the key schedule.
        schedule[0] ^= TK2[0];
        schedule[1] ^= TK2[1];

        // Permute TK2 for the next round.
        skinny128_permute_tk(TK2);

        // Apply LFSR2 to the first two rows of TK2.
        TK2[0] = skinny128_LFSR2(TK2[0]);
        TK2[1] = skinny128_LFSR2(TK2[1]);
    }

    // Clean up and exit.
    clean(TK2);
#endif // !USE_AVR_INLINE_ASM
}

/**
 * \brief XOR's the key schedule with the schedule for TK3.
 *
 * \param key Points to the 16 bytes of TK3.
 */
void Skinny128::setTK3(const uint8_t *key)
{
#if USE_AVR_INLINE_ASM
    __asm__ __volatile__ (
        // Load the TK3 bytes into r8..r23.
        "ld r8,Z\n"
        "ldd r9,Z+1\n"
        "ldd r10,Z+2\n"
        "ldd r11,Z+3\n"
        "ldd r12,Z+4\n"
        "ldd r13,Z+5\n"
        "ldd r14,Z+6\n"
        "ldd r15,Z+7\n"
        "ldd r16,Z+8\n"
        "ldd r17,Z+9\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+11\n"
        "ldd r20,Z+12\n"
        "ldd r21,Z+13\n"
        "ldd r22,Z+14\n"
        "ldd r23,Z+15\n"

        // Top of the loop.
        "1:\n"

        // XOR the first two rows of TK3 with the key schedule.
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r8\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r9\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r10\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r11\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r12\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r13\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r14\n"
        "st X+,__tmp_reg__\n"
        "ld __tmp_reg__,X\n"
        "eor __tmp_reg__,r15\n"
        "st X+,__tmp_reg__\n"

        // Permute TK3 for the next round.
        PERMUTE_TKn()

        // Apply LFSR3 to the first two rows of TK3.
        "clr r24\n"
        LFSR3("r8")
        LFSR3("r9")
        LFSR3("r10")
        LFSR3("r11")
        LFSR3("r12")
        LFSR3("r13")
        LFSR3("r14")
        LFSR3("r15")

        // Bottom of the loop.
        "dec %2\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        : : "x"(s), "z"(key), "r"(r)
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    uint32_t TK3[4];
    uint32_t *schedule = s;

    // Unpack the incoming key value into the TK3 array.
    // Easy since we assume the platform is little-endian.
    memcpy(TK3, key, sizeof(TK3));

    // XOR against the key schedule words for all rounds.
    for (uint8_t index = r; index > 0; --index, schedule += 2) {
        // XOR TK2 against the key schedule.
        schedule[0] ^= TK3[0];
        schedule[1] ^= TK3[1];

        // Permute TK3 for the next round.
        skinny128_permute_tk(TK3);

        // Apply LFSR3 to the first two rows of TK3.
        TK3[0] = skinny128_LFSR3(TK3[0]);
        TK3[1] = skinny128_LFSR3(TK3[1]);
    }

    // Clean up and exit.
    clean(TK3);
#endif // !USE_AVR_INLINE_ASM
}

/**
 * \brief Constructs a tweakable Skinny-128 block cipher object.
 *
 * \param schedule Points to the schedule data structure in the subclass.
 * \param rounds The number of rounds to perform during encryption/decryption.
 */
Skinny128_Tweaked::Skinny128_Tweaked(uint32_t *schedule, uint8_t rounds)
    : Skinny128(schedule, rounds)
{
}

/**
 * \brief Destroys this tweakable Skinny-128 block cipher object after
 * clearing sensitive information.
 */
Skinny128_Tweaked::~Skinny128_Tweaked()
{
    clean(t);
}

/**
 * \brief Sets the 128-bit tweak value for this block cipher.
 *
 * \param tweak Points to the tweak, and can be NULL if you want a
 * tweak of all-zeroes (the default).
 * \param len Length of \a tweak in bytes, which must be 16.
 *
 * \return Returns true if the tweak was set or false if \a len
 * is incorrect.
 *
 * This function must be called after setKey() as the setKey()
 * call will implicitly set the tweak back to all-zeroes.
 *
 * \sa setKey()
 */
bool Skinny128_Tweaked::setTweak(const uint8_t *tweak, size_t len)
{
    if (len != 16)
        return false;
    xorTK1(t);
    if (tweak) {
        memcpy(t, tweak, len);
        xorTK1(t);
    } else {
        memset(t, 0, sizeof(t));
    }
    return true;
}

void Skinny128_Tweaked::clear()
{
    clean(t);
    Skinny128::clear();
}

/**
 * \brief Resets the tweak to all-zeroes.
 *
 * This is used by subclass implementations of setKey().
 */
void Skinny128_Tweaked::resetTweak()
{
    memset(t, 0, sizeof(t));
    setTK1(t, true);
}

/**
 * \brief Constructs a Skinny-128 block cipher with a 128-bit key.
 */
Skinny128_128::Skinny128_128()
    : Skinny128(sched, 40)
{
}

/**
 * \brief Destroys this Skinny-128 block cipher object after
 * clearing sensitive information.
 */
Skinny128_128::~Skinny128_128()
{
    clean(sched);
}

/**
 * \brief Size of a Skinny128_128 key in bytes.
 * \return Always returns 16.
 */
size_t Skinny128_128::keySize() const
{
    return 16;
}

bool Skinny128_128::setKey(const uint8_t *key, size_t len)
{
    if (len != 16)
        return false;
    setTK1(key);
    return true;
}

/**
 * \brief Constructs a Skinny-128 block cipher with a 256-bit key.
 */
Skinny128_256::Skinny128_256()
    : Skinny128(sched, 48)
{
}

/**
 * \brief Destroys this Skinny-128 block cipher object after
 * clearing sensitive information.
 */
Skinny128_256::~Skinny128_256()
{
    clean(sched);
}

/**
 * \brief Size of a Skinny128_256 key in bytes.
 * \return Always returns 32.
 */
size_t Skinny128_256::keySize() const
{
    return 32;
}

bool Skinny128_256::setKey(const uint8_t *key, size_t len)
{
    if (len != 32)
        return false;
    setTK1(key);
    setTK2(key + 16);
    return true;
}

/**
 * \brief Constructs a tweakable Skinny-128 block cipher with a 128-bit key
 * and a 128-bit tweak.
 */
Skinny128_256_Tweaked::Skinny128_256_Tweaked()
    : Skinny128_Tweaked(sched, 48)
{
}

/**
 * \brief Destroys this tweakable Skinny-128 block cipher object after
 * clearing sensitive information.
 */
Skinny128_256_Tweaked::~Skinny128_256_Tweaked()
{
    clean(sched);
}

/**
 * \brief Size of a Skinny128_256_Tweaked key in bytes.
 * \return Always returns 16.
 */
size_t Skinny128_256_Tweaked::keySize() const
{
    return 16;
}

bool Skinny128_256_Tweaked::setKey(const uint8_t *key, size_t len)
{
    if (len != 16)
        return false;
    resetTweak();
    setTK2(key);
    return true;
}

/**
 * \brief Constructs a Skinny-128 block cipher with a 384-bit key.
 */
Skinny128_384::Skinny128_384()
    : Skinny128(sched, 56)
{
}

/**
 * \brief Destroys this Skinny-128 block cipher object after
 * clearing sensitive information.
 */
Skinny128_384::~Skinny128_384()
{
    clean(sched);
}

/**
 * \brief Size of a Skinny128_384 key in bytes.
 * \return Always returns 48.
 */
size_t Skinny128_384::keySize() const
{
    return 48;
}

bool Skinny128_384::setKey(const uint8_t *key, size_t len)
{
    if (len != 48)
        return false;
    setTK1(key);
    setTK2(key + 16);
    setTK3(key + 32);
    return true;
}

/**
 * \brief Constructs a tweakable Skinny-128 block cipher with a 256-bit key
 * and a 128-bit tweak.
 */
Skinny128_384_Tweaked::Skinny128_384_Tweaked()
    : Skinny128_Tweaked(sched, 56)
{
}

/**
 * \brief Destroys this tweakable Skinny-128 block cipher object after
 * clearing sensitive information.
 */
Skinny128_384_Tweaked::~Skinny128_384_Tweaked()
{
    clean(sched);
}

/**
 * \brief Size of a Skinny128_384_Tweaked key in bytes.
 * \return Always returns 32.
 */
size_t Skinny128_384_Tweaked::keySize() const
{
    return 32;
}

bool Skinny128_384_Tweaked::setKey(const uint8_t *key, size_t len)
{
    if (len != 32)
        return false;
    resetTweak();
    setTK2(key);
    setTK3(key + 16);
    return true;
}
