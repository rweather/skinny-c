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

#include "Mantis8.h"
#include "Crypto.h"
#include "utility/EndianUtil.h"
#include "utility/RotateUtil.h"
#include "utility/ProgMemUtil.h"
#include <string.h>

/**
 * \class Mantis8 Mantis8.h <Mantis8.h>
 * \brief Mantis-8 tweakable block cipher.
 *
 * Mantis is a tweakable block cipher with 64-bit blocks, a 128-bit
 * key, and a 64-bit tweak.  It is a variant of SKINNY that is designed
 * for memory encryption.  Typically, memory is encrypted in 8-byte blocks
 * in ECB mode with the memory address of each block supplied to the
 * cipher as the tweak.
 *
 * Mantis comes in variants with round counts between 5 and 8.
 * The authors advise that there is a known efficient attack
 * against Mantis-5.  They recommend using at least Mantis-7.
 * In this implementation we only support Mantis-8.  For a larger
 * security margin, use Skinny64 or Skinny128 instead.
 *
 * In Mantis, ECB encryption and decryption are identical operations.
 * The initial mode is set to encryption by setKey() and can then be
 * switched to decryption by calling swapModes().  The application can
 * continue to swap back and forth between encryption and decryption
 * as needed.
 *
 * Reference: https://sites.google.com/site/skinnycipher/
 *
 * \sa Skinny64, Skinny128
 */

#if defined(__AVR__)
#define USE_AVR_INLINE_ASM 1
#endif

#ifndef CRYPTO_LITTLE_ENDIAN
#error "Arduino platforms are assumed to be little-endian"
#endif

// Extract the 32 bits for a row from a 64-bit round constant.
#define RC_EXTRACT_ROW(x,shift) \
    (((((uint32_t)((x) >> ((shift) + 24))) & 0xFF)) | \
     ((((uint32_t)((x) >> ((shift) + 16))) & 0xFF) <<  8) | \
     ((((uint32_t)((x) >> ((shift) +  8))) & 0xFF) << 16) | \
     ((((uint32_t)((x) >> ((shift))))      & 0xFF) << 24))

// Alpha constant for adjusting k1 for the inverse rounds.
#define ALPHA      0x243F6A8885A308D3ULL
#define ALPHA_ROW0 (RC_EXTRACT_ROW(ALPHA, 32))
#define ALPHA_ROW1 (RC_EXTRACT_ROW(ALPHA, 0))

#ifndef USE_AVR_INLINE_ASM

// Extract the rows from a 64-bit round constant.
#define RC(x)    \
    {RC_EXTRACT_ROW((x), 32), RC_EXTRACT_ROW((x), 0)}

// Round constants for Mantis, split up into 32-bit row values.
static uint32_t const rc[8][2] = {
    RC(0x13198A2E03707344ULL),
    RC(0xA4093822299F31D0ULL),
    RC(0x082EFA98EC4E6C89ULL),
    RC(0x452821E638D01377ULL),
    RC(0xBE5466CF34E90C6CULL),
    RC(0xC0AC29B7C97C50DDULL),
    RC(0x3F84D5B5B5470917ULL),
    RC(0x9216D5D98979FB1BULL)
};

#endif // !USE_AVR_INLINE_ASM

/**
 * \brief Constructs a new Mantis-8 tweakable block cipher instance.
 */
Mantis8::Mantis8()
{
}

/**
 * \brief Destroys this Mantis-8 block cipher object after clearing
 * sensitive information.
 */
Mantis8::~Mantis8()
{
    clean(st);
}

/**
 * \brief Size of a Mantis-8 block in bytes.
 * \return Always returns 8.
 */
size_t Mantis8::blockSize() const
{
    return 8;
}

/**
 * \brief Size of a Mantis-8 key in bytes.
 * \return Always returns 16.
 */
size_t Mantis8::keySize() const
{
    return 16;
}

#ifndef USE_AVR_INLINE_ASM

inline void mantis_unpack_block(uint32_t *block, const uint8_t *buf)
{
    block[0] = ((uint32_t)(buf[0])) |
              (((uint32_t)(buf[1])) << 8) |
              (((uint32_t)(buf[2])) << 16) |
              (((uint32_t)(buf[3])) << 24);
    block[1] = ((uint32_t)(buf[4])) |
              (((uint32_t)(buf[5])) << 8) |
              (((uint32_t)(buf[6])) << 16) |
              (((uint32_t)(buf[7])) << 24);
}

static void mantis_unpack_rotated_block(uint32_t *block, const uint8_t *buf)
{
    uint8_t rotated[8];
    uint8_t index;
    uint8_t next;
    uint8_t carry = buf[7];
    for (index = 0; index < 8; ++index) {
        next = buf[index];
        rotated[index] = (carry << 7) | (next >> 1);
        carry = next;
    }
    rotated[7] ^= (buf[0] >> 7);
    mantis_unpack_block(block, rotated);
    clean(rotated);
}

#endif // !USE_AVR_INLINE_ASM

bool Mantis8::setKey(const uint8_t *key, size_t len)
{
    if (len != 16)
        return false;
#if USE_AVR_INLINE_ASM
    __asm__ __volatile__ (
        // Load k0 from the incoming key and store into the object.
        "ld r8,X+\n"
        "ld r9,X+\n"
        "ld r10,X+\n"
        "ld r11,X+\n"
        "ld r12,X+\n"
        "ld r13,X+\n"
        "ld r14,X+\n"
        "ld r15,X+\n"
        "st Z,r8\n"
        "std Z+1,r9\n"
        "std Z+2,r10\n"
        "std Z+3,r11\n"
        "std Z+4,r12\n"
        "std Z+5,r13\n"
        "std Z+6,r14\n"
        "std Z+7,r15\n"

        // Rotate k0 to create k0prime.
        "bst r15,0\n"
        "lsr r8\n"
        "ror r9\n"
        "ror r10\n"
        "ror r11\n"
        "ror r12\n"
        "ror r13\n"
        "ror r14\n"
        "ror r15\n"
        "bld r8,7\n"
        "mov __tmp_reg__,__zero_reg__\n"
        "bld __tmp_reg__,0\n"
        "eor r15,__tmp_reg__\n"
        "std Z+8,r8\n"
        "std Z+9,r9\n"
        "std Z+10,r10\n"
        "std Z+11,r11\n"
        "std Z+12,r12\n"
        "std Z+13,r13\n"
        "std Z+14,r14\n"
        "std Z+15,r15\n"

        // Load k1 from the incoming key and store into the object.
        "ld __tmp_reg__,X+\n"
        "std Z+16,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+17,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+18,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+19,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+20,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+21,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+22,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "std Z+23,__tmp_reg__\n"

        // Zero the tweak.
        "std Z+24,__zero_reg__\n"
        "std Z+25,__zero_reg__\n"
        "std Z+26,__zero_reg__\n"
        "std Z+27,__zero_reg__\n"
        "std Z+28,__zero_reg__\n"
        "std Z+29,__zero_reg__\n"
        "std Z+30,__zero_reg__\n"
        "std Z+31,__zero_reg__\n"

        : : "z"(&st), "x"(key)
        : "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory"
    );
#else
    mantis_unpack_block(st.k0, key);
    mantis_unpack_block(st.k1, key + 8);
    mantis_unpack_rotated_block(st.k0prime, key);
    st.tweak[0] = 0;
    st.tweak[1] = 0;
#endif
    return true;
}

/**
 * \brief Sets the 64-bit tweak value for this Mantis-8 block cipher.
 *
 * \param tweak Points to the tweak, and can be NULL if you want a
 * tweak of all-zeroes (the default).
 * \param len Length of \a tweak in bytes, which must be 8.
 *
 * \return Returns true if the tweak was set or false if \a len
 * is incorrect.
 *
 * This function must be called after setKey() as the setKey()
 * call will implicitly set the tweak back to all-zeroes.
 *
 * \sa setKey()
 */
bool Mantis8::setTweak(const uint8_t *tweak, size_t len)
{
    if (len != 8)
        return false;
#if USE_AVR_INLINE_ASM
    __asm__ __volatile__ (
        "mov __tmp_reg__,r26\n"
        "or __tmp_reg__,r27\n"
        "brne 1f\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "st Z+,__zero_reg__\n"
        "rjmp 2f\n"
        "1:\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "ld __tmp_reg__,X+\n"
        "st Z+,__tmp_reg__\n"
        "2:\n"
        : : "z"(st.tweak), "x"(tweak)
    );
#else
    if (tweak) {
        mantis_unpack_block(st.tweak, tweak);
    } else {
        st.tweak[0] = 0;
        st.tweak[1] = 0;
    }
#endif
    return true;
}

/**
 * \brief Swaps the encryption/decryption mode for this Mantis block cipher.
 *
 * When setKey() is called, the object is set up for encryption and calls
 * on either encryptBlock() or decryptBlock() will encrypt.  To decrypt
 * it is necessary to call swapModes() after setKey().
 */
void Mantis8::swapModes()
{
    // Swap k0 with k0prime.
    uint32_t temp = st.k0[0];
    st.k0[0] = st.k0prime[0];
    st.k0prime[0] = temp;
    temp = st.k0[1];
    st.k0[1] = st.k0prime[1];
    st.k0prime[1] = temp;

    // XOR k1 with the alpha constant.
    st.k1[0] ^= ALPHA_ROW0;
    st.k1[1] ^= ALPHA_ROW1;
}

#if USE_AVR_INLINE_ASM

// Extract the bytes from a 64-bit round constant.
#define RC_EXTRACT_BYTE(x,shift) ((uint8_t)((x) >> (shift)))
#define RC(x)    \
    RC_EXTRACT_BYTE((x), 56), \
    RC_EXTRACT_BYTE((x), 48), \
    RC_EXTRACT_BYTE((x), 40), \
    RC_EXTRACT_BYTE((x), 32), \
    RC_EXTRACT_BYTE((x), 24), \
    RC_EXTRACT_BYTE((x), 16), \
    RC_EXTRACT_BYTE((x),  8), \
    RC_EXTRACT_BYTE((x),  0)

// Force the sboxes to be aligned on a 256-byte boundary.
// This makes sbox lookups more efficient.
#define ALIGN256 __attribute__((aligned(256)))

// MIDORI Sb0, expanded from 4 bits to 8 bits for easier byte lookup.
// We only use this for AVR platforms, as there will be issues with
// constant cache behaviour on ARM.  It would be nice to avoid this
// for AVR as well, but the S-box operations are simply too slow using
// bit operations on AVR.
static uint8_t const sbox[256 + 64] PROGMEM ALIGN256 = {
    0xcc, 0xca, 0xcd, 0xc3, 0xce, 0xcb, 0xcf, 0xc7, 0xc8, 0xc9, 0xc1, 0xc5,
    0xc0, 0xc2, 0xc4, 0xc6, 0xac, 0xaa, 0xad, 0xa3, 0xae, 0xab, 0xaf, 0xa7,
    0xa8, 0xa9, 0xa1, 0xa5, 0xa0, 0xa2, 0xa4, 0xa6, 0xdc, 0xda, 0xdd, 0xd3,
    0xde, 0xdb, 0xdf, 0xd7, 0xd8, 0xd9, 0xd1, 0xd5, 0xd0, 0xd2, 0xd4, 0xd6,
    0x3c, 0x3a, 0x3d, 0x33, 0x3e, 0x3b, 0x3f, 0x37, 0x38, 0x39, 0x31, 0x35,
    0x30, 0x32, 0x34, 0x36, 0xec, 0xea, 0xed, 0xe3, 0xee, 0xeb, 0xef, 0xe7,
    0xe8, 0xe9, 0xe1, 0xe5, 0xe0, 0xe2, 0xe4, 0xe6, 0xbc, 0xba, 0xbd, 0xb3,
    0xbe, 0xbb, 0xbf, 0xb7, 0xb8, 0xb9, 0xb1, 0xb5, 0xb0, 0xb2, 0xb4, 0xb6,
    0xfc, 0xfa, 0xfd, 0xf3, 0xfe, 0xfb, 0xff, 0xf7, 0xf8, 0xf9, 0xf1, 0xf5,
    0xf0, 0xf2, 0xf4, 0xf6, 0x7c, 0x7a, 0x7d, 0x73, 0x7e, 0x7b, 0x7f, 0x77,
    0x78, 0x79, 0x71, 0x75, 0x70, 0x72, 0x74, 0x76, 0x8c, 0x8a, 0x8d, 0x83,
    0x8e, 0x8b, 0x8f, 0x87, 0x88, 0x89, 0x81, 0x85, 0x80, 0x82, 0x84, 0x86,
    0x9c, 0x9a, 0x9d, 0x93, 0x9e, 0x9b, 0x9f, 0x97, 0x98, 0x99, 0x91, 0x95,
    0x90, 0x92, 0x94, 0x96, 0x1c, 0x1a, 0x1d, 0x13, 0x1e, 0x1b, 0x1f, 0x17,
    0x18, 0x19, 0x11, 0x15, 0x10, 0x12, 0x14, 0x16, 0x5c, 0x5a, 0x5d, 0x53,
    0x5e, 0x5b, 0x5f, 0x57, 0x58, 0x59, 0x51, 0x55, 0x50, 0x52, 0x54, 0x56,
    0x0c, 0x0a, 0x0d, 0x03, 0x0e, 0x0b, 0x0f, 0x07, 0x08, 0x09, 0x01, 0x05,
    0x00, 0x02, 0x04, 0x06, 0x2c, 0x2a, 0x2d, 0x23, 0x2e, 0x2b, 0x2f, 0x27,
    0x28, 0x29, 0x21, 0x25, 0x20, 0x22, 0x24, 0x26, 0x4c, 0x4a, 0x4d, 0x43,
    0x4e, 0x4b, 0x4f, 0x47, 0x48, 0x49, 0x41, 0x45, 0x40, 0x42, 0x44, 0x46,
    0x6c, 0x6a, 0x6d, 0x63, 0x6e, 0x6b, 0x6f, 0x67, 0x68, 0x69, 0x61, 0x65,
    0x60, 0x62, 0x64, 0x66,

    // Put the round constants at the end of the S-box table so that
    // they can be accessed from the same pgmspace base pointer.
    RC(0x13198A2E03707344ULL),
    RC(0xA4093822299F31D0ULL),
    RC(0x082EFA98EC4E6C89ULL),
    RC(0x452821E638D01377ULL),
    RC(0xBE5466CF34E90C6CULL),
    RC(0xC0AC29B7C97C50DDULL),
    RC(0x3F84D5B5B5470917ULL),
    RC(0x9216D5D98979FB1BULL)
};

// Figure out how to do lookups from a pgmspace sbox table on this platform.
#if defined(RAMPZ)
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "out %6,r24\n" \
    "elpm " reg ",Z\n"
#define RC_SETUP(reg) \
    "ldi r25,1\n" \
    "mov r30," reg "\n" \
    "add r31,r25\n" \
    "adc r24,__zero_reg__\n" \
    "out %6,r24\n"
#define RC_CLEANUP(reg) \
    "sub r31,r25\n" \
    "sbc r24,__zero_reg__\n" \
    "sbiw r30,8\n" \
    "sbc r24,__zero_reg__\n"
#define RC_ADD(reg)   \
    "elpm r0,Z+\n" \
    "eor " reg ",r0\n"
#elif defined(__AVR_HAVE_LPMX__)
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "lpm " reg ",Z\n"
#define RC_SETUP(reg) \
    "ldi r25,1\n" \
    "mov r30," reg "\n" \
    "add r31,r25\n"
#define RC_CLEANUP(reg) \
    "sub r31,r25\n" \
    "sbiw r30,8\n"
#define RC_ADD(reg)   \
    "lpm r0,Z+\n" \
    "eor " reg ",r0\n"
#elif defined(__AVR_TINY__)
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "ld " reg ",Z\n"
#define RC_SETUP(reg) \
    "ldi r25,1\n" \
    "mov r30," reg "\n" \
    "add r31,r25\n"
#define RC_CLEANUP(reg) \
    "sub r31,r25\n" \
    "sbiw r30,8\n"
#define RC_ADD(reg)   \
    "ld r0,Z+\n" \
    "eor " reg ",r0\n"
#else
#define SBOX(reg)   \
    "mov r30," reg "\n" \
    "lpm\n" \
    "mov " reg ",r0\n"
#define RC_SETUP(reg) \
    "ldi r25,1\n" \
    "mov r30," reg "\n" \
    "add r31,r25\n"
#define RC_CLEANUP(reg) \
    "sub r31,r25\n" \
    "sbiw r30,8\n"
#define RC_ADD(reg)   \
    "lpm\n" \
    "eor " reg ",r0\n" \
    "adiw r30,1\n"
#endif

// Mix the columns during an encryption round.
#define MIX_COLUMNS(row0, row1, row2, row3) \
    "mov __tmp_reg__," row0 "\n" \
    "mov r25," row2 "\n" \
    "mov " row0 "," row1 "\n" \
    "mov " row1 ",__tmp_reg__\n" \
    "mov " row2 "," row3 "\n" \
    "mov " row3 ",r25\n" \
    "eor __tmp_reg__," row0 "\n" \
    "eor r25," row2 "\n" \
    "eor " row0 ",r25\n" \
    "eor " row1 ",r25\n" \
    "eor " row2 ",__tmp_reg__\n" \
    "eor " row3 ",__tmp_reg__\n" \

#else // !USE_AVR_INLINE_ASM

typedef union
{
    uint16_t row[4];
    uint32_t lrow[2];

} MantisCells_t;

inline uint32_t mantis_sbox(uint32_t d)
{
    /*
     * MIDORI Sb0 from section 4.2 of https://eprint.iacr.org/2015/1142.pdf
     *
     * {a, b, c, d} -> {aout, bout, cout, dout} where a/aout is the MSB.
     *
     * aout = NAND(NAND(~c, NAND(a, b)), (a | d))
     * bout = NAND(NOR(NOR(a, d), (b & c)), NAND((a & c), d))
     * cout = NAND(NAND(b, d), (NOR(b, d) | a))
     * dout = NOR(NOR(a, (b | c)), NAND(NAND(a, b), (c | d)))
     */
    uint32_t a = (d >> 3);
    uint32_t b = (d >> 2);
    uint32_t c = (d >> 1);
    uint32_t not_a = ~a;
    uint32_t ab = not_a | (~b);
    uint32_t ad = not_a & (~d);
    uint32_t aout = (((~c) & ab) | ad);
    uint32_t bout = ad | (b & c) | (a & c & d);
    uint32_t cout = (b & d) | ((b | d) & not_a);
    uint32_t dout = (a | b | c) & ab & (c | d);
    return ((aout & 0x11111111U) << 3) | ((bout & 0x11111111U) << 2) |
           ((cout & 0x11111111U) << 1) |  (dout & 0x11111111U);
}

inline void mantis_update_tweak(MantisCells_t *tweak)
{
    /* h = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11] */
    uint16_t row1 = tweak->row[1];
    uint16_t row3 = tweak->row[3];
    tweak->row[1] = tweak->row[0];
    tweak->row[3] = tweak->row[2];
    tweak->row[0] = ((row1 >>  8) & 0x00F0U) |
                     (row1        & 0x000FU) |
                     (row3        & 0xFF00U);
    tweak->row[2] = ((row1 <<  4) & 0x0F00U) |
                    ((row1 >>  4) & 0x00F0U) |
                    ((row3 >>  4) & 0x000FU) |
                    ((row3 << 12) & 0xF000U);
}

inline void mantis_update_tweak_inverse(MantisCells_t *tweak)
{
    /* h' = [4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3] */
    uint16_t row0 = tweak->row[0];
    uint16_t row2 = tweak->row[2];
    tweak->row[0] = tweak->row[1];
    tweak->row[2] = tweak->row[3];
    tweak->row[1] = ((row2 >>  4) & 0x00F0U) |
                    ((row2 <<  4) & 0x0F00U) |
                     (row0        & 0x000FU) |
                    ((row0 <<  8) & 0xF000U);
    tweak->row[3] =  (row0        & 0xFF00U) |
                    ((row2 <<  4) & 0x00F0U) |
                    ((row2 >> 12) & 0x000FU);
}

inline void mantis_shift_rows(MantisCells_t *state)
{
    /* P = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2] */
    uint16_t row0 = state->row[0];
    uint16_t row1 = state->row[1];
    uint16_t row2 = state->row[2];
    uint16_t row3 = state->row[3];
    state->row[0] =  (row0        & 0x00F0U) |
                     (row1        & 0xF000U) |
                    ((row2 >>  8) & 0x000FU) |
                    ((row3 <<  8) & 0x0F00U);
    state->row[1] =  (row0        & 0x000FU) |
                     (row1        & 0x0F00U) |
                    ((row2 >>  8) & 0x00F0U) |
                    ((row3 <<  8) & 0xF000U);
    state->row[2] = ((row0 <<  4) & 0xF000U) |
                    ((row1 <<  4) & 0x00F0U) |
                    ((row2 <<  4) & 0x0F00U) |
                    ((row3 >> 12) & 0x000FU);
    state->row[3] = ((row0 >>  4) & 0x0F00U) |
                    ((row1 >>  4) & 0x000FU) |
                    ((row2 << 12) & 0xF000U) |
                    ((row3 >>  4) & 0x00F0U);
}

inline void mantis_shift_rows_inverse(MantisCells_t *state)
{
    /* P' = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12] */
    uint16_t row0 = state->row[0];
    uint16_t row1 = state->row[1];
    uint16_t row2 = state->row[2];
    uint16_t row3 = state->row[3];
    state->row[0] =  (row0        & 0x00F0U) |
                     (row1        & 0x000FU) |
                    ((row2 >>  4) & 0x0F00U) |
                    ((row3 <<  4) & 0xF000U);
    state->row[1] =  (row0        & 0xF000U) |
                     (row1        & 0x0F00U) |
                    ((row2 >>  4) & 0x000FU) |
                    ((row3 <<  4) & 0x00F0U);
    state->row[2] = ((row0 <<  8) & 0x0F00U) |
                    ((row1 <<  8) & 0xF000U) |
                    ((row2 >>  4) & 0x00F0U) |
                    ((row3 >> 12) & 0x000FU);
    state->row[3] = ((row0 >>  8) & 0x000FU) |
                    ((row1 >>  8) & 0x00F0U) |
                    ((row2 << 12) & 0xF000U) |
                    ((row3 <<  4) & 0x0F00U);
}

inline void mantis_mix_columns(MantisCells_t *state)
{
    uint16_t t0 = state->row[0];
    uint16_t t1 = state->row[1];
    uint16_t t2 = state->row[2];
    uint16_t t3 = state->row[3];
    state->row[0] = t1 ^ t2 ^ t3;
    state->row[1] = t0 ^ t2 ^ t3;
    state->row[2] = t0 ^ t1 ^ t3;
    state->row[3] = t0 ^ t1 ^ t2;
}

#endif // !USE_AVR_INLINE_ASM

void Mantis8::encryptBlock(uint8_t *output, const uint8_t *input)
{
#if USE_AVR_INLINE_ASM
#if defined(RAMPZ)
    uint32_t sbox_addr = (uint32_t)sbox;
#else
    uint16_t sbox_addr = (uint16_t)sbox;
#endif
    uint32_t k1_0, k1_1;
    __asm__ __volatile__ (
        // Load the input block into r8..r15.
        "ld r8,X+\n"
        "ld r9,X+\n"
        "ld r10,X+\n"
        "ld r11,X+\n"
        "ld r12,X+\n"
        "ld r13,X+\n"
        "ld r14,X+\n"
        "ld r15,X+\n"

        // Load k1 from the state into k1_0 and k1_1 and XOR with the state.
        "ldd r16,Z+16\n"
        "ldd r17,Z+17\n"
        "ldd r18,Z+18\n"
        "ldd r19,Z+19\n"
        "ldd r20,Z+20\n"
        "ldd r21,Z+21\n"
        "ldd r22,Z+22\n"
        "ldd r23,Z+23\n"
        "eor r8,r16\n"
        "eor r9,r17\n"
        "eor r10,r18\n"
        "eor r11,r19\n"
        "eor r12,r20\n"
        "eor r13,r21\n"
        "eor r14,r22\n"
        "eor r15,r23\n"
        "std %A4,r16\n"
        "std %B4,r17\n"
        "std %C4,r18\n"
        "std %D4,r19\n"
        "std %A5,r20\n"
        "std %B5,r21\n"
        "std %C5,r22\n"
        "std %D5,r23\n"

        // Load the tweak into r16..r23.
        "ldd r16,Z+24\n"
        "ldd r17,Z+25\n"
        "ldd r18,Z+26\n"
        "ldd r19,Z+27\n"
        "ldd r20,Z+28\n"
        "ldd r21,Z+29\n"
        "ldd r22,Z+30\n"
        "ldd r23,Z+31\n"

        // XOR the initial whitening key k0 and the tweak with the state.
        // state.lrow[0] ^= st.k0[0] ^ k1.lrow[0] ^ tweak.lrow[0];
        // state.lrow[1] ^= st.k0[1] ^ k1.lrow[1] ^ tweak.lrow[1];
        // Note: k1 was already XOR'ed in above prior to loading the tweak.
        "ld __tmp_reg__,Z\n"            // r8 ^= k0[0] ^ k1[0] ^ r16
        "eor r8,__tmp_reg__\n"
        "eor r8,r16\n"
        "ldd __tmp_reg__,Z+1\n"         // r9 ^= k0[1] ^ k1[1] ^ r17
        "eor r9,__tmp_reg__\n"
        "eor r9,r17\n"
        "ldd __tmp_reg__,Z+2\n"         // r10 ^= k0[2] ^ k1[2] ^ r18
        "eor r10,__tmp_reg__\n"
        "eor r10,r18\n"
        "ldd __tmp_reg__,Z+3\n"         // r11 ^= k0[3] ^ k1[3] ^ r19
        "eor r11,__tmp_reg__\n"
        "eor r11,r19\n"
        "ldd __tmp_reg__,Z+4\n"         // r12 ^= k0[4] ^ k1[4] ^ r20
        "eor r12,__tmp_reg__\n"
        "eor r12,r20\n"
        "ldd __tmp_reg__,Z+5\n"         // r13 ^= k0[5] ^ k1[5] ^ r21
        "eor r13,__tmp_reg__\n"
        "eor r13,r21\n"
        "ldd __tmp_reg__,Z+6\n"         // r14 ^= k0[6] ^ k1[6] ^ r22
        "eor r14,__tmp_reg__\n"
        "eor r14,r22\n"
        "ldd __tmp_reg__,Z+7\n"         // r15 ^= k0[7] ^ k1[7] ^ r23
        "eor r15,__tmp_reg__\n"
        "eor r15,r23\n"

        // Save the state pointer in Z into X.
        "movw r26,r30\n"

        // Set up Z to point to the start of the sbox table.
#if defined(RAMPZ)
        "in __tmp_reg__,%6\n"
        "push __tmp_reg__\n"
#endif
        "ldd r30,%A3\n"
        "ldd r31,%B3\n"

        // Top of the loop for the eight forward rounds.
        "clr r7\n"              // r7 is the RC table offset and loop counter.
        "1:\n"

        // Update the tweak using the h permutation.
        // h = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11]
        "push r16\n"        // Save [0, 1, 2, 3, 8, 9, 10, 11] on the stack.
        "push r17\n"
        "push r20\n"
        "push r21\n"
        "mov r17,r23\n"     // TK[2/3] = TK[14/15]
        "mov r16,r18\n"     // TK[1] = TK[5]
        "andi r16,0x0F\n"
        "swap r18\n"        // TK[11] = TK[4]
        "mov r21,r18\n"
        "andi r21,0x0F\n"
        "mov r20,r19\n"     // TK[8] = TK[7]
        "swap r20\n"
        "andi r20,0xF0\n"
        "andi r19,0xF0\n"   // TK[0] = TK[6]
        "or r16,r19\n"
        "swap r22\n"        // TK[9] = TK[12]
        "mov r23,r22\n"
        "andi r23,0x0F\n"
        "or r20,r23\n"
        "andi r22,0xF0\n"   // TK[10] = TK[13]
        "or r21,r22\n"
        "pop r23\n"         // Restore saved values from the stack
        "pop r22\n"         // into [4, 5, 6, 7, 12, 13, 14, 15]
        "pop r19\n"
        "pop r18\n"

        // Transform the state using the sbox.
#if defined(RAMPZ)
        "ldd r24,%C3\n"
#endif
        SBOX("r8")
        SBOX("r9")
        SBOX("r10")
        SBOX("r11")
        SBOX("r12")
        SBOX("r13")
        SBOX("r14")
        SBOX("r15")

        // Add the round constant.
        RC_SETUP("r7")
        RC_ADD("r8")
        RC_ADD("r9")
        RC_ADD("r10")
        RC_ADD("r11")
        RC_ADD("r12")
        RC_ADD("r13")
        RC_ADD("r14")
        RC_ADD("r15")
        RC_CLEANUP("r7")

        // XOR with the key and tweak.
        // state.lrow[0] ^= k1.lrow[0] ^ tweak.lrow[0];
        // state.lrow[1] ^= k1.lrow[1] ^ tweak.lrow[1];
        "ldd __tmp_reg__,%A4\n"
        "eor r8,__tmp_reg__\n"
        "eor r8,r16\n"
        "ldd __tmp_reg__,%B4\n"
        "eor r9,__tmp_reg__\n"
        "eor r9,r17\n"
        "ldd __tmp_reg__,%C4\n"
        "eor r10,__tmp_reg__\n"
        "eor r10,r18\n"
        "ldd __tmp_reg__,%D4\n"
        "eor r11,__tmp_reg__\n"
        "eor r11,r19\n"
        "ldd __tmp_reg__,%A5\n"
        "eor r12,__tmp_reg__\n"
        "eor r12,r20\n"
        "ldd __tmp_reg__,%B5\n"
        "eor r13,__tmp_reg__\n"
        "eor r13,r21\n"
        "ldd __tmp_reg__,%C5\n"
        "eor r14,__tmp_reg__\n"
        "eor r14,r22\n"
        "ldd __tmp_reg__,%D5\n"
        "eor r15,__tmp_reg__\n"
        "eor r15,r23\n"

        // Shift the rows using the P permutation.
        // P = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2]
        "ldi r24,0xF0\n"
        "ldi r25,0x0F\n"
        "mov __tmp_reg__,r8\n"
        "and r8,r24\n"              // S'[0] = S[0]
        "mov r6,r10\n"
        "mov r10,r13\n"             // S'[4] = S[10]
        "and r10,r24\n"
        "and __tmp_reg__,r25\n"     // S'[5] = S[1]
        "or r10,__tmp_reg__\n"
        "and r13,r25\n"             // S'[1] = S[11]
        "or r8,r13\n"
        "swap r9\n"                 // S'[10] = S[3]
        "mov r13,r9\n"
        "and r13,r24\n"
        "swap r12\n"                // S'[11] = S[8]
        "mov __tmp_reg__,r12\n"
        "and __tmp_reg__,r25\n"
        "or r13,__tmp_reg__\n"
        "and r9,r25\n"              // S'[15] = S[2]
        "and r12,r24\n"
        "or r12,r9\n"               // S'[14] = S[9]
        "mov r9,r11\n"              // S'[2] = S[6]
        "and r9,r24\n"
        "mov __tmp_reg__,r14\n"     // S'[3] = S[13]
        "and __tmp_reg__,r25\n"
        "or r9,__tmp_reg__\n"
        "and r11,r25\n"             // S'[7] = S[7]
        "and r14,r24\n"             // S'[6] = S[12]
        "or r11,r14\n"
        "mov r14,r15\n"             // S'[12] = S[15]
        "swap r14\n"
        "mov __tmp_reg__,r14\n"
        "mov r15,r12\n"
        "and r14,r24\n"
        "swap r6\n"                 // S'[8] = S[5]
        "mov r12,r6\n"
        "and r12,r24\n"
        "and __tmp_reg__,r25\n"     // S'[9] = S[14]
        "or r12,__tmp_reg__\n"
        "and r6,r25\n"              // S'[13] = S[4]
        "or r14,r6\n"

        // Mix the columns.
        MIX_COLUMNS("r8", "r10", "r12", "r14")
        MIX_COLUMNS("r9", "r11", "r13", "r15")

        // Bottom of the loop for the eight forward rounds.
        "ldi r24,8\n"           // r7 += 8
        "add r7,r24\n"          // loop if r7 < 64
        "ldi r24,64\n"
        "cp r7,r24\n"
        "breq 2f\n"
        "rjmp 1b\n"
        "2:\n"

        // Half-way there: sbox, mix, sbox.
#if defined(RAMPZ)
        "ldd r24,%C3\n"
#endif
        SBOX("r8")
        SBOX("r9")
        SBOX("r10")
        SBOX("r11")
        SBOX("r12")
        SBOX("r13")
        SBOX("r14")
        SBOX("r15")
        MIX_COLUMNS("r8", "r10", "r12", "r14")
        MIX_COLUMNS("r9", "r11", "r13", "r15")
        SBOX("r8")
        SBOX("r9")
        SBOX("r10")
        SBOX("r11")
        SBOX("r12")
        SBOX("r13")
        SBOX("r14")
        SBOX("r15")

        // Convert k1 into k1 XOR alpha for the reverse rounds.
        // alpha = 0x243F6A8885A308D3
        #define ALPHA_ADJUST(reg, c) \
            "ldi r24," c "\n" \
            "ldd __tmp_reg__," reg "\n" \
            "eor __tmp_reg__,r24\n" \
            "std " reg ",__tmp_reg__\n"
        ALPHA_ADJUST("%A4", "0x24")
        ALPHA_ADJUST("%B4", "0x3F")
        ALPHA_ADJUST("%C4", "0x6A")
        ALPHA_ADJUST("%D4", "0x88")
        ALPHA_ADJUST("%A5", "0x85")
        ALPHA_ADJUST("%B5", "0xA3")
        ALPHA_ADJUST("%C5", "0x08")
        ALPHA_ADJUST("%D5", "0xD3")

        // Top of the loop for the eight reverse rounds.
        "3:\n"
        "ldi r24,8\n"           // r7 -= 8
        "sub r7,r24\n"

        // Mix the columns.
        MIX_COLUMNS("r8", "r10", "r12", "r14")
        MIX_COLUMNS("r9", "r11", "r13", "r15")

        // Shift the rows using the inverse of the P permutation.
        // P' = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12]
        "ldi r24,0xF0\n"
        "ldi r25,0x0F\n"
        "mov __tmp_reg__,r8\n"      // S'[0] = S[0]
        "and r8,r24\n"
        "mov r6,r10\n"              // S'[1] = S[5]
        "and r6,r25\n"
        "or r8,r6\n"
        "and __tmp_reg__,r25\n"     // S'[11] = S[1]
        "and r10,r24\n"             // S'[10] = S[4]
        "or r10,__tmp_reg__\n"
        "mov __tmp_reg__,r13\n"
        "mov r13,r10\n"
        "swap __tmp_reg__\n"        // S'[3] = S[10]
        "mov r6,r9\n"
        "mov r9,__tmp_reg__\n"
        "and r9,r25\n"
        "swap r15\n"                // S'[2] = S[15]
        "mov r10,r15\n"
        "and r10,r24\n"
        "or r9,r10\n"
        "and r15,r25\n"             // S'[9] = S[14]
        "and __tmp_reg__,r24\n"     // S'[8] = S[11]
        "or r15,__tmp_reg__\n"
        "mov __tmp_reg__,r11\n"     // S'[7] = S[7]
        "and r11,r25\n"
        "and __tmp_reg__,r24\n"     // S'[12] = S[6]
        "mov r10,r6\n"              // S'[6] = S[2]
        "and r10,r24\n"
        "or r11,r10\n"
        "and r6,r25\n"              // S'[13] = S[3]
        "or r6,__tmp_reg__\n"
        "swap r12\n"                // S'[5] = S[8]
        "swap r14\n"                // S'[4] = S[13]
        "mov r10,r12\n"
        "and r10,r25\n"
        "mov __tmp_reg__,r14\n"
        "and __tmp_reg__,r24\n"
        "or r10,__tmp_reg__\n"
        "and r12,r24\n"             // S'[14] = S[9]
        "and r14,r25\n"             // S'[15] = S[12]
        "or r14,r12\n"
        "mov r12,r15\n"
        "mov r15,r14\n"
        "mov r14,r6\n"

        // XOR with the key and tweak.
        // state.lrow[0] ^= k1.lrow[0] ^ tweak.lrow[0];
        // state.lrow[1] ^= k1.lrow[1] ^ tweak.lrow[1];
        "ldd __tmp_reg__,%A4\n"
        "eor r8,__tmp_reg__\n"
        "eor r8,r16\n"
        "ldd __tmp_reg__,%B4\n"
        "eor r9,__tmp_reg__\n"
        "eor r9,r17\n"
        "ldd __tmp_reg__,%C4\n"
        "eor r10,__tmp_reg__\n"
        "eor r10,r18\n"
        "ldd __tmp_reg__,%D4\n"
        "eor r11,__tmp_reg__\n"
        "eor r11,r19\n"
        "ldd __tmp_reg__,%A5\n"
        "eor r12,__tmp_reg__\n"
        "eor r12,r20\n"
        "ldd __tmp_reg__,%B5\n"
        "eor r13,__tmp_reg__\n"
        "eor r13,r21\n"
        "ldd __tmp_reg__,%C5\n"
        "eor r14,__tmp_reg__\n"
        "eor r14,r22\n"
        "ldd __tmp_reg__,%D5\n"
        "eor r15,__tmp_reg__\n"
        "eor r15,r23\n"

        // Add the round constant.
#if defined(RAMPZ)
        "ldd r24,%C3\n"
#endif
        RC_SETUP("r7")
        RC_ADD("r8")
        RC_ADD("r9")
        RC_ADD("r10")
        RC_ADD("r11")
        RC_ADD("r12")
        RC_ADD("r13")
        RC_ADD("r14")
        RC_ADD("r15")
        RC_CLEANUP("r7")

        // Transform the state using the sbox.
        SBOX("r8")
        SBOX("r9")
        SBOX("r10")
        SBOX("r11")
        SBOX("r12")
        SBOX("r13")
        SBOX("r14")
        SBOX("r15")

        // Update the tweak using the inverse h permutation.
        // h' = [4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3]
        "push r18\n"        // Save [4, 5, 6, 7, 12, 13, 14, 15] on the stack.
        "push r19\n"
        "push r22\n"
        "push r23\n"
        "mov r23,r17\n"     // TK[14/15] = TK[2/3]
        "mov r19,r16\n"     // TK[6] = TK[0]
        "andi r19,0xF0\n"
        "mov r18,r16\n"     // TK[5] = TK[1]
        "andi r18,0x0F\n"
        "swap r20\n"        // TK[12] = TK[9]
        "mov r22,r20\n"
        "andi r22,0xF0\n"
        "andi r20,0x0F\n"   // TK[7] = TK[8]
        "or r19,r20\n"
        "swap r21\n"
        "mov r20,r21\n"     // TK[4] = TK[11]
        "andi r20,0xF0\n"
        "or r18,r20\n"
        "andi r21,0x0F\n"   // TK[13] = TK[10]
        "or r22,r21\n"
        "pop r21\n"         // Restore saved values from the stack
        "pop r20\n"         // into [0, 1, 2, 3, 8, 9, 10, 11]
        "pop r17\n"
        "pop r16\n"

        // Bottom of the loop for the eight reverse rounds.
        "or r7,r7\n"            // loop if r7 > 0
        "breq 4f\n"
        "rjmp 3b\n"
        "4:\n"

        // Restore the original RAMPZ value.
#if defined(RAMPZ)
        "pop __tmp_reg__\n"
        "out %6,__tmp_reg__\n"
#endif

        // Restore the state pointer from X into Z.
        "movw r30,r26\n"

        // XOR the final whitening key k0prime with the state,
        // together with k1alpha and the final tweak value.
        // state.lrow[0] ^= st.k0prime[0] ^ k1.lrow[0] ^ tweak.lrow[0];
        // state.lrow[1] ^= st.k0prime[1] ^ k1.lrow[1] ^ tweak.lrow[1];
        "ldd __tmp_reg__,Z+8\n"         // r8 ^= k0prime[0] ^ k1[0] ^ r16
        "eor r8,__tmp_reg__\n"
        "ldd __tmp_reg__,%A4\n"
        "eor r8,__tmp_reg__\n"
        "eor r8,r16\n"
        "ldd __tmp_reg__,Z+9\n"         // r9 ^= k0prime[1] ^ k1[1] ^ r17
        "eor r9,__tmp_reg__\n"
        "ldd __tmp_reg__,%B4\n"
        "eor r9,__tmp_reg__\n"
        "eor r9,r17\n"
        "ldd __tmp_reg__,Z+10\n"        // r10 ^= k0prime[2] ^ k1[2] ^ r18
        "eor r10,__tmp_reg__\n"
        "ldd __tmp_reg__,%C4\n"
        "eor r10,__tmp_reg__\n"
        "eor r10,r18\n"
        "ldd __tmp_reg__,Z+11\n"        // r11 ^= k0prime[3] ^ k1[3] ^ r19
        "eor r11,__tmp_reg__\n"
        "ldd __tmp_reg__,%D4\n"
        "eor r11,__tmp_reg__\n"
        "eor r11,r19\n"
        "ldd __tmp_reg__,Z+12\n"        // r12 ^= k0prime[4] ^ k1[4] ^ r20
        "eor r12,__tmp_reg__\n"
        "ldd __tmp_reg__,%A5\n"
        "eor r12,__tmp_reg__\n"
        "eor r12,r20\n"
        "ldd __tmp_reg__,Z+13\n"        // r13 ^= k0prime[5] ^ k1[5] ^ r21
        "eor r13,__tmp_reg__\n"
        "ldd __tmp_reg__,%B5\n"
        "eor r13,__tmp_reg__\n"
        "eor r13,r21\n"
        "ldd __tmp_reg__,Z+14\n"        // r14 ^= k0prime[6] ^ k1[6] ^ r22
        "eor r14,__tmp_reg__\n"
        "ldd __tmp_reg__,%C5\n"
        "eor r14,__tmp_reg__\n"
        "eor r14,r22\n"
        "ldd __tmp_reg__,Z+15\n"        // r15 ^= k0prime[7] ^ k1[7] ^ r23
        "eor r15,__tmp_reg__\n"
        "ldd __tmp_reg__,%D5\n"
        "eor r15,__tmp_reg__\n"
        "eor r15,r23\n"

        // Store r8..r15 to the output block.
        "ldd r26,%A2\n"
        "ldd r27,%B2\n"
        "st X+,r8\n"
        "st X+,r9\n"
        "st X+,r10\n"
        "st X+,r11\n"
        "st X+,r12\n"
        "st X+,r13\n"
        "st X+,r14\n"
        "st X+,r15\n"
        : : "x"(input), "z"(&st), "Q"(output), "Q"(sbox_addr),
            "Q"(k1_0), "Q"(k1_1)
#if defined(RAMPZ)
            , "I" (_SFR_IO_ADDR(RAMPZ))
#endif
        :  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
          "r24", "r25", "r6", "r7", "memory"
    );
#else // !USE_AVR_INLINE_ASM
    const uint32_t *r = rc[0];
    MantisCells_t tweak;
    MantisCells_t k1;
    MantisCells_t state;
    uint8_t index;

    // Copy the initial tweak and k1 values into local variables.
    tweak.lrow[0] = st.tweak[0];
    tweak.lrow[1] = st.tweak[1];
    k1.lrow[0] = st.k1[0];
    k1.lrow[1] = st.k1[1];

    // Read the input buffer and convert little-endian to host-endian.
    mantis_unpack_block(state.lrow, input);

    // XOR the initial whitening key k0 with the state,
    // together with k1 and the initial tweak value.
    state.lrow[0] ^= st.k0[0] ^ k1.lrow[0] ^ tweak.lrow[0];
    state.lrow[1] ^= st.k0[1] ^ k1.lrow[1] ^ tweak.lrow[1];

    // Perform all eight forward rounds.
    for (index = 8; index > 0; --index) {
        // Update the tweak with the forward h function.
        mantis_update_tweak(&tweak);

        // Apply the S-box.
        state.lrow[0] = mantis_sbox(state.lrow[0]);
        state.lrow[1] = mantis_sbox(state.lrow[1]);

        // Add the round constant.
        state.lrow[0] ^= r[0];
        state.lrow[1] ^= r[1];
        r += 2;

        // XOR with the key and tweak.
        state.lrow[0] ^= k1.lrow[0] ^ tweak.lrow[0];
        state.lrow[1] ^= k1.lrow[1] ^ tweak.lrow[1];

        // Shift the rows.
        mantis_shift_rows(&state);

        // Mix the columns.
        mantis_mix_columns(&state);
    }

    // Half-way there: sbox, mix, sbox.
    state.lrow[0] = mantis_sbox(state.lrow[0]);
    state.lrow[1] = mantis_sbox(state.lrow[1]);
    mantis_mix_columns(&state);
    state.lrow[0] = mantis_sbox(state.lrow[0]);
    state.lrow[1] = mantis_sbox(state.lrow[1]);

    // Convert k1 into k1 XOR alpha for the reverse rounds.
    k1.lrow[0] ^= ALPHA_ROW0;
    k1.lrow[1] ^= ALPHA_ROW1;

    // Perform all eight reverse rounds.
    for (index = 8; index > 0; --index) {
        // Inverse mix of the columns (same as the forward mix).
        mantis_mix_columns(&state);

        // Inverse shift of the rows.
        mantis_shift_rows_inverse(&state);

        /* XOR with the key and tweak */
        state.lrow[0] ^= k1.lrow[0] ^ tweak.lrow[0];
        state.lrow[1] ^= k1.lrow[1] ^ tweak.lrow[1];

        // Add the round constant.
        r -= 2;
        state.lrow[0] ^= r[0];
        state.lrow[1] ^= r[1];

        // Apply the inverse S-box (which is the same as the forward S-box).
        state.lrow[0] = mantis_sbox(state.lrow[0]);
        state.lrow[1] = mantis_sbox(state.lrow[1]);

        // Update the tweak with the reverse h function.
        mantis_update_tweak_inverse(&tweak);
    }

    // XOR the final whitening key k0prime with the state,
    // together with k1alpha and the final tweak value.
    state.lrow[0] ^= st.k0prime[0] ^ k1.lrow[0] ^ tweak.lrow[0];
    state.lrow[1] ^= st.k0prime[1] ^ k1.lrow[1] ^ tweak.lrow[1];

    // Convert host-endian back into little-endian in the output buffer.
    uint32_t x = state.lrow[0];
    output[0] = (uint8_t)x;
    output[1] = (uint8_t)(x >> 8);
    output[2] = (uint8_t)(x >> 16);
    output[3] = (uint8_t)(x >> 24);
    x = state.lrow[1];
    output[4] = (uint8_t)x;
    output[5] = (uint8_t)(x >> 8);
    output[6] = (uint8_t)(x >> 16);
    output[7] = (uint8_t)(x >> 24);
#endif // !USE_AVR_INLINE_ASM
}

void Mantis8::decryptBlock(uint8_t *output, const uint8_t *input)
{
    // Decryption is the same as encryption - need to use swapModes()
    // after setKey() to select decryption mode instead of encryption.
    encryptBlock(output, input);
}

void Mantis8::clear()
{
    clean(st);
}
