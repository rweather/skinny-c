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

/*
This example runs tests on the Skinny128 implementation to
verify correct behaviour.
*/

#include <Skinny.h>
#include <string.h>

struct TestVector
{
    const char *name;
    byte key[48];
    byte plaintext[16];
    byte ciphertext[16];
};

// Define the test vectors from https://eprint.iacr.org/2016/660.pdf
static TestVector const testVectorSkinny128_128 = {
    "Skinny-128-128",
    {0x4f, 0x55, 0xcf, 0xb0, 0x52, 0x0c, 0xac, 0x52,
     0xfd, 0x92, 0xc1, 0x5f, 0x37, 0x07, 0x3e, 0x93},
    {0xf2, 0x0a, 0xdb, 0x0e, 0xb0, 0x8b, 0x64, 0x8a,
     0x3b, 0x2e, 0xee, 0xd1, 0xf0, 0xad, 0xda, 0x14},
    {0x22, 0xff, 0x30, 0xd4, 0x98, 0xea, 0x62, 0xd7,
     0xe4, 0x5b, 0x47, 0x6e, 0x33, 0x67, 0x5b, 0x74}
};
static TestVector const testVectorSkinny128_256 = {
    "Skinny-128-256",
    {0x00, 0x9c, 0xec, 0x81, 0x60, 0x5d, 0x4a, 0xc1,
     0xd2, 0xae, 0x9e, 0x30, 0x85, 0xd7, 0xa1, 0xf3,
     0x1a, 0xc1, 0x23, 0xeb, 0xfc, 0x00, 0xfd, 0xdc,
     0xf0, 0x10, 0x46, 0xce, 0xed, 0xdf, 0xca, 0xb3},
    {0x3a, 0x0c, 0x47, 0x76, 0x7a, 0x26, 0xa6, 0x8d,
     0xd3, 0x82, 0xa6, 0x95, 0xe7, 0x02, 0x2e, 0x25},
    {0xb7, 0x31, 0xd9, 0x8a, 0x4b, 0xde, 0x14, 0x7a,
     0x7e, 0xd4, 0xa6, 0xf1, 0x6b, 0x9b, 0x58, 0x7f}
};
static TestVector const testVectorSkinny128_384 = {
    "Skinny-128-384",
    {0xdf, 0x88, 0x95, 0x48, 0xcf, 0xc7, 0xea, 0x52,
     0xd2, 0x96, 0x33, 0x93, 0x01, 0x79, 0x74, 0x49,
     0xab, 0x58, 0x8a, 0x34, 0xa4, 0x7f, 0x1a, 0xb2,
     0xdf, 0xe9, 0xc8, 0x29, 0x3f, 0xbe, 0xa9, 0xa5,
     0xab, 0x1a, 0xfa, 0xc2, 0x61, 0x10, 0x12, 0xcd,
     0x8c, 0xef, 0x95, 0x26, 0x18, 0xc3, 0xeb, 0xe8},
    {0xa3, 0x99, 0x4b, 0x66, 0xad, 0x85, 0xa3, 0x45,
     0x9f, 0x44, 0xe9, 0x2b, 0x08, 0xf5, 0x50, 0xcb},
    {0x94, 0xec, 0xf5, 0x89, 0xe2, 0x01, 0x7c, 0x60,
     0x1b, 0x38, 0xc6, 0x34, 0x6a, 0x10, 0xdc, 0xfa}
};

Skinny128_128 *skinny128_128;
Skinny128_256 *skinny128_256;
Skinny128_384 *skinny128_384;

byte buffer[16];

void testCipher(BlockCipher *cipher, const struct TestVector *test)
{
    Serial.print(test->name);
    Serial.print(" Encryption ... ");
    cipher->setKey(test->key, cipher->keySize());
    cipher->encryptBlock(buffer, test->plaintext);
    if (memcmp(buffer, test->ciphertext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");

    Serial.print(test->name);
    Serial.print(" Decryption ... ");
    cipher->decryptBlock(buffer, test->ciphertext);
    if (memcmp(buffer, test->plaintext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void perfCipher(BlockCipher *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    Serial.print(test->name);
    Serial.print(" Set Key ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->setKey(test->key, cipher->keySize());
    }
    elapsed = micros() - start;
    Serial.print(elapsed / 5000.0);
    Serial.print("us per operation, ");
    Serial.print((5000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");

    Serial.print(test->name);
    Serial.print(" Encrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->encryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.print(test->name);
    Serial.print(" Decrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->decryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.println();
}

void setup()
{
    Serial.begin(9600);

    Serial.println();

    Serial.println("State Sizes:");
    Serial.print("Skinny128_128 ... ");
    Serial.println(sizeof(Skinny128_128));
    Serial.print("Skinny128_256 ... ");
    Serial.println(sizeof(Skinny128_256));
    Serial.print("Skinny128_384 ... ");
    Serial.println(sizeof(Skinny128_384));
    Serial.println();

    Serial.println("Skinny128 Test Vectors:");
    skinny128_128 = new Skinny128_128();
    testCipher(skinny128_128, &testVectorSkinny128_128);
    delete skinny128_128;
    skinny128_256 = new Skinny128_256();
    testCipher(skinny128_256, &testVectorSkinny128_256);
    delete skinny128_256;
    skinny128_384 = new Skinny128_384();
    testCipher(skinny128_384, &testVectorSkinny128_384);
    delete skinny128_384;

    Serial.println();

    Serial.println("Skinny128 Performance Tests:");
    skinny128_128 = new Skinny128_128();
    perfCipher(skinny128_128, &testVectorSkinny128_128);
    delete skinny128_128;
    skinny128_256 = new Skinny128_256();
    perfCipher(skinny128_256, &testVectorSkinny128_256);
    delete skinny128_256;
    skinny128_384 = new Skinny128_384();
    perfCipher(skinny128_384, &testVectorSkinny128_384);
    delete skinny128_384;
}

void loop()
{
}
