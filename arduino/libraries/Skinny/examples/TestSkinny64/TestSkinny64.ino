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
This example runs tests on the Skinny64 implementation to
verify correct behaviour.
*/

#include <Skinny.h>
#include <string.h>

struct TestVector
{
    const char *name;
    byte key[24];
    byte plaintext[8];
    byte ciphertext[8];
};

// Define the test vectors from https://eprint.iacr.org/2016/660.pdf
static TestVector const testVectorSkinny64_64 = {
    "Skinny-64-64",
    {0xf5, 0x26, 0x98, 0x26, 0xfc, 0x68, 0x12, 0x38},
    {0x06, 0x03, 0x4f, 0x95, 0x77, 0x24, 0xd1, 0x9d},
    {0xbb, 0x39, 0xdf, 0xb2, 0x42, 0x9b, 0x8a, 0xc7}
};
static TestVector const testVectorSkinny64_128 = {
    "Skinny-64-128",
    {0x9e, 0xb9, 0x36, 0x40, 0xd0, 0x88, 0xda, 0x63,
     0x76, 0xa3, 0x9d, 0x1c, 0x8b, 0xea, 0x71, 0xe1},
    {0xcf, 0x16, 0xcf, 0xe8, 0xfd, 0x0f, 0x98, 0xaa},
    {0x6c, 0xed, 0xa1, 0xf4, 0x3d, 0xe9, 0x2b, 0x9e}
};
static TestVector const testVectorSkinny64_192 = {
    "Skinny-64-192",
    {0xed, 0x00, 0xc8, 0x5b, 0x12, 0x0d, 0x68, 0x61,
     0x87, 0x53, 0xe2, 0x4b, 0xfd, 0x90, 0x8f, 0x60,
     0xb2, 0xdb, 0xb4, 0x1b, 0x42, 0x2d, 0xfc, 0xd0},
    {0x53, 0x0c, 0x61, 0xd3, 0x5e, 0x86, 0x63, 0xc3},
    {0xdd, 0x2c, 0xf1, 0xa8, 0xf3, 0x30, 0x30, 0x3c}
};

Skinny64_64 *skinny64_64;
Skinny64_128 *skinny64_128;
Skinny64_192 *skinny64_192;

byte buffer[8];

void testCipher(BlockCipher *cipher, const struct TestVector *test)
{
    Serial.print(test->name);
    Serial.print(" Encryption ... ");
    cipher->setKey(test->key, cipher->keySize());
    cipher->encryptBlock(buffer, test->plaintext);
    if (memcmp(buffer, test->ciphertext, 8) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");

    Serial.print(test->name);
    Serial.print(" Decryption ... ");
    cipher->decryptBlock(buffer, test->ciphertext);
    if (memcmp(buffer, test->plaintext, 8) == 0)
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
    Serial.print("Skinny64_64 ... ");
    Serial.println(sizeof(Skinny64_64));
    Serial.print("Skinny64_128 ... ");
    Serial.println(sizeof(Skinny64_128));
    Serial.print("Skinny64_192 ... ");
    Serial.println(sizeof(Skinny64_192));
    Serial.println();

    Serial.println("Skinny64 Test Vectors:");
    skinny64_64 = new Skinny64_64();
    testCipher(skinny64_64, &testVectorSkinny64_64);
    delete skinny64_64;
    skinny64_128 = new Skinny64_128();
    testCipher(skinny64_128, &testVectorSkinny64_128);
    delete skinny64_128;
    skinny64_192 = new Skinny64_192();
    testCipher(skinny64_192, &testVectorSkinny64_192);
    delete skinny64_192;

    Serial.println();

    Serial.println("Skinny64 Performance Tests:");
    skinny64_64 = new Skinny64_64();
    perfCipher(skinny64_64, &testVectorSkinny64_64);
    delete skinny64_64;
    skinny64_128 = new Skinny64_128();
    perfCipher(skinny64_128, &testVectorSkinny64_128);
    delete skinny64_128;
    skinny64_192 = new Skinny64_192();
    perfCipher(skinny64_192, &testVectorSkinny64_192);
    delete skinny64_192;
}

void loop()
{
}
