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
This example runs tests on the Mantis8 implementation to
verify correct behaviour.
*/

#include <Skinny.h>
#include <string.h>

struct TestVector
{
    const char *name;
    byte plaintext[8];
    byte ciphertext[8];
    byte key[16];
    byte tweak[8];
};

// Define the test vectors from https://eprint.iacr.org/2016/660.pdf
static TestVector const testVectorMantis8 = {
    "Mantis-8",
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x97, 0x1e, 0xa0, 0x1a, 0x86, 0xb4, 0x10, 0xbb},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2}
};

Mantis8 mantis8;

byte buffer[8];

void testCipher(Mantis8 *cipher, const struct TestVector *test)
{
    Serial.print(test->name);
    Serial.print(" Encryption ... ");
    cipher->setKey(test->key, cipher->keySize());
    cipher->setTweak(test->tweak, 8);
    cipher->encryptBlock(buffer, test->plaintext);
    if (memcmp(buffer, test->ciphertext, 8) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");

    Serial.print(test->name);
    Serial.print(" Decryption ... ");
    cipher->swapModes();
    cipher->decryptBlock(buffer, test->ciphertext);
    if (memcmp(buffer, test->plaintext, 8) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void perfCipher(Mantis8 *cipher, const struct TestVector *test)
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
    Serial.print(" Set Tweak ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->setTweak(test->tweak, 8);
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
        // decryptBlock() is a wrapper that calls encryptBlock().
        cipher->encryptBlock(buffer, buffer);
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
    Serial.print("Mantis8 ... ");
    Serial.println(sizeof(Mantis8));
    Serial.println();

    Serial.println("Mantis8 Test Vectors:");
    testCipher(&mantis8, &testVectorMantis8);

    Serial.println();

    Serial.println("Mantis8 Performance Tests:");
    perfCipher(&mantis8, &testVectorMantis8);
}

void loop()
{
}
