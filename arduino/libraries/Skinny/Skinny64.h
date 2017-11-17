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

#ifndef CRYPTO_SKINNY64_h
#define CRYPTO_SKINNY64_h

#include "BlockCipher.h"

class Skinny64 : public BlockCipher
{
public:
    virtual ~Skinny64();

    size_t blockSize() const;

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

protected:
    Skinny64(uint32_t *schedule, uint8_t rounds);

    void setTK1(const uint8_t *key, bool tweaked = false);
    void xorTK1(const uint8_t *key);
    void setTK2(const uint8_t *key);
    void setTK3(const uint8_t *key);

private:
    uint32_t *s;
    uint8_t r;
};

class Skinny64_Tweaked : public Skinny64
{
public:
    virtual ~Skinny64_Tweaked();

    bool setTweak(const uint8_t *tweak, size_t len);

    void clear();

protected:
    Skinny64_Tweaked(uint32_t *schedule, uint8_t rounds);

    void resetTweak();

private:
    uint8_t t[8];
};

class Skinny64_64 : public Skinny64
{
public:
    Skinny64_64();
    virtual ~Skinny64_64();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint32_t sched[32];
};

class Skinny64_128 : public Skinny64
{
public:
    Skinny64_128();
    virtual ~Skinny64_128();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint32_t sched[36];
};

class Skinny64_128_Tweaked : public Skinny64_Tweaked
{
public:
    Skinny64_128_Tweaked();
    virtual ~Skinny64_128_Tweaked();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint32_t sched[36];
};

class Skinny64_192 : public Skinny64
{
public:
    Skinny64_192();
    virtual ~Skinny64_192();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint32_t sched[40];
};

class Skinny64_192_Tweaked : public Skinny64_Tweaked
{
public:
    Skinny64_192_Tweaked();
    virtual ~Skinny64_192_Tweaked();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint32_t sched[40];
};

#endif
