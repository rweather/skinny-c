
Skinny-C
========

The SKINNY family of tweakable block ciphers is intended for lightweight
implementation in hardware and software, [paper](https://eprint.iacr.org/2016/660.pdf).

The author's [web site](https://sites.google.com/site/skinnycipher/) provides a
[reference implementation](https://sites.google.com/site/skinnycipher/downloads/skinny_reference.c)
in C, but it isn't terribly efficient - it is intended to be *correct*,
not *fast* and that's OK.  Correct and simple is easier to analyze from a
security standpoint.

This repository provides alternative reference implementations in C
that are designed for 32-bit and 64-bit platforms.  The main focus is
on efficiency while sticking to standard C99.  Assembly language and
SIMD speed-ups are definitely possible, such as
[this](https://github.com/kste/skinny_avx) AVX2 implementation.

This implementation is designed to have constant-time and constant-cache
behaviour.  There are no lookup tables, particularly for the S-boxes.

To build the code with gcc, simply type "make".  Then type "make check"
to run the test cases.

For more information on this code, to report bugs, or to suggest
improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).
