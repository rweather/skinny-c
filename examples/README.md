
There are two example programs in this directory:

    skinny-ctr
        Encrypts or decrypts a file using SKINNY in CTR mode.
        Key only, no tweak.

    skinny-tweak
        Same as skinny-ctr, but the cipher tweak is used for the counter.

    skinny-ecb
        Encrypts or decrypts a file using SKINNY in ECB mode.
        Key only, no tweak.

To get command-line usage information on the programs, run them without
any arguments:

    ./skinny-ctr
    ./skinny-tweak
    ./skinny-ecb

To encrypt a file with "skinny-ctr", supply the block size, key, and files
on the command-line:

    ./skinny-ctr -b64 -k 0123456789abcdef plaintext ciphertext

The data will be encrypted in CTR mode, starting with a default counter
of zero (the counter can be changed with the -c option).

Decryption in CTR mode is the same as encryption:

    ./skinny-ctr -b64 -k 0123456789abcdef ciphertext original

If the block size, key, or counter on the command-line are not the same as
the original encryption, then the file will decrypt to garbage.

The "skinny-tweak" program is similar, except that decryption must be
requested explicitly:

    ./skinny-tweak -b64 -k 0123456789abcdef plaintext ciphertext
    ./skinny-tweak -d -b64 -k 0123456789abcdef ciphertext original

The "skinny-tweak" program requires that its input be a multiple of the
block size.  If this isn't the case, then the output will be truncated.
This was easier than implementing a block padding scheme for this example.
A more complete example would of course need to handle block padding.
