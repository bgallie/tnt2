# NAME

tnt2 - an infinite key encryption system

# SYNOPSIS

**tnt2** \[*OPTION*\]  
**tnt2** *PATTERN*

# DESCRIPTION

**tnt2** is an encryption/description system that uses an infinite (with
respect to the plaintext) key to encode the data. The psuedo-random
generator used by **tnt2** can encode approximately 1.64×10³⁵ bytes
before the key will repeat itself.

# OPTIONS

**-a** encrypted data is outputed using ascii85 encoding

**-c** the plaintext is compressed before encrypting

**-d** decrypt the input file

**-e** encrypt the input file

**-if string** the input file name

**-n string** the starting block count (default “0”)

**-of string** the output file name

**-p** encrypted data is outputted using PEM encoding

**-pf string** the file name containing the proforma machine to use
instead of the builtin proforma machine

# COPYRIGHT

This is free and unencumbered software released into the public domain.
See the UNLICENSE file for details.

