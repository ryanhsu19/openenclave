// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXTENSION_H
#define _OE_EXTENSION_H

#define OE_EXTENSION_MODULUS_SIZE 384
#define OE_EXTENSION_EXPONENT_SIZE 4

/* An extension injected by oesignext tool. */
typedef struct _oe_extension
{
    /* Modulus of the public RSA signing key (the exponent must be 3). */
    uint8_t modulus[OE_EXTENSION_MODULUS_SIZE];

    /* Exponent of the public RSA signing key. */
    uint8_t exponent[OE_EXTENSION_EXPONENT_SIZE];

    /* The integer product identifier. */
    uint16_t isvprodid;

    /* The integer security version number. */
    uint16_t isvsvn;
} oe_extension_t;

#endif /* _OE_EXTENSION_H */
