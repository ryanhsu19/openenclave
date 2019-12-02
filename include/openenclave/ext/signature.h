// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXT_SIGNATURE_H
#define _OE_EXT_SIGNATURE_H

#include <openenclave/bits/types.h>

#define OE_SIGNATURE_KEY_SIZE 384
#define OE_SIGNATURE_EXPONENT_SIZE 4
#define OE_SIGNATURE_HASH_SIZE 32
#define OE_SIGNATURE_MAGIC 0x06ee1812

/* An signature injected by oesignext tool. */
typedef struct _oe_signature
{
    /* Magic number (must be OE_SIGNATURE_MAGIC) */
    uint32_t magic;

    /* The signer's ID (the SHA-256 of the public signing key). */
    uint8_t signer[OE_SIGNATURE_HASH_SIZE];

    /* The hash of the extension. */
    uint8_t hash[OE_SIGNATURE_HASH_SIZE];

    /* The integer product identifier. */
    uint16_t isvprodid;

    /* The integer security version number. */
    uint16_t isvsvn;

    /* The signature of SHA-256(hash | isvprodid | isvsvn). */
    uint8_t signature[OE_SIGNATURE_KEY_SIZE];
} oe_signature_t;

#endif /* _OE_EXT_SIGNATURE_H */
