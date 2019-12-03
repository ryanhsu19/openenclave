// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXT_SIGNATURE_H
#define _OE_EXT_SIGNATURE_H

#include <openenclave/bits/types.h>

#define OE_EXT_SIGNATURE_MAGIC 0x06ee1812
#define OE_EXT_SIGNATURE_SIZE 384
#define OE_EXT_SIGNATURE_HASH_SIZE 32
#define OE_EXT_SIGNATURE_SIGNER_SIZE 32

/* An signature injected by oesignext tool. */
typedef struct _oe_ext_signature
{
    /* The signer's ID (the SHA-256 of the public signing key). */
    uint8_t signer[OE_EXT_SIGNATURE_HASH_SIZE];

    /* The hash of the extension. */
    uint8_t hash[OE_EXT_SIGNATURE_HASH_SIZE];

    /* The signature of SHA-256(hash | isvprodid | isvsvn). */
    uint8_t signature[OE_EXT_SIGNATURE_SIZE];
} oe_ext_signature_t;

#endif /* _OE_EXT_SIGNATURE_H */
