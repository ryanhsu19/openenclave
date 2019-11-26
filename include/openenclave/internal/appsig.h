// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_APPSIG_H
#define _OE_APPSIG_H

#define OE_APPSIG_KEY_SIZE 384
#define OE_APPSIG_EXPONENT_SIZE 4
#define OE_APPSIG_HASH_SIZE 32
#define OE_APPSIG_MAGIC 0x06ee1812

/* An appsig injected by oesignext tool. */
typedef struct _oe_appsig
{
    /* Magic number (must be OE_APPSIG_MAGIC) */
    uint32_t magic;

    /* The application signer's ID: SHA-256(public signing key). */
    uint8_t signer[OE_APPSIG_HASH_SIZE];

    /* The hash of the application. */
    uint8_t hash[OE_APPSIG_HASH_SIZE];

    /* The integer product identifier. */
    uint16_t isvprodid;

    /* The integer security version number. */
    uint16_t isvsvn;

    /* The signature of SHA-256(hash | isvprodid | isvsvn). */
    uint8_t signature[OE_APPSIG_KEY_SIZE];
} oe_appsig_t;

#endif /* _OE_APPSIG_H */
