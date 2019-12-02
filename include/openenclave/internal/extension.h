// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXTENSION_H
#define _OE_EXTENSION_H

#define OE_EXTENSION_DECLARATION __attribute__((section(".oeextension")))
#define OE_EXTENSION_SIGNER_SIZE 32
#define OE_MAX_PUBKEY_SIZE 1024

#include <openenclave/bits/types.h>

/* An extension injected by oesignext tool. */
typedef struct _oe_extension
{
    /* The public key of the signer in PEM format. */
    uint8_t pubkey_data[OE_MAX_PUBKEY_SIZE];
    uint64_t pubkey_size;

    /* The signer's ID: SHA-256(public signing key) */
    uint8_t signer[OE_EXTENSION_SIGNER_SIZE];

    /* The integer product identifier. */
    uint16_t isvprodid;

    /* The integer security version number. */
    uint16_t isvsvn;
} oe_extension_t;

#endif /* _OE_EXTENSION_H */
