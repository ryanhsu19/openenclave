// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_APPID_H
#define _OE_APPID_H

#define OE_APPID_DECLARATION __attribute__((section(".oeappid")))
#define OE_APPID_SIGNER_SIZE 32
#define OE_MAX_PUBKEY_SIZE 1024

#include <openenclave/bits/types.h>

/* An appid injected by oesignext tool. */
typedef struct _oe_appid
{
    /* The public key of the signer in PEM format. */
    uint8_t pubkey_data[OE_MAX_PUBKEY_SIZE];
    uint64_t pubkey_size;

    /* The signer's ID: SHA-256(public signing key) */
    uint8_t signer[OE_APPID_SIGNER_SIZE];

    /* The integer product identifier. */
    uint16_t isvprodid;

    /* The integer security version number. */
    uint16_t isvsvn;
} oe_appid_t;

#endif /* _OE_APPID_H */
