// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXT_POLICY_H
#define _OE_EXT_POLICY_H

#include <openenclave/bits/types.h>

#define OE_EXT_POLICY_DECLARATION __attribute__((section(".oeext")))
#define OE_EXT_POLICY_SIGNER_SIZE 32
#define OE_EXT_POLICY_PUBKEY_SIZE 1024

/* An policy injected by 'oeext sign' tool. */
typedef struct _oe_ext_policy
{
    /* The public key of the signer in PEM format. */
    uint8_t pubkey_data[OE_EXT_POLICY_PUBKEY_SIZE];
    uint64_t pubkey_size;

    /* The signer's ID (the SHA-256 public signing key) */
    uint8_t signer[OE_EXT_POLICY_SIGNER_SIZE];
} oe_ext_policy_t;

#endif /* _OE_EXT_POLICY_H */
