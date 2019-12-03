// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXT_POLICY_H
#define _OE_EXT_POLICY_H

#include <openenclave/bits/types.h>

#define OE_EXT_POLICY_DECLARATION __attribute__((section(".oeext")))
#define OE_EXT_POLICY_SIGNER_SIZE 32
#define OE_EXT_POLICY_PUBKEY_SIZE 1024
#define OE_EXT_POLICY_MODULUS_SIZE 384
#define OE_EXT_POLICY_EXPONENT_SIZE 4

/* A policy injected by 'oeext extend' tool. */
typedef struct _oe_ext_policy
{
    /* The modulus of the signer's public key. */
    uint8_t modulus[OE_EXT_POLICY_MODULUS_SIZE];

    /* The exponent of the signer's public key. */
    uint8_t exponent[OE_EXT_POLICY_EXPONENT_SIZE];

    /* The signer's ID (the SHA-256 public signing key) */
    uint8_t signer[OE_EXT_POLICY_SIGNER_SIZE];
} oe_ext_policy_t;

#endif /* _OE_EXT_POLICY_H */
