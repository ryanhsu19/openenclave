// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/ext/ext.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <stdio.h>
#include <string.h>

oe_result_t oe_ext_verify_signature(
    const oe_ext_signature_t* signature,
    const oe_ext_policy_t* policy,
    const uint8_t* hash,
    size_t hash_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_rsa_public_key_t pubkey;
    bool pubkey_initialized = false;

    /* Check the parameters. */
    if (!signature || !policy || !hash)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (hash_size != OE_EXT_SIGNATURE_HASH_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (memcmp(signature->hash, hash, OE_EXT_SIGNATURE_HASH_SIZE) != 0)
        OE_RAISE(OE_FAILURE);

    /* Check that the signers are the same. */
    if (memcmp(signature->signer, policy->signer, sizeof policy->signer) != 0)
        OE_RAISE(OE_FAILURE);

    /* Initialize the RSA key from the policy. */
    OE_CHECK(oe_rsa_public_key_init_from_binary(
        &pubkey,
        policy->modulus,
        sizeof(policy->modulus),
        policy->exponent,
        sizeof(policy->exponent)));
    pubkey_initialized = true;

    /* Verify the hash is the right size. */
    if (hash_size != sizeof(signature->hash))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify that the signer signed the hash. */
    OE_CHECK(oe_rsa_public_key_verify(
        &pubkey,
        OE_HASH_TYPE_SHA256,
        hash,
        hash_size,
        signature->signature,
        sizeof signature->signature));

    result = OE_OK;

done:

    if (pubkey_initialized)
        oe_rsa_public_key_free(&pubkey);

    return result;
}
