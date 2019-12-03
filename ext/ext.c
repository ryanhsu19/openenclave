// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/ext/ext.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <string.h>

oe_result_t oe_ext_verify_signature(
    const oe_ext_signature_t* signature,
    const oe_ext_policy_t* policy)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_rsa_public_key_t pubkey;
    bool pubkey_initialized = false;

    if (!signature || !policy)
        OE_RAISE(OE_INVALID_PARAMETER);

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

    /* Verify that the signer signed the hash. */
    OE_CHECK(oe_rsa_public_key_verify(
        &pubkey,
        OE_HASH_TYPE_SHA256,
        signature->hash,
        sizeof(signature->hash),
        signature->signature,
        sizeof signature->signature));

    result = OE_OK;

done:

    if (pubkey_initialized)
        oe_rsa_public_key_free(&pubkey);

    return result;
}
