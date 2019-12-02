// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/ext/policy.h>
#include <openenclave/ext/signature.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "oeext_t.h"

/* The 'oeext policy' subcommand fills this in. */
OE_EXT_POLICY_DECLARATION oe_ext_policy_t policy;

void hex_dump(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
}

void dump_string(const uint8_t* s, size_t n)
{
    printf("\"");

    for (size_t i = 0; i < n; i++)
    {
        int c = s[i];

        if (c >= ' ' && c <= '~')
            printf("%c", s[i]);
        else
            printf("\\%03o", s[i]);
    }

    printf("\"");
}

void dump_policy(oe_ext_policy_t* policy)
{
    printf("policy =\n");
    printf("{\n");

    printf("    pubkey=");
    dump_string(policy->pubkey_data, policy->pubkey_size);
    printf("\n");

    printf("    pubkey_size=%llu\n", policy->pubkey_size);

    printf("    signer=");
    hex_dump(policy->signer, sizeof(policy->signer));
    printf("\n");

    printf("}\n");
}

void dump_policy_ecall(void)
{
    dump_policy(&policy);
}

void dump_signature(const oe_ext_signature_t* signature)
{
    printf("signature =\n");
    printf("{\n");

    printf("    signer=");
    hex_dump(signature->signer, sizeof(signature->signer));
    printf("\n");

    printf("    hash=");
    hex_dump(signature->hash, sizeof(signature->hash));
    printf("\n");

    printf("    signature=");
    hex_dump(signature->signature, sizeof(signature->signature));
    printf("\n");

    printf("}\n");
}

void verify_ecall(struct _oe_ext_signature* signature)
{
    /* Dump the structure. */
    dump_signature(signature);

    OE_TEST(
        memcmp(signature->signer, policy.signer, sizeof signature->signer) ==
        0);

    oe_rsa_public_key_t pubkey;

    OE_TEST(
        oe_rsa_public_key_read_pem(
            &pubkey, policy.pubkey_data, policy.pubkey_size) == OE_OK);

    OE_TEST(
        oe_rsa_public_key_verify(
            &pubkey,
            OE_HASH_TYPE_SHA256,
            signature->hash,
            sizeof(signature->hash),
            signature->signature,
            sizeof signature->signature) == OE_OK);

    OE_TEST(oe_rsa_public_key_free(&pubkey) == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
