// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/extension.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/signature.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "oeext_t.h"

/* The 'oeext extension' subcommand fills this in. */
OE_EXTENSION_DECLARATION oe_extension_t extension;

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

void dump_extension(oe_extension_t* extension)
{
    printf("extension =\n");
    printf("{\n");

    printf("    pubkey=");
    dump_string(extension->pubkey_data, extension->pubkey_size);
    printf("\n");

    printf("    pubkey_size=%llu\n", extension->pubkey_size);

    printf("    signer=");
    hex_dump(extension->signer, sizeof(extension->signer));
    printf("\n");

    printf("    isvprodid=%u\n", extension->isvprodid);

    printf("    isvsvn=%u\n", extension->isvsvn);

    printf("}\n");
}

void dump_extension_ecall(void)
{
    dump_extension(&extension);
}

void dump_signature(const oe_signature_t* signature)
{
    printf("signature =\n");
    printf("{\n");

    printf("    signer=");
    hex_dump(signature->signer, sizeof(signature->signer));
    printf("\n");

    printf("    hash=");
    hex_dump(signature->hash, sizeof(signature->hash));
    printf("\n");

    printf("    isvprodid=%u\n", signature->isvprodid);

    printf("    isvsvn=%u\n", signature->isvsvn);

    printf("    signature=");
    hex_dump(signature->signature, sizeof(signature->signature));
    printf("\n");

    printf("}\n");
}

void verify_ecall(struct _oe_signature* signature)
{
    /* Dump the structure. */
    dump_signature(signature);

    printf("STUFF=%u:%u\n", signature->isvprodid, extension.isvprodid);
    OE_TEST(signature->isvprodid == extension.isvprodid);
    OE_TEST(signature->isvsvn == extension.isvsvn);
    OE_TEST(
        memcmp(signature->signer, extension.signer, sizeof signature->signer) ==
        0);

    oe_rsa_public_key_t pubkey;

    OE_TEST(
        oe_rsa_public_key_read_pem(
            &pubkey, extension.pubkey_data, extension.pubkey_size) == OE_OK);

    /* Recompute the composite hash. */
    oe_sha256_context_t ctx;
    OE_SHA256 sha256;
    oe_sha256_init(&ctx);
    oe_sha256_update(&ctx, signature->hash, sizeof signature->hash);
    oe_sha256_update(&ctx, &extension.isvprodid, sizeof extension.isvprodid);
    oe_sha256_update(&ctx, &extension.isvsvn, sizeof extension.isvsvn);
    oe_sha256_final(&ctx, &sha256);

    OE_TEST(
        oe_rsa_public_key_verify(
            &pubkey,
            OE_HASH_TYPE_SHA256,
            sha256.buf,
            sizeof sha256,
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
