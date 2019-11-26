// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/appid.h>
#include <openenclave/internal/appsig.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "oeapp_t.h"

/* The 'oeapp appid' subcommand fills this in. */
OE_APPID_DECLARATION oe_appid_t appid;

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

void dump_appid(oe_appid_t* appid)
{
    printf("appid =\n");
    printf("{\n");

    printf("    pubkey=");
    dump_string(appid->pubkey_data, appid->pubkey_size);
    printf("\n");

    printf("    pubkey_size=%llu\n", appid->pubkey_size);

    printf("    signer=");
    hex_dump(appid->signer, sizeof(appid->signer));
    printf("\n");

    printf("    isvprodid=%u\n", appid->isvprodid);

    printf("    isvsvn=%u\n", appid->isvsvn);

    printf("}\n");
}

void dump_appid_ecall(void)
{
    dump_appid(&appid);
}

void dump_appsig(const oe_appsig_t* appsig)
{
    printf("appsig =\n");
    printf("{\n");

    printf("    signer=");
    hex_dump(appsig->signer, sizeof(appsig->signer));
    printf("\n");

    printf("    hash=");
    hex_dump(appsig->hash, sizeof(appsig->hash));
    printf("\n");

    printf("    isvprodid=%u\n", appsig->isvprodid);

    printf("    isvsvn=%u\n", appsig->isvsvn);

    printf("    signature=");
    hex_dump(appsig->signature, sizeof(appsig->signature));
    printf("\n");

    printf("}\n");
}

void verify_ecall(struct _oe_appsig* appsig)
{
    /* Dump the structure. */
    dump_appsig(appsig);

    OE_TEST(appsig->isvprodid == appid.isvprodid);
    OE_TEST(appsig->isvsvn == appid.isvsvn);
    OE_TEST(memcmp(appsig->signer, appid.signer, sizeof appsig->signer) == 0);

    oe_rsa_public_key_t pubkey;

    OE_TEST(
        oe_rsa_public_key_read_pem(
            &pubkey, appid.pubkey_data, appid.pubkey_size) == OE_OK);

    /* Recompute the composite hash. */
    oe_sha256_context_t ctx;
    OE_SHA256 sha256;
    oe_sha256_init(&ctx);
    oe_sha256_update(&ctx, appsig->hash, sizeof appsig->hash);
    oe_sha256_update(&ctx, &appid.isvprodid, sizeof appid.isvprodid);
    oe_sha256_update(&ctx, &appid.isvsvn, sizeof appid.isvsvn);
    oe_sha256_final(&ctx, &sha256);

    OE_TEST(
        oe_rsa_public_key_verify(
            &pubkey,
            OE_HASH_TYPE_SHA256,
            sha256.buf,
            sizeof sha256,
            appsig->signature,
            sizeof appsig->signature) == OE_OK);

    OE_TEST(oe_rsa_public_key_free(&pubkey) == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
