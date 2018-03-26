// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/trace.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "../util.h"
#include "init.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

#define OE_CERT_MAGIC 0x882b9943ac1ca95d

#define BEGIN_CERTIFICATE "-----BEGIN CERTIFICATE-----"
#define BEGIN_CERTIFICATE_LEN (sizeof(BEGIN_CERTIFICATE) - 1)

#define END_CERTIFICATE "-----END CERTIFICATE-----"
#define END_CERTIFICATE_LEN (sizeof(END_CERTIFICATE) - 1)

typedef struct _OE_CertImpl
{
    uint64_t magic;
    X509* x509;
} OE_CertImpl;

static void _InitCertImpl(OE_CertImpl* impl, X509* x509)
{
    if (impl)
    {
        impl->magic = OE_CERT_MAGIC;
        impl->x509 = x509;
    }
}

static bool _ValidCertImpl(const OE_CertImpl* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->x509;
}

static void _ClearCertImpl(OE_CertImpl* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->x509 = NULL;
    }
}

#define OE_CERT_CHAIN_MAGIC 0xe863a8d48452376a

typedef struct _OE_CertChainImpl
{
    uint64_t magic;
    STACK_OF(X509) * sk;
} OE_CertChainImpl;

static void _InitCertChainImpl(OE_CertChainImpl* impl, STACK_OF(X509) * sk)
{
    if (impl)
    {
        impl->magic = OE_CERT_CHAIN_MAGIC;
        impl->sk = sk;
    }
}

static bool _ValidCertChainImpl(const OE_CertChainImpl* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->sk;
}

static void _ClearCertChainImpl(OE_CertChainImpl* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->sk = NULL;
    }
}

static STACK_OF(X509) * _ReadCertChain(const char* pem)
{
    STACK_OF(X509)* result = NULL;
    STACK_OF(X509)* sk = NULL;
    BIO* bio = NULL;
    X509* x509 = NULL;

    // Check parameters:
    if (!pem)
        goto done;

    // Create empty X509 stack:
    if (!(sk = sk_X509_new_null()))
        goto done;

    while (*pem)
    {
        const char* end;

        /* The PEM certificate must start with this */
        if (strncmp(pem, BEGIN_CERTIFICATE, BEGIN_CERTIFICATE_LEN) != 0)
            goto done;

        /* Find the end of this PEM certificate */
        {
            if (!(end = strstr(pem, END_CERTIFICATE)))
                goto done;

            end += END_CERTIFICATE_LEN;
        }

        /* Skip trailing spaces */
        while (isspace(*end))
            end++;

        /* Create a BIO for this certificate */
        if (!(bio = BIO_new_mem_buf(pem, end - pem)))
            goto done;

        /* Read BIO into X509 object */
        if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
            goto done;

        // Push certificate onto stack:
        {
            if (!sk_X509_push(sk, x509))
                goto done;

            x509 = NULL;
        }

        // Release the bio:
        BIO_free(bio);
        bio = NULL;

        pem = end;
    }

    result = sk;
    sk = NULL;

done:

    if (bio)
        BIO_free(bio);

    if (sk)
        sk_X509_pop_free(sk, X509_free);

    return result;
}

/* Clone the certificate to clear any verification state */
static X509* _CloneX509(X509* x509)
{
    X509* ret = NULL;
    BIO* out = NULL;
    BIO* in = NULL;
    BUF_MEM* mem;

    if (!x509)
        goto done;

    if (!(out = BIO_new(BIO_s_mem())))
        goto done;

    if (!PEM_write_bio_X509(out, x509))
        goto done;

    if (!BIO_get_mem_ptr(out, &mem))
        goto done;

    if (!(in = BIO_new_mem_buf(mem->data, mem->length)))
        goto done;

    ret = PEM_read_bio_X509(in, NULL, 0, NULL);

done:

    if (out)
        BIO_free(out);

    if (in)
        BIO_free(in);

    return ret;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

OE_Result OE_CertReadPEM(const void* pemData, size_t pemSize, OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertImpl* impl = (OE_CertImpl*)cert;
    BIO* bio = NULL;
    X509* x509 = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pemData || !pemSize || !cert)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_THROW(OE_FAILURE);

    /* Convert the PEM BIO into a certificate object */
    if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
        OE_THROW(OE_FAILURE);

    _InitCertImpl(impl, x509);
    x509 = NULL;

    OE_THROW(OE_OK);

OE_CATCH:

    if (bio)
        BIO_free(bio);

    if (x509)
        X509_free(x509);

    return result;
}

OE_Result OE_CertFree(OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertImpl* impl = (OE_CertImpl*)cert;

    /* Check parameters */
    if (!_ValidCertImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Free the certificate */
    X509_free(impl->x509);
    _ClearCertImpl(impl);

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

OE_Result OE_CertChainReadPEM(
    const void* pemData,
    size_t pemSize,
    OE_CertChain* chain)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertChainImpl* impl = (OE_CertChainImpl*)chain;
    STACK_OF(X509)* sk = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pemData || !pemSize || !chain)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    OE_InitializeOpenSSL();

    /* Read the cerfificate chain into memory */
    if (!(sk = _ReadCertChain((const char*)pemData)))
        OE_THROW(OE_FAILURE);

    _InitCertChainImpl(impl, sk);

    OE_THROW(OE_OK);

OE_CATCH:

    return result;
}

OE_Result OE_CertChainFree(OE_CertChain* __chain)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertChainImpl* impl = (OE_CertChainImpl*)__chain;

    /* Check the parameter */
    if (_ValidCertChainImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Release the stack of certificates */
    sk_X509_pop_free(impl->sk, X509_free);

    /* Clear the implementation */
    _ClearCertChainImpl(impl);

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

OE_Result OE_CertVerify(
    OE_Cert* __cert,
    OE_CertChain* __chain,
    OE_CRL* crl, /* ATTN: placeholder for future feature work */
    OE_VerifyCertError* error)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertImpl* certImpl = (OE_CertImpl*)__cert;
    OE_CertChainImpl* chainImpl = (OE_CertChainImpl*)__chain;
    X509_STORE_CTX* ctx = NULL;
    X509* x509 = NULL;

    /* Initialize error to NULL for now */
    if (error)
        *error->buf = '\0';

    /* Reject null parameters */
    if (!_ValidCertImpl(certImpl) || !_ValidCertChainImpl(chainImpl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* We must make a copy of the certificate, else previous successful
     * verifications cause subsequent bad verifications to succeed. It is
     * likely that some state is stored in the certificate upon successful
     * verification. We can clear this by making a copy.
     */
    if (!(x509 = _CloneX509(certImpl->x509)))
        OE_THROW(OE_FAILURE);

    /* Initialize OpenSSL (if not already initialized) */
    OE_InitializeOpenSSL();

    /* Create a context for verification */
    if (!(ctx = X509_STORE_CTX_new()))
        OE_THROW(OE_FAILURE);

    /* Initialize the context that will be used to verify the certificate */
    if (!X509_STORE_CTX_init(ctx, NULL, NULL, NULL))
        OE_THROW(OE_FAILURE);

    /* Set the certificate into the verification context */
    X509_STORE_CTX_set_cert(ctx, x509);

    /* Set the CA chain into the verification context */
    X509_STORE_CTX_trusted_stack(ctx, chainImpl->sk);

    /* Finally verify the certificate */
    if (!X509_verify_cert(ctx))
    {
        if (error)
        {
            *error->buf = '\0';
            strncat(
                error->buf,
                X509_verify_cert_error_string(ctx->error),
                sizeof(error->buf) - 1);
        }

        OE_THROW(OE_VERIFY_FAILED);
    }

    OE_THROW(OE_OK);

OE_CATCH:

    if (ctx)
        X509_STORE_CTX_free(ctx);

    if (x509)
        X509_free(x509);

    return result;
}
