// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <ctype.h>
#include <limits.h>
#include <openenclave/bits/defs.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../../host/crypto/rsa.h"
#include "extension.h"

#define HASH_SIZE 32

#define SIGNATURE_SIZE OE_EXTENSION_MODULUS_SIZE

static const char* arg0;

OE_PRINTF_FORMAT(1, 2)
static void err(const char* format, ...)
{
    fprintf(stderr, "\n");

    fprintf(stderr, "%s: error: ", arg0);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n\n");

    exit(1);
}

static bool valid_symbol_name(const char* name)
{
    bool ret = false;
    const char* p = name;

    if (*p != '_' && !isalpha(*p))
        goto done;

    p++;

    while (*p == '_' || isalnum(*p))
        p++;

    if (*p != '\0')
        goto done;

    ret = true;

done:
    return ret;
}

static bool valid_ascii_hash(const char* value)
{
    bool ret = false;
    const char* p = value;

    while (isxdigit(*p))
        p++;

    if (*p != '\0')
        goto done;

    if (p - value != 64)
        goto done;

    ret = true;

done:
    return ret;
}

void dump_symbol(const uint8_t* symbol)
{
    for (size_t i = 0; i < HASH_SIZE; i++)
        printf("%02x", symbol[i]);

    printf("\n");
}

static uint64_t find_file_offset(elf64_t* elf, uint64_t vaddr)
{
    elf64_ehdr_t* eh = (elf64_ehdr_t*)elf->data;
    elf64_phdr_t* ph = (elf64_phdr_t*)((uint8_t*)elf->data + eh->e_phoff);
    size_t i;

    /* Search for the segment that contains this virtual address. */
    for (i = 0; i < eh->e_phnum; i++)
    {
        if (vaddr >= ph->p_vaddr && vaddr < ph->p_vaddr + ph->p_memsz)
        {
            size_t vaddr_offset = vaddr - ph->p_vaddr;

            /* Calculate the offset within the file. */
            size_t file_offset = ph->p_offset + vaddr_offset;

            if (file_offset >= elf->size)
                return (uint64_t)-1;

            return file_offset;
        }

        ph++;
    }

    return (uint64_t)-1;
}

int ascii_to_hash(const char* ascii_hash, uint8_t hash[HASH_SIZE])
{
    const char* p = ascii_hash;

    memset(hash, 0, HASH_SIZE);

    if (!valid_ascii_hash(ascii_hash))
        return -1;

    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        unsigned int byte;
        sscanf(p, "%02x", &byte);
        hash[i] = (uint8_t)byte;
        p += 2;
    }

    return 0;
}

int write_file(const char* path, const void* data, size_t size)
{
    FILE* os;

    if (!(os = fopen(path, "wb")))
        return -1;

    if (fwrite(data, 1, size, os) != size)
        return -1;

    fclose(os);

    return 0;
}

static int _load_pem_file(const char* path, void** data, size_t* size)
{
    int rc = -1;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        goto done;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        *size = (size_t)st.st_size;
    }

    /* Allocate memory. We add 1 to null terimate the file since the crypto
     * libraries require null terminated PEM data. */
    if (*size == SIZE_MAX)
        goto done;

    if (!(*data = (uint8_t*)malloc(*size + 1)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        goto done;

    /* Zero terminate the PEM data. */
    {
        uint8_t* data_tmp = (uint8_t*)*data;
        data_tmp[*size] = 0;
        *size += 1;
    }

    rc = 0;

done:

    if (rc != 0)
    {
        if (data && *data)
        {
            free(*data);
            *data = NULL;
        }

        if (size)
            *size = 0;
    }

    if (is)
        fclose(is);

    return rc;
}

static void _mem_reverse(void* dest_, const void* src_, size_t n)
{
    unsigned char* dest = (unsigned char*)dest_;
    const unsigned char* src = (const unsigned char*)src_;
    const unsigned char* end = src + n;

    while (n--)
        *dest++ = *--end;
}

static oe_result_t _get_modulus(
    const oe_rsa_public_key_t* rsa,
    uint8_t modulus[SIGNATURE_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[SIGNATURE_SIZE];
    size_t bufsize = sizeof(buf);

    if (!rsa || !modulus)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_get_modulus(rsa, buf, &bufsize));

    /* RSA key length is the modulus length, so these have to be equal. */
    if (bufsize != SIGNATURE_SIZE)
        OE_RAISE(OE_FAILURE);

    _mem_reverse(modulus, buf, bufsize);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_exponent(
    const oe_rsa_public_key_t* rsa,
    uint8_t exponent[OE_EXTENSION_EXPONENT_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_EXTENSION_EXPONENT_SIZE];
    size_t bufsize = sizeof(buf);

    if (!rsa || !exponent)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_get_exponent(rsa, buf, &bufsize));

    /* Exponent is in big endian. So, we need to reverse. */
    _mem_reverse(exponent, buf, bufsize);

    /* We zero out the rest to get the right exponent in little endian. */
    memset(exponent + bufsize, 0, OE_EXTENSION_EXPONENT_SIZE - bufsize);

    result = OE_OK;

done:
    return result;
}

static const char _usage[] =
    "\n"
    "Usage: %s ENCLAVE SYMBOL HASH ISVPRODID ISVSVN KEYFILE\n"
    "\n"
    "\n";

typedef struct _options
{
    const char* enclave;
    const char* symbol;
    uint8_t hash[HASH_SIZE];
    uint16_t isvprodid;
    uint16_t isvsvn;
    const char* keyfile;
} options_t;

int main(int argc, const char* argv[])
{
    options_t opts;
    elf64_t elf;
    bool loaded = false;
    elf64_sym_t sym;
    uint8_t* symbol_address;
    size_t file_offset;
    void* pem_data = NULL;
    size_t pem_size = 0;
    oe_rsa_private_key_t rsa_private;
    bool rsa_private_initialized = false;
    oe_rsa_public_key_t rsa_public;
    bool rsa_public_initialized = false;

    arg0 = argv[0];

    int ret = 1;

    /* Check and collect arguments. */
    {
        if (argc != 7)
        {
            fprintf(stderr, _usage, argv[0]);
            goto done;
        }

        /* Get the ENCLAVE argument */
        opts.enclave = argv[1];

        /* Get the SYMBOL argument. */
        {
            /* Check that the symbol name is valid. */
            if (!valid_symbol_name(argv[2]))
            {
                err("bad symbol name: %s", argv[2]);
                goto done;
            }

            opts.symbol = argv[2];
        }

        /* Get the HASH argument. */
        if (ascii_to_hash(argv[3], opts.hash) != 0)
            err("bad HASH argument: %s", argv[3]);

        /* Get the ISVPRODID argument. */
        {
            char* end;
            unsigned long x;

            x = strtoul(argv[4], &end, 10);

            if (!end || *end || x > SHRT_MAX)
                err("bad ISVPRODID argument: %s", argv[4]);

            opts.isvprodid = (uint16_t)x;
        }

        /* Get the ISVSVN argument. */
        {
            char* end;
            unsigned long x;

            x = strtoul(argv[5], &end, 10);

            if (!end || *end || x > SHRT_MAX)
                err("bad ISVSVN argument: %s", argv[4]);

            opts.isvsvn = (uint16_t)x;
        }

        /* Handle the KEYFILE argument. */
        {
            opts.keyfile = argv[6];
        }
    }

    /* Disable logging. */
    setenv("OE_LOG_LEVEL", "NONE", 1);

    /* Load the ELF-64 object */
    {
        if (elf64_load(opts.enclave, &elf) != 0)
            err("cannot load %s", opts.enclave);

        loaded = true;
    }

    /* Find the symbol within the ELF image. */
    if (elf64_find_symbol_by_name(&elf, opts.symbol, &sym) != 0)
        err("cannot find symbol: %s", opts.symbol);

    /* Check the size of the symbol. */
    if (sym.st_size != sizeof(oe_extension_t))
        err("symbol %s is wrong size", opts.symbol);

    /* Find the offset within the ELF file of this symbol. */
    if ((file_offset = find_file_offset(&elf, sym.st_value)) == (uint64_t)-1)
        err("cannot locate symbol %s in %s", opts.symbol, opts.enclave);

    /* Make sure the entire symbol falls within the file image. */
    if (file_offset + sizeof(oe_extension_t) >= elf.size)
        err("unexpected");

    /* Get the address of the symbol. */
    symbol_address = (uint8_t*)elf.data + file_offset;

    /* Load the private key. */
    if (_load_pem_file(opts.keyfile, &pem_data, &pem_size) != 0)
        err("failed to load keyfile: %s", opts.keyfile);

    /* Initialize the RSA private key. */
    if (oe_rsa_private_key_read_pem(&rsa_private, pem_data, pem_size) != OE_OK)
        err("failed to initialize private key");
    rsa_private_initialized = true;

    /* Get the RSA public key. */
    if (oe_rsa_get_public_key_from_private(&rsa_private, &rsa_public) != OE_OK)
        err("failed to get public key");
    rsa_public_initialized = true;

    /* Sign the extension. */
#if 0
    oe_result_t oe_rsa_private_key_sign(
        const oe_rsa_private_key_t* private_key,
        oe_hash_type_t hash_type,
        const void* hash_data,
        size_t hash_size,
        uint8_t* signature,
        size_t* signature_size)
#endif

    /* Update the symbol. */
    {
        oe_extension_t ext;

        memset(&ext, 0, sizeof(ext));

        if (_get_modulus(&rsa_public, ext.modulus) != 0)
            err("failed to get modulus");

        if (_get_exponent(&rsa_public, ext.exponent) != 0)
            err("failed to get modulus");

        ext.isvprodid = opts.isvprodid;
        ext.isvsvn = opts.isvsvn;

        memcpy(symbol_address, &ext, sizeof(ext));
    }

    /* Perform the signing operation. */
    {
        oe_sha256_context_t context;
        OE_SHA256 hash;
        uint8_t signature[SIGNATURE_SIZE];

        oe_sha256_init(&context);
        oe_sha256_update(&context, opts.hash, sizeof(opts.hash));
        oe_sha256_update(&context, &opts.isvprodid, sizeof(opts.isvprodid));
        oe_sha256_update(&context, &opts.isvsvn, sizeof(opts.isvsvn));
        oe_sha256_final(&context, &hash);

        /* Create the signature from the hash. */
        {
            uint8_t buf[SIGNATURE_SIZE];
            size_t buf_size = SIGNATURE_SIZE;

            if (oe_rsa_private_key_sign(
                    &rsa_private,
                    OE_HASH_TYPE_SHA256,
                    hash.buf,
                    sizeof(hash),
                    buf,
                    &buf_size) != 0)
            {
                err("signing operation failed");
            }

            if (buf_size != SIGNATURE_SIZE)
                err("bad resulting signature size");

            /* The signature is backwards and needs to be reversed */
            _mem_reverse(signature, buf, SIGNATURE_SIZE);
        }
    }

    /* Rewrite the file. */
    if (write_file(opts.enclave, elf.data, elf.size) != 0)
    {
        fprintf(stderr, "%s: failed to write: %s\n", arg0, opts.enclave);
        goto done;
    }

    ret = 0;

done:

    if (pem_data)
        free(pem_data);

    if (loaded)
        elf64_unload(&elf);

    if (rsa_private_initialized)
        oe_rsa_private_key_free(&rsa_private);

    if (rsa_public_initialized)
        oe_rsa_public_key_free(&rsa_public);

    return ret;
}
