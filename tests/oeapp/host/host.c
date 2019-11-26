// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/appsig.h>
#include <openenclave/internal/files.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oeapp_u.h"

int _load_signature_file(const char* path, oe_appsig_t* appsig)
{
    int ret = -1;
    void* data = NULL;
    size_t size;

    if (__oe_load_file(path, 0, &data, &size) != 0)
        goto done;

    if (size != sizeof(oe_appsig_t))
        goto done;

    memcpy(appsig, data, sizeof(oe_appsig_t));

    ret = 0;

done:

    if (data)
        free(data);

    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    oe_appsig_t appsig;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH SIGFILE\n", argv[0]);
        return 1;
    }

    /* Load the signature file. */
    OE_TEST(_load_signature_file(argv[2], &appsig) == 0);

    OE_TEST(appsig.magic == OE_APPSIG_MAGIC);

    result = oe_create_oeapp_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = dump_appid_ecall(enclave);
    OE_TEST(result == OE_OK);

    result = verify_ecall(enclave, &appsig);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (oeapp)\n");

    return 0;
}
