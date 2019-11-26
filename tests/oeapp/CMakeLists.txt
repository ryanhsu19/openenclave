# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

set(PUBKEY "${CMAKE_CURRENT_BINARY_DIR}/public.pem")
set(PRIVKEY "${CMAKE_CURRENT_BINARY_DIR}/private.pem")
set(PRODID 100)
set(SVN 200)

# Generate a self-signed private key:
add_test(tests/oeapp_privkey
    openssl genrsa -out ${PRIVKEY} -3 3072)

# Generate a public key from the private key:
add_test(tests/oeapp_pubkey
    openssl rsa -in ${PRIVKEY} -out ${PUBKEY} -pubout -outform PEM)

add_test(tests/oeapp_appid
    oeapp appid
    pubkey=${PUBKEY}
    isvprodid=${PRODID}
    isvsvn=${SVN}
    enclave=${CMAKE_CURRENT_BINARY_DIR}/enc/oeapp_enc
    symbol=appid)

set(HASH 042aea10a0f14f2d391373599be69d53a75dde9951fc3d3cd10b6100aa7a9f24)
set(SIGFILE ${CMAKE_CURRENT_BINARY_DIR}/appsig)

add_test(tests/oeapp_appsig
    oeapp appsig
    privkey=${PRIVKEY}
    hash=${HASH}
    isvprodid=${PRODID}
    isvsvn=${SVN}
    sigfile=${SIGFILE})

add_enclave_test(tests/oeapp oeapp_host oeapp_enc ${SIGFILE})
