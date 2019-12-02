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
add_test(tests/oeext_privkey
    openssl genrsa -out ${PRIVKEY} -3 3072)

# Generate a public key from the private key:
add_test(tests/oeext_pubkey
    openssl rsa -in ${PRIVKEY} -out ${PUBKEY} -pubout -outform PEM)

add_test(tests/oeext_extend
    oeext extend
    pubkey=${PUBKEY}
    enclave=${CMAKE_CURRENT_BINARY_DIR}/enc/oeext_enc
    symbol=policy)

set(HASH 042aea10a0f14f2d391373599be69d53a75dde9951fc3d3cd10b6100aa7a9f24)
set(SIGFILE ${CMAKE_CURRENT_BINARY_DIR}/sign)

add_test(tests/oeext_sign
    oeext sign
    privkey=${PRIVKEY}
    hash=${HASH}
    sigfile=${SIGFILE})

add_enclave_test(tests/oeext oeext_host oeext_enc ${SIGFILE})
