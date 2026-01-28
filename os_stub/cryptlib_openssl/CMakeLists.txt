cmake_minimum_required(VERSION 3.5)

add_library(cryptlib_openssl STATIC "")

target_include_directories(cryptlib_openssl
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/cryptlib_openssl
        ${LIBSPDM_DIR}/os_stub/openssllib/include
)

target_sources(cryptlib_openssl
    PRIVATE
        cipher/aead_aes_gcm.c
        cipher/aead_chacha20_poly1305.c
        cipher/aead_sm4_gcm.c
        der/der.c
        der/der_pqc.c
        hash/sha.c
        hash/sha3.c
        hash/sm3.c
        hmac/hmac_sha.c
        hmac/hmac_sha3.c
        hmac/hmac_sm3.c
        kdf/hkdf_sha.c
        kdf/hkdf_sha3.c
        kdf/hkdf_sm3.c
        pem/pem.c
        pem/pem_pqc.c
        pk/ec.c
        pk/ecd.c
        pk/dh.c
        pk/sm2.c
        pk/rsa_basic.c
        pk/rsa_ext.c
        pk/mldsa_basic.c
        pk/mldsa_ext.c
        pk/mlkem.c
        pk/slhdsa_basic.c
        pk/slhdsa_ext.c
        pk/x509.c
        pk/x509_pqc.c
        rand/rand.c
)

target_compile_options(cryptlib_openssl PRIVATE ${OPENSSL_FLAGS})

if(ENABLE_BINARY_BUILD STREQUAL "1")
    target_link_libraries(cryptlib_openssl PUBLIC ssl crypto memlib)
else()
    target_link_libraries(cryptlib_openssl PUBLIC openssllib memlib)
endif()
