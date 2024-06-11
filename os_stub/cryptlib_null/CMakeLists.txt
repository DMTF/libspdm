cmake_minimum_required(VERSION 3.5)

add_library(cryptlib_null STATIC "")

target_include_directories(cryptlib_null
    PRIVATE
        ${LIBSPDM_DIR}/os_stub/cryptlib_null
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
)

target_sources(cryptlib_null
    PRIVATE
        cipher/aead_aes_gcm.c
        cipher/aead_chacha20_poly1305.c
        cipher/aead_sm4_gcm.c
        der/der.c
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
        pk/ec.c
        pk/ecd.c
        pk/dh.c
        pk/sm2.c
        pk/rsa_basic.c
        pk/rsa_ext.c
        pk/x509.c
        rand/rand.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_options(cryptlib_null PRIVATE -Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()