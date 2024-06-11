cmake_minimum_required(VERSION 3.5)

add_library(cryptlib_mbedtls STATIC "")

target_include_directories(cryptlib_mbedtls
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
        ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
        ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
        ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
        ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
        ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

target_sources(cryptlib_mbedtls
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
        sys_call/mem_allocation.c
        sys_call/crt_wrapper_host.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_options(cryptlib_mbedtls PRIVATE -Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(cryptlib_mbedtls PRIVATE /wd4090 /wd4200)
    endif()
endif()

if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(cryptlib_mbedtls PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
