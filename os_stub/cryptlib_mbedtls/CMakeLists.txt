cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

add_library(cryptlib_mbedtls STATIC "")

target_include_directories(cryptlib_mbedtls
    PUBLIC
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
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/cipher/aead_aes_gcm.c
        ${CMAKE_CURRENT_LIST_DIR}/cipher/aead_chacha20_poly1305.c
        ${CMAKE_CURRENT_LIST_DIR}/cipher/aead_sm4_gcm.c
        ${CMAKE_CURRENT_LIST_DIR}/der/der.c
        ${CMAKE_CURRENT_LIST_DIR}/hash/sha.c
        ${CMAKE_CURRENT_LIST_DIR}/hash/sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/hash/sm3.c
        ${CMAKE_CURRENT_LIST_DIR}/hmac/hmac_sha.c
        ${CMAKE_CURRENT_LIST_DIR}/hmac/hmac_sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/hmac/hmac_sm3.c
        ${CMAKE_CURRENT_LIST_DIR}/kdf/hkdf_sha.c
        ${CMAKE_CURRENT_LIST_DIR}/kdf/hkdf_sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/kdf/hkdf_sm3.c
        ${CMAKE_CURRENT_LIST_DIR}/pem/pem.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/ec.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/ecd.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/dh.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/sm2.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/rsa_basic.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/rsa_ext.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/x509.c
        ${CMAKE_CURRENT_LIST_DIR}/rand/rand.c
        ${CMAKE_CURRENT_LIST_DIR}/sys_call/mem_allocation.c
        ${CMAKE_CURRENT_LIST_DIR}/sys_call/crt_wrapper_host.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(cryptlib_mbedtls PRIVATE /wd4090 /wd4200)
    endif()
endif()

if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(cryptlib_mbedtls PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
