cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
                    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

add_compile_definitions(LIBSPDM_UNIT_TEST=1)

SET(src_cryptlib_wrapper
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/cipher/aead_aes_gcm.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/cipher/aead_chacha20_poly1305.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/cipher/aead_sm4_gcm.c
    hash/sha.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/hash/sha.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/hash/sha3.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/hash/sm3.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/hmac/hmac_sha.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/hmac/hmac_sha3.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/hmac/hmac_sm3.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/kdf/hkdf_sha.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/kdf/hkdf_sha3.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/kdf/hkdf_sm3.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pem/pem.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/ec.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/ecd.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/dh.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/sm2.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/rsa_basic.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/rsa_ext.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/pk/x509.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/rand/rand.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/sys_call/mem_allocation.c
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(cryptlib_wrapper STATIC ${src_cryptlib_wrapper})
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        TARGET_COMPILE_OPTIONS(cryptlib_wrapper PRIVATE /wd4090)
    endif()
endif()
