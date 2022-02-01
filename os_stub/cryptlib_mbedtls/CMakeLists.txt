cmake_minimum_required(VERSION 2.8.12)

SET(src_cryptlib_mbedtls
    cipher/aead_aes_gcm.c
    cipher/aead_chacha20_poly1305.c
    cipher/aead_sm4_gcm.c
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
    pk/ecx.c
    pk/dh.c
    pk/sm2.c
    pk/rsa_basic.c
    pk/rsa_ext.c
    pk/x509.c
    rand/rand.c
    sys_call/mem_allocation.c
    sys_call/crt_wrapper_host.c
    sys_call/timer_wrapper_host.c
)
ADD_LIBRARY(cryptlib STATIC ${src_cryptlib_mbedtls})
TARGET_INCLUDE_DIRECTORIES(cryptlib PRIVATE
    ${LIBSPDM_DIR}/include
    ${LIBSPDM_DIR}/include/hal
    ${LIBSPDM_DIR}/include/hal/${ARCH}
    ${LIBSPDM_DIR}/os_stub/include
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    TARGET_COMPILE_OPTIONS(cryptlib PRIVATE
        -Wno-incompatible-pointer-types
        -Wno-pointer-sign
    )
endif()

if(ENABLE_BINARY_BUILD)
    MESSAGE(FATAL_ERROR "Using prebuilt mbedtls libraries is not supported.")
    TARGET_LINK_LIBRARIES(cryptlib PRIVATE
        mbedtls
        mbedx509
        mbedcrypto
    )
else()
    MESSAGE("Building mbedtls from source")
    TARGET_LINK_LIBRARIES(cryptlib PRIVATE
        cryptlib_mbedtls
    )
endif()
