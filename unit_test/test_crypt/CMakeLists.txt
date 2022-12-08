cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_crypt
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_test_crypt
    test_crypt.c
    hash_verify.c
    hmac_verify.c
    hkdf_verify.c
    aead_verify.c
    rsa_verify.c
    rsa_verify2.c
    dh_verify.c
    ec_verify.c
    ec_verify2.c
    ecd_verify.c
    ecd_verify2.c
    sm2_verify.c
    sm2_verify2.c
    rand_verify.c
    x509_verify.c
    os_support.c
)

SET(test_crypt_LIBRARY
    memlib
    debuglib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_device_secret_lib_sample
    spdm_crypt_lib
    spdm_crypt_ext_lib
)

if(CRYPTO STREQUAL "mbedtls")
    add_definitions(-DLIBSPDM_RSA_SSA_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_RSA_PSS_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_ECDSA_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SM2_DSA_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_EDDSA_ED25519_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_EDDSA_ED448_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_FFDHE_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_ECDHE_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SM2_KEY_EXCHANGE_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_AEAD_GCM_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_AEAD_SM4_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_SHA256_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA384_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA512_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA3_256_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_SHA3_384_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_SHA3_512_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_SM3_256_SUPPORT_TEST=0)
elseif(CRYPTO STREQUAL "openssl")
    add_definitions(-DLIBSPDM_RSA_SSA_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_RSA_PSS_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_ECDSA_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SM2_DSA_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_EDDSA_ED25519_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_EDDSA_ED448_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_FFDHE_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_ECDHE_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SM2_KEY_EXCHANGE_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_AEAD_GCM_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_AEAD_SM4_SUPPORT_TEST=0)
    add_definitions(-DLIBSPDM_SHA256_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA384_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA512_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA3_256_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA3_384_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SHA3_512_SUPPORT_TEST=1)
    add_definitions(-DLIBSPDM_SM3_256_SUPPORT_TEST=1)
endif()

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    SET(test_crypt_LIBRARY ${test_crypt_LIBRARY} armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_crypt
                   ${src_test_crypt}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
    )
else()
    ADD_EXECUTABLE(test_crypt ${src_test_crypt})
    TARGET_LINK_LIBRARIES(test_crypt ${test_crypt_LIBRARY})
endif()

