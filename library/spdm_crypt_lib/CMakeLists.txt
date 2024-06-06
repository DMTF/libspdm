cmake_minimum_required(VERSION 3.5)

add_library(spdm_crypt_lib STATIC "")

target_include_directories(spdm_crypt_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_crypt_lib
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_hash.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_hmac.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_hkdf.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_asym.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_cert.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_aead.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_dhe.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_crypt_rng.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_hmac.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_aes_gcm.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_rsa_ssa.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_rsa_pss.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_hkdf.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_ecdh.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_sha2.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_ffdh.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/fips/libspdm_selftest_eddsa.c
)