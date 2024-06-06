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
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_options(cryptlib_null PRIVATE -Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()