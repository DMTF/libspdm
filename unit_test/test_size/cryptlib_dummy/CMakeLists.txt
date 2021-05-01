cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-pointer-types -Wno-pointer-sign")
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_size/cryptlib_dummy
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include                   
)

SET(src_cryptlib_dummy
    cipher/aead_aes_gcm.c
    cipher/aead_chacha20_poly1305.c
    hash/sha256.c
    hash/sha512.c
    hmac/hmac_sha.c
    kdf/hkdf.c
    pem/pem.c
    pk/ec.c
    pk/dh.c
    pk/rsa_basic.c
    pk/rsa_ext.c
    pk/x509.c
    rand/rand.c
)

ADD_LIBRARY(cryptlib_dummy STATIC ${src_cryptlib_dummy})
