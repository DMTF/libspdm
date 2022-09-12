cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub/cryptlib_openssl
                    ${LIBSPDM_DIR}/os_stub/openssllib/include
                    ${LIBSPDM_DIR}/os_stub/openssllib/openssl/include
                    ${LIBSPDM_DIR}/os_stub/openssllib/openssl/crypto/include
                    ${LIBSPDM_DIR}/os_stub/openssllib/openssl
)

SET(src_cryptlib_openssl
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
    pk/dh.c
    pk/sm2.c
    pk/rsa_basic.c
    pk/rsa_ext.c
    pk/x509.c
    rand/rand.c
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(cryptlib_openssl STATIC ${src_cryptlib_openssl})
TARGET_COMPILE_OPTIONS(cryptlib_openssl PRIVATE ${OPENSSL_FLAGS})
