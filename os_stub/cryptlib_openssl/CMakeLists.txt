cmake_minimum_required(VERSION 2.6)

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
    hash/sha256.c
    hash/sha512.c
    hash/sha3.c
    hash/sm3.c
    hmac/hmac_sha.c
    kdf/hkdf.c
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
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(cryptlib_openssl STATIC ${src_cryptlib_openssl})
