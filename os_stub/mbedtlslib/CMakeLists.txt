cmake_minimum_required(VERSION 2.6)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MBEDTLS_FLAGS}")

if(ARCH STREQUAL "x64")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEFIx64")
elseif(ARCH STREQUAL "ia32")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEFI32")
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

SET(src_mbedtlslib
    mbedtls/library/aes.c
    mbedtls/library/aesni.c
    mbedtls/library/arc4.c
    mbedtls/library/aria.c
    mbedtls/library/asn1parse.c
    mbedtls/library/asn1write.c
    mbedtls/library/base64.c
    mbedtls/library/bignum.c
    mbedtls/library/blowfish.c
    mbedtls/library/camellia.c
    mbedtls/library/ccm.c
    mbedtls/library/certs.c
    mbedtls/library/chacha20.c
    mbedtls/library/chachapoly.c
    mbedtls/library/cipher.c
    mbedtls/library/cipher_wrap.c
    mbedtls/library/cmac.c
    mbedtls/library/ctr_drbg.c
    mbedtls/library/debug.c
    mbedtls/library/des.c
    mbedtls/library/dhm.c
    mbedtls/library/ecdh.c
    mbedtls/library/ecdsa.c
    mbedtls/library/ecjpake.c
    mbedtls/library/ecp.c
    mbedtls/library/ecp_curves.c
    mbedtls/library/entropy.c
    mbedtls/library/error.c
    mbedtls/library/gcm.c
    mbedtls/library/havege.c
    mbedtls/library/hkdf.c
    mbedtls/library/hmac_drbg.c
    mbedtls/library/md.c
    mbedtls/library/md2.c
    mbedtls/library/md4.c
    mbedtls/library/md5.c
    mbedtls/library/md_wrap.c
    mbedtls/library/memory_buffer_alloc.c
    mbedtls/library/nist_kw.c
    mbedtls/library/oid.c
    mbedtls/library/padlock.c
    mbedtls/library/pem.c
    mbedtls/library/pk.c
    mbedtls/library/pkcs11.c
    mbedtls/library/pkcs12.c
    mbedtls/library/pkcs5.c
    mbedtls/library/pkparse.c
    mbedtls/library/pkwrite.c
    mbedtls/library/pk_wrap.c
    mbedtls/library/poly1305.c
    mbedtls/library/ripemd160.c
    mbedtls/library/rsa.c
    mbedtls/library/rsa_internal.c
    mbedtls/library/sha1.c
    mbedtls/library/sha256.c
    mbedtls/library/sha512.c
    mbedtls/library/ssl_cache.c
    mbedtls/library/ssl_ciphersuites.c
    mbedtls/library/ssl_cli.c
    mbedtls/library/ssl_cookie.c
    mbedtls/library/ssl_srv.c
    mbedtls/library/ssl_ticket.c
    mbedtls/library/ssl_tls.c
    mbedtls/library/threading.c
    mbedtls/library/version.c
    mbedtls/library/version_features.c
    mbedtls/library/x509.c
    mbedtls/library/x509write_crt.c
    mbedtls/library/x509write_csr.c
    mbedtls/library/x509_create.c
    mbedtls/library/x509_crl.c
    mbedtls/library/x509_crt.c
    mbedtls/library/x509_csr.c
    mbedtls/library/xtea.c
)

ADD_LIBRARY(mbedtlslib STATIC ${src_mbedtlslib})
