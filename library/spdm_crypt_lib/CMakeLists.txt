cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_crypt_lib
    libspdm_crypt_hash.c
    libspdm_crypt_hmac.c
    libspdm_crypt_hkdf.c
    libspdm_crypt_asym.c
    libspdm_crypt_cert.c
    libspdm_crypt_aead.c
    libspdm_crypt_dhe.c
    libspdm_crypt_rng.c
)

ADD_LIBRARY(spdm_crypt_lib STATIC ${src_spdm_crypt_lib})
