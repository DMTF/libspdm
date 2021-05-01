cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_crypt_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_crypt_lib
    crypt.c
)

ADD_LIBRARY(spdm_crypt_lib STATIC ${src_spdm_crypt_lib})
