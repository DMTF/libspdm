cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_crypt_lib
    libspdm_crypt_crypt.c
)

ADD_LIBRARY(spdm_crypt_lib STATIC ${src_spdm_crypt_lib})
