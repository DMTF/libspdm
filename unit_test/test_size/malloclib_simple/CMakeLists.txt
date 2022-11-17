cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_malloclib_simple
    malloclib.c
)

ADD_LIBRARY(malloclib_simple STATIC ${src_malloclib_simple})
