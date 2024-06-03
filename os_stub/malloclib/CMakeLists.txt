cmake_minimum_required(VERSION 3.5)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

SET(src_malloclib
    malloclib.c
)

ADD_LIBRARY(malloclib STATIC ${src_malloclib})
