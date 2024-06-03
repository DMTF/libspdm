cmake_minimum_required(VERSION 3.5)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

SET(src_debuglib_null
    debuglib.c
)

ADD_LIBRARY(debuglib_null STATIC ${src_debuglib_null})
