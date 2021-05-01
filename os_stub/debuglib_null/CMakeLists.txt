cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_debuglib_null
    debuglib.c
)

ADD_LIBRARY(debuglib_null STATIC ${src_debuglib_null})
