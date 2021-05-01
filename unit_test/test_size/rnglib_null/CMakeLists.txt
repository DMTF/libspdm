cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_rnglib_null
    rnglib.c
)

ADD_LIBRARY(rnglib_null STATIC ${src_rnglib_null})
