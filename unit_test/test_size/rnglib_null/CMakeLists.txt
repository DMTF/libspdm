cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

set(src_rnglib_null
    rnglib.c
)

add_library(rnglib_null STATIC ${src_rnglib_null})
