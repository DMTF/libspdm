cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

set(src_debuglib_null
    debuglib.c
)

add_library(debuglib_null STATIC ${src_debuglib_null})
