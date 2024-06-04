cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

set(src_debuglib
    debuglib.c
)

add_library(debuglib STATIC ${src_debuglib})
