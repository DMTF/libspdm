cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

set(src_malloclib
    malloclib.c
)

add_library(malloclib STATIC ${src_malloclib})
