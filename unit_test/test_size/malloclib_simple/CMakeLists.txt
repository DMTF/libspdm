cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include)

set(src_malloclib_simple
    malloclib.c
)

add_library(malloclib_simple STATIC ${src_malloclib_simple})
