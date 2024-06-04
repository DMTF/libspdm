cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include)

set(src_malloclib_null
    malloclib.c
)

add_library(malloclib_null STATIC ${src_malloclib_null})
