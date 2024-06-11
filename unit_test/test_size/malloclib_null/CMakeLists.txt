cmake_minimum_required(VERSION 3.5)

add_library(malloclib_null STATIC "")

target_include_directories(malloclib_null
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(malloclib_null
    PRIVATE
        malloclib.c
)
