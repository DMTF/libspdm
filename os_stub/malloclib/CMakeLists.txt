cmake_minimum_required(VERSION 3.5)

add_library(malloclib STATIC "")

target_include_directories(malloclib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(malloclib
    PRIVATE
        malloclib.c
)
