cmake_minimum_required(VERSION 3.16)

add_library(cryptstublib_null STATIC "")

target_include_directories(cryptstublib_null
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub/include
)

target_sources(cryptstublib_null
    PRIVATE
        rand_null.c
)