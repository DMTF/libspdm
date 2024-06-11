cmake_minimum_required(VERSION 3.5)

add_library(rnglib_null STATIC "")

target_include_directories(rnglib_null
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(rnglib_null
    PRIVATE
        rnglib.c
)
