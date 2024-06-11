cmake_minimum_required(VERSION 3.5)

add_library(debuglib STATIC "")

target_include_directories(debuglib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(debuglib
    PRIVATE
        debuglib.c
)