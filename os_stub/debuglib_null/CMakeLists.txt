cmake_minimum_required(VERSION 3.5)

add_library(debuglib_null STATIC "")

target_include_directories(debuglib_null
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(debuglib_null
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/debuglib.c
)