cmake_minimum_required(VERSION 3.5)

add_library(malloclib_simple STATIC "")

target_include_directories(malloclib_simple
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(malloclib_simple
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/malloclib.c
)
