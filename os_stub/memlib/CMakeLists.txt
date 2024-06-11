cmake_minimum_required(VERSION 3.5)

add_library(memlib STATIC "")

target_include_directories(memlib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(memlib
    PRIVATE
        compare_mem.c
        copy_mem.c
        set_mem.c
        zero_mem.c
)
