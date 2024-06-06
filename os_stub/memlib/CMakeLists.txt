cmake_minimum_required(VERSION 3.5)

add_library(memlib STATIC "")

target_include_directories(memlib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(memlib
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/compare_mem.c
        ${CMAKE_CURRENT_LIST_DIR}/copy_mem.c
        ${CMAKE_CURRENT_LIST_DIR}/set_mem.c
        ${CMAKE_CURRENT_LIST_DIR}/zero_mem.c
)
