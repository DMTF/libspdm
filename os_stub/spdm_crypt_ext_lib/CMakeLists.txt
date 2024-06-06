cmake_minimum_required(VERSION 3.5)

add_library(spdm_crypt_ext_lib STATIC "")

target_include_directories(spdm_crypt_ext_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_crypt_ext_lib
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/spdm_crypt_ext.c
)