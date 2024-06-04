cmake_minimum_required(VERSION 3.5)

add_library(spdm_transport_pcidoe_lib STATIC "")

target_include_directories(spdm_transport_pcidoe_lib
    PUBLIC
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_transport_pcidoe_lib
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_doe_common.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_doe_pcidoe.c
)