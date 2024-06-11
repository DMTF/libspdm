cmake_minimum_required(VERSION 3.5)

add_library(spdm_transport_pcidoe_lib STATIC "")

target_include_directories(spdm_transport_pcidoe_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_transport_pcidoe_lib
    PRIVATE
        libspdm_doe_common.c
        libspdm_doe_pcidoe.c
)