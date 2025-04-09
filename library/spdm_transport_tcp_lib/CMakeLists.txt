cmake_minimum_required(VERSION 3.5)

add_library(spdm_transport_tcp_lib STATIC "")

target_include_directories(spdm_transport_tcp_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_transport_tcp_lib
    PRIVATE
        libspdm_tcp_common.c
        libspdm_tcp_tcp.c
)
