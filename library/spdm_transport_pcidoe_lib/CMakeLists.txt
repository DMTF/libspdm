cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include)

set(src_spdm_transport_pcidoe_lib
    libspdm_doe_common.c
    libspdm_doe_pcidoe.c
)

add_library(spdm_transport_pcidoe_lib STATIC ${src_spdm_transport_pcidoe_lib})
