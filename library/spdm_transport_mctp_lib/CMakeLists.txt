cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include)

set(src_spdm_transport_mctp_lib
    libspdm_mctp_common.c
    libspdm_mctp_mctp.c
)

add_library(spdm_transport_mctp_lib STATIC ${src_spdm_transport_mctp_lib})
