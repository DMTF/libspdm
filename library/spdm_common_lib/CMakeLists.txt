cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include)

set(src_spdm_common_lib
    libspdm_com_context_data.c
    libspdm_com_context_data_session.c
    libspdm_com_crypto_service.c
    libspdm_com_crypto_service_session.c
    libspdm_com_opaque_data.c
    libspdm_com_support.c
    libspdm_com_msg_log.c
)

add_library(spdm_common_lib STATIC ${src_spdm_common_lib})
