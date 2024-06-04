cmake_minimum_required(VERSION 3.5)

add_library(spdm_common_lib STATIC "")

target_include_directories(spdm_common_lib
    PUBLIC
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_common_lib
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_context_data.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_context_data_session.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_crypto_service.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_crypto_service_session.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_opaque_data.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_support.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_com_msg_log.c
)