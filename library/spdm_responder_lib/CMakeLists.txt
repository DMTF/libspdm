cmake_minimum_required(VERSION 3.5)

add_library(spdm_responder_lib STATIC "")

target_include_directories(spdm_responder_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_responder_lib
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_algorithms.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_capabilities.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_certificate.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_challenge_auth.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_common.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_communication.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_digests.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_encap_challenge.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_encap_get_certificate.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_encap_get_digests.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_encap_key_update.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_encap_response.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_end_session.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_error.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_finish.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_handle_response_state.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_heartbeat.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_key_exchange.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_key_update.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_measurements.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_psk_exchange.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_psk_finish.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_receive_send.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_respond_if_ready.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_version.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_set_certificate.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_supported_event_types.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_csr.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_chunk_send_ack.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_chunk_get.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_rsp_vendor_response.c
)