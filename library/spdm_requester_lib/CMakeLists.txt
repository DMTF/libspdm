cmake_minimum_required(VERSION 3.5)

add_library(spdm_requester_lib STATIC "")

target_include_directories(spdm_requester_lib
    PUBLIC
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_requester_lib
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_challenge.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_common.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_communication.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_encap_certificate.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_encap_challenge_auth.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_encap_digests.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_encap_error.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_encap_key_update.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_encap_request.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_end_session.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_finish.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_capabilities.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_certificate.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_digests.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_event_types.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_measurements.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_version.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_handle_error_response.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_heartbeat.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_key_exchange.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_key_update.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_negotiate_algorithms.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_psk_exchange.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_psk_finish.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_send_receive.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_set_certificate.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_get_csr.c
        ${CMAKE_CURRENT_LIST_DIR}/libspdm_req_vendor_request.c
)