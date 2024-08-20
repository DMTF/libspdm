cmake_minimum_required(VERSION 3.5)

add_library(spdm_requester_lib STATIC "")

target_include_directories(spdm_requester_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_requester_lib
    PRIVATE
        libspdm_req_challenge.c
        libspdm_req_common.c
        libspdm_req_communication.c
        libspdm_req_encap_certificate.c
        libspdm_req_encap_challenge_auth.c
        libspdm_req_encap_digests.c
        libspdm_req_encap_error.c
        libspdm_req_encap_key_update.c
        libspdm_req_encap_request.c
        libspdm_req_end_session.c
        libspdm_req_finish.c
        libspdm_req_get_capabilities.c
        libspdm_req_get_certificate.c
        libspdm_req_get_digests.c
        libspdm_req_get_event_types.c
        libspdm_req_subscribe_event_types.c
        libspdm_req_get_measurements.c
        libspdm_req_get_version.c
        libspdm_req_handle_error_response.c
        libspdm_req_heartbeat.c
        libspdm_req_key_exchange.c
        libspdm_req_key_update.c
        libspdm_req_negotiate_algorithms.c
        libspdm_req_psk_exchange.c
        libspdm_req_psk_finish.c
        libspdm_req_send_receive.c
        libspdm_req_set_certificate.c
        libspdm_req_get_csr.c
        libspdm_req_vendor_request.c
        libspdm_req_get_measurement_extension_log.c
        libspdm_req_get_key_pair_info.c
        libspdm_req_set_key_pair_info.c
)