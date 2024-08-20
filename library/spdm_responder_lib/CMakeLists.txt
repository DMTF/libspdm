cmake_minimum_required(VERSION 3.5)

add_library(spdm_responder_lib STATIC "")

target_include_directories(spdm_responder_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_responder_lib
    PRIVATE
        libspdm_rsp_algorithms.c
        libspdm_rsp_capabilities.c
        libspdm_rsp_certificate.c
        libspdm_rsp_challenge_auth.c
        libspdm_rsp_common.c
        libspdm_rsp_communication.c
        libspdm_rsp_digests.c
        libspdm_rsp_encap_challenge.c
        libspdm_rsp_encap_get_certificate.c
        libspdm_rsp_encap_get_digests.c
        libspdm_rsp_encap_key_update.c
        libspdm_rsp_encap_response.c
        libspdm_rsp_end_session.c
        libspdm_rsp_error.c
        libspdm_rsp_finish.c
        libspdm_rsp_handle_response_state.c
        libspdm_rsp_heartbeat.c
        libspdm_rsp_key_exchange.c
        libspdm_rsp_key_update.c
        libspdm_rsp_measurements.c
        libspdm_rsp_psk_exchange.c
        libspdm_rsp_psk_finish.c
        libspdm_rsp_receive_send.c
        libspdm_rsp_respond_if_ready.c
        libspdm_rsp_version.c
        libspdm_rsp_set_certificate.c
        libspdm_rsp_supported_event_types.c
        libspdm_rsp_subscribe_event_types_ack.c
        libspdm_rsp_csr.c
        libspdm_rsp_chunk_send_ack.c
        libspdm_rsp_chunk_get.c
        libspdm_rsp_vendor_response.c
        libspdm_rsp_measurement_extension_log.c
        libspdm_rsp_get_key_pair_info.c
        libspdm_rsp_set_key_pair_info_ack.c
)