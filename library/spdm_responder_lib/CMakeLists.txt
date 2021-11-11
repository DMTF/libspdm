cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_responder_lib
    libspdm_rsp_algorithms.c
    libspdm_rsp_capabilities.c
    libspdm_rsp_certificate.c
    libspdm_rsp_challenge_auth.c
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
)

ADD_LIBRARY(spdm_responder_lib STATIC ${src_spdm_responder_lib})