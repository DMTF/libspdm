cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_responder_lib
                    ${LIBSPDM_DIR}/library/spdm_common_lib 
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_responder_lib
    algorithms.c
    capabilities.c
    certificate.c
    challenge_auth.c
    communication.c
    digests.c
    encap_challenge.c
    encap_get_certificate.c
    encap_get_digests.c
    encap_key_update.c
    encap_response.c
    end_session.c
    error.c
    finish.c
    handle_response_state.c
    heartbeat.c
    key_exchange.c
    key_update.c
    measurements.c
    psk_exchange.c
    psk_finish.c
    receive_send.c
    respond_if_ready.c
    version.c
)

ADD_LIBRARY(spdm_responder_lib STATIC ${src_spdm_responder_lib})