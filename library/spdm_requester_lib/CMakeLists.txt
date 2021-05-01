cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_requester_lib
                    ${LIBSPDM_DIR}/library/spdm_common_lib 
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_requester_lib
    challenge.c
    communication.c
    encap_certificate.c
    encap_challenge_auth.c
    encap_digests.c
    encap_error.c
    encap_key_update.c
    encap_request.c
    end_session.c
    finish.c
    get_capabilities.c
    get_certificate.c
    get_digests.c
    get_measurements.c
    get_version.c
    handle_error_response.c
    heartbeat.c
    key_exchange.c
    key_update.c
    negotiate_algorithms.c
    psk_exchange.c
    psk_finish.c
    send_receive.c
)

ADD_LIBRARY(spdm_requester_lib STATIC ${src_spdm_requester_lib})
