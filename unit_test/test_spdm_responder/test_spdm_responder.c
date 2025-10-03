/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

int libspdm_rsp_version_test(void);
int libspdm_rsp_capabilities_test(void);
int libspdm_rsp_algorithms_test(void);

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
int libspdm_rsp_digests_test(void);
int libspdm_rsp_certificate_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
int libspdm_rsp_challenge_auth_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
int libspdm_rsp_measurements_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP
int libspdm_rsp_endpoint_info_test(void);
int libspdm_rsp_endpoint_info_error_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
int libspdm_rsp_measurement_extension_log_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
int libspdm_rsp_key_pair_info_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
int libspdm_rsp_set_key_pair_info_ack_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || \
     LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || \
     LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
int libspdm_rsp_respond_if_ready_test (void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP */
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
int libspdm_rsp_key_exchange_rsp_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

int libspdm_rsp_finish_test(void);

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
int libspdm_rsp_psk_exchange_rsp_test(void);
int libspdm_rsp_psk_finish_rsp_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
int libspdm_rsp_heartbeat_ack_test(void);
int libspdm_rsp_key_update_ack_test(void);
int libspdm_rsp_end_session_ack_test(void);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
int spdm_rsp_encap_get_digests_test(void);
int spdm_rsp_encap_get_certificate_test(void);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if LIBSPDM_SEND_CHALLENGE_SUPPORT
int libspdm_rsp_encap_challenge_test(void);
#endif /* LIBSPDM_SEND_CHALLENGE_SUPPORT */
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
int libspdm_rsp_encapsulated_response_test(void);
int libspdm_rsp_encap_key_update_test(void);
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
int libspdm_rsp_encap_get_endpoint_info_test(void);
int libspdm_rsp_encap_get_endpoint_info_error_test(void);
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
int libspdm_rsp_encap_send_event_test(void);
int libspdm_rsp_encap_send_event_error_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/

int libspdm_rsp_set_certificate_rsp_test(void);
int libspdm_rsp_csr_test(void);

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
int libspdm_rsp_chunk_response_test(void);
int libspdm_rsp_receive_send_test(void);
int libspdm_rsp_chunk_send_ack_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
int libspdm_rsp_supported_event_types_test(void);
int libspdm_rsp_supported_event_types_error_test(void);
int libspdm_rsp_subscribe_event_types_ack_test(void);
int libspdm_rsp_subscribe_event_types_ack_error_test(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT
int libspdm_rsp_event_ack_test(void);
int libspdm_rsp_event_ack_error_test(void);
#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
int libspdm_rsp_vendor_defined_response_test(void);
int libspdm_rsp_vendor_defined_response_error_test(void);
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

int main(void)
{
    int return_value = 0;

    if (libspdm_rsp_version_test() != 0) {
        return_value = 1;
    }

    if (libspdm_rsp_capabilities_test() != 0) {
        return_value = 1;
    }

    if (libspdm_rsp_algorithms_test() != 0) {
        return_value = 1;
    }

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    if (libspdm_rsp_digests_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_certificate_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    if (libspdm_rsp_challenge_auth_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if (libspdm_rsp_measurements_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP
    if (libspdm_rsp_endpoint_info_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_endpoint_info_error_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
    if (libspdm_rsp_measurement_extension_log_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
    if (libspdm_rsp_key_pair_info_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
    if (libspdm_rsp_set_key_pair_info_ack_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/

    #if LIBSPDM_RESPOND_IF_READY_SUPPORT
    #if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || \
         LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || \
         LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    if (libspdm_rsp_respond_if_ready_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP */
    #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (libspdm_rsp_key_exchange_rsp_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (libspdm_rsp_finish_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (libspdm_rsp_psk_exchange_rsp_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (libspdm_rsp_psk_finish_rsp_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    if (libspdm_rsp_heartbeat_ack_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_key_update_ack_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_end_session_ack_test() != 0) {
        return_value = 1;
    }
    #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

    #if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
    #if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    #if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    if (spdm_rsp_encap_get_digests_test() != 0) {
        return_value = 1;
    }
    if (spdm_rsp_encap_get_certificate_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
    #if LIBSPDM_SEND_CHALLENGE_SUPPORT
    if (libspdm_rsp_encap_challenge_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_SEND_CHALLENGE_SUPPORT */
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
    if (libspdm_rsp_encapsulated_response_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_encap_key_update_test() != 0) {
        return_value = 1;
    }
    #if (LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT) && (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
    if (libspdm_rsp_encap_get_endpoint_info_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_encap_get_endpoint_info_error_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
    #if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
    if (libspdm_rsp_encap_send_event_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_encap_send_event_error_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
    #endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    if (libspdm_rsp_set_certificate_rsp_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    if (libspdm_rsp_csr_test() != 0) {
        return_value = 1;
    }
    #endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    if (libspdm_rsp_chunk_response_test() != 0) {
        return_value = 1;
    }

    if (libspdm_rsp_receive_send_test() != 0) {
        return_value = 1;
    }

    if (libspdm_rsp_chunk_send_ack_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
    if (libspdm_rsp_supported_event_types_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_supported_event_types_error_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_subscribe_event_types_ack_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_subscribe_event_types_ack_error_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

    #if LIBSPDM_EVENT_RECIPIENT_SUPPORT
    if (libspdm_rsp_event_ack_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_event_ack_error_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */

    #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
    if (libspdm_rsp_vendor_defined_response_test() != 0) {
        return_value = 1;
    }
    if (libspdm_rsp_vendor_defined_response_error_test() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

    return return_value;
}
