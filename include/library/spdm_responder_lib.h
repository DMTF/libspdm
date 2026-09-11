/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_RESPONDER_LIB_H
#define SPDM_RESPONDER_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "library/spdm_common_lib.h"
#include "library/spdm_secured_message_lib.h"

/**
 * Process the SPDM or APP request and return the response.
 *
 * The APP message is encoded to a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          Indicates if it is a secured message protected via SPDM session.
 *                             If session_id is NULL, it is a normal message.
 *                             If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message      Indicates if it is an APP message or SPDM message.
 * @param  request_size        size in bytes of the request data.
 * @param  request             A pointer to the request data.
 * @param  response_size       size in bytes of the response data.
 *                             On input, it means the size in bytes of response data buffer.
 *                             On output, it means the size in bytes of copied response data buffer
 *                             if LIBSPDM_STATUS_SUCCESS is returned, and means the size in bytes of
 *                             desired response data buffer if LIBSPDM_STATUS_BUFFER_TOO_SMALL is
 *                             returned.
 * @param  response            A pointer to the response data.
 **/
typedef libspdm_return_t (*libspdm_get_response_func)(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response);

/**
 * Register an SPDM or APP message process function.
 *
 * If the default message process function cannot handle the message,
 * this function will be invoked.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  get_response_func              The function to process the encapsuled message.
 **/
void libspdm_register_get_response_func(
    void *spdm_context, libspdm_get_response_func get_response_func);

/**
 * Process a SPDM request from a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  request_size                  size in bytes of the request data buffer.
 * @param  request                      A pointer to a destination buffer to store the request.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 **/
libspdm_return_t libspdm_process_request(void *spdm_context,
                                         uint32_t **session_id,
                                         bool *is_app_message,
                                         size_t request_size, void *request);

/**
 * Build a SPDM response to a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the response is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  response_size                 size in bytes of the response data buffer.
 * @param  response                     A pointer to a destination buffer to store the response.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 **/
libspdm_return_t libspdm_build_response(void *spdm_context, const uint32_t *session_id,
                                        bool is_app_message,
                                        size_t *response_size,
                                        void **response);

/**
 * This is the main dispatch function in SPDM responder.
 *
 * It receives one request message, processes it and sends the response message.
 *
 * It should be called in a while loop or an timer/interrupt handler.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
libspdm_return_t libspdm_responder_dispatch_message(void *spdm_context);

/**
 * Generate ERROR message.
 *
 * This function can be called in libspdm_get_response_func.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  error_code          The error code of the message.
 * @param  error_data          The error data of the message.
 * @param  spdm_response_size  size in bytes of the response data.
 *                             On input, it means the size in bytes of response data buffer.
 *                             On output, it means the size in bytes of copied response data buffer
 *                             if LIBSPDM_STATUS_SUCCESS is returned, and means the size in bytes of
 *                             desired response data buffer if LIBSPDM_STATUS_BUFFER_TOO_SMALL is
 *                             returned.
 * @param  spdm_response       A pointer to the response data.
 **/
libspdm_return_t libspdm_generate_error_response(const void *spdm_context,
                                                 uint8_t error_code,
                                                 uint8_t error_data,
                                                 size_t *spdm_response_size,
                                                 void *spdm_response);

/**
 * Generate ERROR message with extended error data.
 *
 * This function can be called in libspdm_get_response_func.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  error_code          The error code of the message.
 * @param  error_data          The error data of the message.
 * @param  extended_error_data_size  The size in bytes of the extended error data.
 * @param  extended_error_data A pointer to the extended error data.
 * @param  spdm_response_size  size in bytes of the response data.
 *                             On input, it means the size in bytes of response data buffer.
 *                             On output, it means the size in bytes of copied response data buffer
 *                             if LIBSPDM_STATUS_SUCCESS is returned, and means the size in bytes of
 *                             desired response data buffer if LIBSPDM_STATUS_BUFFER_TOO_SMALL is
 *                             returned.
 * @param  spdm_response                 A pointer to the response data.
 **/
libspdm_return_t libspdm_generate_extended_error_response(
    const void *spdm_context, uint8_t error_code, uint8_t error_data,
    size_t extended_error_data_size, const uint8_t *extended_error_data,
    size_t *spdm_response_size, void *spdm_response);

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
typedef void (*libspdm_session_state_callback_func)(
    void *spdm_context, uint32_t session_id,
    libspdm_session_state_t session_state);

/**
 * Register an SPDM state callback function.
 *
 * This function can be called multiple times to let different session APPs register its own callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_state_callback     The function to be called in SPDM session state change.
 **/
void libspdm_register_session_state_callback_func(
    void *spdm_context,
    libspdm_session_state_callback_func spdm_session_state_callback);

/**
 * Notify the connection state to an SPDM context register.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 **/
typedef void (*libspdm_connection_state_callback_func)(
    void *spdm_context, libspdm_connection_state_t connection_state);

/**
 * Register an SPDM connection state callback function.
 *
 * This function can be called multiple times to let different register its own callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_connection_state_callback  The function to be called in SPDM connection state change.
 **/
void libspdm_register_connection_state_callback_func(
    void *spdm_context,
    libspdm_connection_state_callback_func spdm_connection_state_callback);

/**
 * Notify the key update operation to an SPDM context register.
 *
 * @param  spdm_context           A pointer to the SPDM context.
 * @param  session_id             Session ID for the keys being updated.
 * @param  key_update_operation   Indicate the key update operation.
 * @param  key_update_action      Indicate the direction of the key update.
 **/
typedef void (*libspdm_key_update_callback_func)(
    void *spdm_context, uint32_t session_id, libspdm_key_update_operation_t key_update_op,
    libspdm_key_update_action_t key_update_action);

/**
 * Notify the key update operation to an SPDM context register.
 *
 * @param  spdm_context           A pointer to the SPDM context.
 * @param  session_id             Session ID for the keys being updated.
 * @param  key_update_operation   Indicate the key update operation.
 * @param  key_update_action      Indicate the direction of the key update.
 **/
void libspdm_trigger_key_update_callback(
    void *spdm_context, uint32_t session_id, libspdm_key_update_operation_t key_update_op,
    libspdm_key_update_action_t key_update_action);

/**
 * Register a key update callback function.
 *
 * This function can be called multiple times to register multiple callbacks.
 *
 * @param  spdm_context              A pointer to the SPDM context.
 * @param  spdm_key_update_callback  The function to be called in key update operation.
 **/
void libspdm_register_key_update_callback_func(
    void *spdm_context, libspdm_key_update_callback_func spdm_key_update_callback);

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
/**
 * This function is called when the Responder receives a GET_ENCAPSULATED_REQUEST or
 * DELIVER_ENCAPSULATED_RESPONSE.
 *
 * It is not called when libspdm itself determines the next encapsulated request:
 * - when a multi-part GET_CERTIFICATE or KEY_UPDATE is still in progress
 * - when the outstanding request is reissued with RESPOND_IF_READY after the Requester delivered
 *   an encapsulated ERROR(ResponseNotReady)
 * - when the flow is one that libspdm must terminate on the Responder's behalf
 *
 * @param  spdm_context       A pointer to the SPDM context.
 * @param  session_id         If non-NULL, the session ID.
 * @param  encap_flow_type    One of
 *                            - LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH
 *                            - LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH
 *                            - LIBSPDM_ENCAP_FLOW_REQ_INITIATED
 * @param  last_request_code  One of the SPDM_* request codes. If this function is called due to
 *                            GET_ENCAPSULATED_REQUEST then its value is 0x00.
 * @param  error_code         If the Requester delivered an encapsulated ERROR then its ErrorCode,
 *                            and the encapsulated flow terminates once this function returns. Its
 *                            value is 0x00 otherwise.
 * @param  terminate_flow     Specifies whether to terminate the encapsulated flow or not. Its
 *                            value is false on input. It must be set to true when error_code is
 *                            non-zero.
 * @param  encap_request_size Size, in bytes, of the encapsulated request.
 * @param  encap_request      The encapsulated request.
 **/
typedef libspdm_return_t (*libspdm_encap_flow_handler_func)(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request);

/**
 * Register the encapsulated flow handler function.
 *
 * If the Responder sets ENCAP_CAP then it must register a handler, as libspdm calls it to obtain
 * each encapsulated request.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  encap_flow_handler  The function that libspdm calls during an encapsulated flow.
 **/
void libspdm_register_encap_flow_handler(void *spdm_context,
                                         libspdm_encap_flow_handler_func encap_flow_handler);

/**
 * Get the size of the payload that the last encapsulated request retrieved.
 *
 * Some encapsulated requests, such as GET_CERTIFICATE and GET_ENDPOINT_INFO, are given a buffer
 * that libspdm writes the Requester's payload into. This returns the number of bytes written to
 * that buffer. The value is meaningful when the encapsulated flow handler is called with the
 * last_request_code of the request that the payload answers.
 *
 * @param  spdm_context   A pointer to the SPDM context.
 * @param  session_id     The session_id given to libspdm_encap_flow_handler_func.
 * @param  payload_size   On output, the size in bytes of the payload that was written to the
 *                        buffer given to the encapsulated request function.
 *
 * @retval LIBSPDM_STATUS_SUCCESS              payload_size is returned.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL  session_id does not refer to an existing session.
 **/
libspdm_return_t libspdm_get_encap_payload_size(void *spdm_context,
                                                const uint32_t *session_id,
                                                size_t *payload_size);

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Get the SPDM encapsulated GET_DIGESTS request.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          The session_id given to libspdm_encap_flow_handler_func.
 * @param  encap_request_size  On input, the size in bytes of the encapsulated request buffer.
 *                             On output, the size in bytes of the encapsulated request.
 * @param  encap_request       A pointer to the encapsulated request data.
 *
 * @retval LIBSPDM_STATUS_SUCCESS              The encapsulated request is returned.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL  session_id does not refer to an existing session.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP      The connection is SPDM 1.0, or the Requester does
 *                                             not support CERT_CAP.
 * @retval LIBSPDM_STATUS_BUFFER_FULL          The request does not fit in the transcript.
 **/
libspdm_return_t libspdm_get_encap_request_get_digests(void *spdm_context,
                                                       const uint32_t *session_id,
                                                       size_t *encap_request_size,
                                                       void *encap_request);

/**
 * Get the SPDM encapsulated GET_CERTIFICATE request.
 *
 * The Requester's certificate chain can span multiple encapsulated requests. libspdm issues the
 * remaining requests itself, accumulating the chain into cert_chain, and calls the encapsulated
 * flow handler once the entire chain has been retrieved. cert_chain shall therefore remain valid
 * until the handler is next called, at which point its size can be read with
 * libspdm_get_encap_payload_size.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          The session_id given to libspdm_encap_flow_handler_func.
 * @param  slot_id             The slot of the Requester's certificate chain to be retrieved,
 *                             which is less than SPDM_MAX_SLOT_COUNT.
 * @param  cert_chain_size     The size, in bytes, of cert_chain.
 * @param  cert_chain          A pointer to a buffer that will store the certificate chain.
 * @param  encap_request_size  On input, the size in bytes of the encapsulated request buffer.
 *                             On output, the size in bytes of the encapsulated request.
 * @param  encap_request       A pointer to the encapsulated request data.
 *
 * @retval LIBSPDM_STATUS_SUCCESS            The encapsulated request is returned.
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER  cert_chain is NULL, cert_chain_size is 0, or
 *                                           slot_id is not a valid slot.
 **/
libspdm_return_t libspdm_get_encap_request_get_certificate(void *spdm_context,
                                                           const uint32_t *session_id,
                                                           uint8_t slot_id,
                                                           size_t cert_chain_size,
                                                           void *cert_chain,
                                                           size_t *encap_request_size,
                                                           void *encap_request);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
/**
 * Get the SPDM encapsulated CHALLENGE request.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  req_slot_id         The Requester's certificate slot to be challenged, or 0xFF if its
 *                             public key was provisioned.
 * @param  requester_context   SPDM_REQ_CONTEXT_SIZE bytes of context, or NULL for zeros. Ignored
 *                             before SPDM 1.3.
 * @param  encap_request_size  On input, the size in bytes of the encapsulated request buffer.
 *                             On output, the size in bytes of the encapsulated request.
 * @param  encap_request       A pointer to the encapsulated request data.
 *
 * @retval LIBSPDM_STATUS_SUCCESS            The encapsulated request is returned.
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER  req_slot_id is neither a valid slot nor 0xFF.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP    The connection is SPDM 1.0, or the Requester does not
 *                                           support CHAL_CAP.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE   The encapsulated request buffer is too small for
 *                                           CHALLENGE.
 * @retval LIBSPDM_STATUS_LOW_ENTROPY        A nonce could not be generated.
 * @retval LIBSPDM_STATUS_BUFFER_FULL        The request does not fit in the transcript.
 **/
libspdm_return_t libspdm_get_encap_request_challenge(void *spdm_context,
                                                     uint8_t req_slot_id,
                                                     const void *requester_context,
                                                     size_t *encap_request_size,
                                                     void *encap_request);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */

/**
 * Get the SPDM encapsulated KEY_UPDATE request.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          The session in which the KEY_UPDATE request is sent.
 * @param  operation           SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY or
 *                             SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY.
 *                             SPDM_KEY_UPDATE_OPERATIONS_UPDATE_ALL_KEYS is currently not legal in
 *                             the encapsulated flow.
 * @param  encap_request_size  On input, the size in bytes of the encapsulated request buffer.
 *                             On output, the size in bytes of the encapsulated request.
 * @param  encap_request       A pointer to the encapsulated request data.
 *
 * @retval LIBSPDM_STATUS_SUCCESS              The encapsulated request is returned.
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER    operation is not legal in the encapsulated flow.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL  session_id does not refer to an existing session, or
 *                                             the session is not established.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP      The connection is SPDM 1.0, or KEY_UPD_CAP is not
 *                                             supported by both endpoints.
 * @retval LIBSPDM_STATUS_LOW_ENTROPY          The KEY_UPDATE tag could not be generated.
 * @retval LIBSPDM_STATUS_CRYPTO_ERROR         The new session data key could not be created or
 *                                             activated.
 **/
libspdm_return_t libspdm_get_encap_request_key_update(void *spdm_context,
                                                      uint32_t session_id,
                                                      uint8_t operation,
                                                      size_t *encap_request_size,
                                                      void *encap_request);

#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
/**
 * Get the SPDM encapsulated GET_ENDPOINT_INFO request.
 *
 * This is intended to be called by the integrator's encap flow handler to build
 * the next encapsulated request within the handler callback.
 *
 * libspdm writes the Requester's endpoint information into ep_info, so ep_info shall remain valid
 * until the handler is next called, at which point its size can be read with
 * libspdm_get_encap_payload_size.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          The session_id given to libspdm_encap_flow_handler_func.
 * @param  sub_code            Subcode for the GET_ENDPOINT_INFO request.
 * @param  slot_id             The slot of the Requester's certificate chain that signs the
 *                             response, or 0xF if its public key was provisioned. It is only
 *                             meaningful when a signature is requested.
 * @param  request_attributes  Request attributes; set
 *                             SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED
 *                             to request a signature.
 * @param  ep_info_size        The size, in bytes, of ep_info.
 * @param  ep_info             A pointer to a buffer that will store the endpoint information.
 * @param  encap_request_size  On input: size of the encap_request buffer.
 *                             On output: size of the written request.
 * @param  encap_request       Buffer to receive the encapsulated request.
 *
 * @retval LIBSPDM_STATUS_SUCCESS            The encapsulated request is returned.
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER  ep_info is NULL, ep_info_size is 0, or slot_id
 *                                           is neither a valid slot nor 0xF.
 **/
libspdm_return_t libspdm_get_encap_request_get_endpoint_info(
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t sub_code,
    uint8_t slot_id,
    uint8_t request_attributes,
    size_t ep_info_size,
    void *ep_info,
    size_t *encap_request_size,
    void *encap_request);
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
/**
 * Get the SPDM encapsulated SEND_EVENT request.
 *
 * This is intended to be called by the integrator's encap flow handler to build
 * the next encapsulated request within the handler callback.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          The session in which the event is sent.
 * @param  encap_request_size  On input: size of the encap_request buffer.
 *                             On output: size of the written request.
 * @param  encap_request       Buffer to receive the encapsulated request.
 **/
libspdm_return_t libspdm_get_encap_request_send_event(
    void *spdm_context,
    uint32_t session_id,
    size_t *encap_request_size,
    void *encap_request);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

/**
 * Register the request-aware vendor-defined response callback.
 *
 * This is useful for creating unique responses to devices.
 *
 * @param  spdm_context     A pointer to the SPDM context.
 * @param  resp_callback    Response callback function
 *
 * @retval LIBSPDM_STATUS_SUCCESS Success
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER Some parameters invalid or NULL
 **/
libspdm_return_t libspdm_register_vendor_callback_func(void *spdm_context,
                                                       libspdm_vendor_response_callback_func resp_callback);

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/**
 * This function registers the callback function for notify
 * integrator L1L2 is reset.
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  spdm_meas_log_reset_callback     L1L2 reset callback function
 *
 * @retval LIBSPDM_STATUS_SUCCESS Success
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER Some parameters invalid or NULL
 */
libspdm_return_t libspdm_register_meas_log_reset_callback(
    void *spdm_context, libspdm_meas_log_reset_callback_func spdm_meas_log_reset_callback);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

/**
 * This function allows the consumer to terminate a session.
 * For example, it can be used when watchdog fires.
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   session_id of the session to be terminated.
 *
 * @retval LIBSPDM_STATUS_SUCCESS Success
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER session_id is invalid.
 **/
libspdm_return_t libspdm_terminate_session(
    void *spdm_context, uint32_t session_id);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_RESPONDER_LIB_H */
