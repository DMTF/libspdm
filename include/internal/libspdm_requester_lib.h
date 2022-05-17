/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_REQUESTER_LIB_INTERNAL_H__
#define __SPDM_REQUESTER_LIB_INTERNAL_H__

#include "library/spdm_requester_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "internal/libspdm_common_lib.h"

/**
 * This function handles simple error code.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  error_code                    Indicate the error code.
 *
 * @retval RETURN_NO_RESPONSE           If the error code is BUSY.
 * @retval RETURN_DEVICE_ERROR          If the error code is REQUEST_RESYNCH or others.
 **/
libspdm_return_t libspdm_handle_simple_error_response(void *context,
                                                      uint8_t error_code);

/**
 * This function handles the error response.
 *
 * The SPDM response code must be SPDM_ERROR.
 * For error code RESPONSE_NOT_READY, this function sends RESPOND_IF_READY and receives an expected SPDM response.
 * For error code BUSY, this function shrinks the managed buffer, and return RETURN_NO_RESPONSE.
 * For error code REQUEST_RESYNCH, this function shrinks the managed buffer, clears connection_state, and return RETURN_DEVICE_ERROR.
 * For error code DECRYPT_ERROR, end the session: free session id and session key, return RETURN_SECURITY_VIOLATION.
 * For any other error code, this function shrinks the managed buffer, and return RETURN_DEVICE_ERROR.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                       If session_id is NULL, it is a normal message.
 *                                       If session_id is NOT NULL, it is a secured message.
 * @param  response_size                 The size of the response.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
 * @param  response                     The SPDM response message.
 * @param  original_request_code          Indicate the original request code.
 * @param  expected_response_code         Indicate the expected response code.
 * @param  expected_response_size         Indicate the expected response size.
 *
 * @retval RETURN_SUCCESS               The error code is RESPONSE_NOT_READY. The RESPOND_IF_READY is sent and an expected SPDM response is received.
 * @retval RETURN_NO_RESPONSE           The error code is BUSY.
 * @retval RETURN_DEVICE_ERROR          The error code is REQUEST_RESYNCH or others.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    The error code is DECRYPT_ERROR and session_id is NOT NULL.
 **/
libspdm_return_t libspdm_handle_error_response_main(
    libspdm_context_t *spdm_context, const uint32_t *session_id,
    size_t *response_size, void **response,
    uint8_t original_request_code, uint8_t expected_response_code,
    size_t expected_response_size);

/**
 * This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the KEY_EXCHANGE request.
 * @param  slot_id                      slot_id to the KEY_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the KEY_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the KEY_EXCHANGE_RSP response.
 * @param  req_slot_id_param               req_slot_id_param from the KEY_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the KEY_EXCHANGE_RSP response.
 *
 * @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

libspdm_return_t libspdm_send_receive_key_exchange(
    libspdm_context_t *spdm_context, uint8_t measurement_hash_type,
    uint8_t slot_id, uint8_t session_policy, uint32_t *session_id,
    uint8_t *heartbeat_period,
    uint8_t *req_slot_id_param, void *measurement_hash);

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

/**
 * This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the KEY_EXCHANGE request.
 * @param  slot_id                      slot_id to the KEY_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the KEY_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the KEY_EXCHANGE_RSP response.
 * @param  req_slot_id_param               req_slot_id_param from the KEY_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the KEY_EXCHANGE_RSP response.
 * @param  requester_random_in           A buffer to hold the requester random (32 bytes) as input, if not NULL.
 * @param  requester_random              A buffer to hold the requester random (32 bytes), if not NULL.
 * @param  responder_random              A buffer to hold the responder random (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

libspdm_return_t libspdm_send_receive_key_exchange_ex(
    libspdm_context_t *spdm_context, uint8_t measurement_hash_type,
    uint8_t slot_id, uint8_t session_policy, uint32_t *session_id,
    uint8_t *heartbeat_period,
    uint8_t *req_slot_id_param, void *measurement_hash,
    const void *requester_random_in,
    void *requester_random,
    void *responder_random);

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

/**
 * This function sends FINISH and receives FINISH_RSP for SPDM finish.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    session_id to the FINISH request.
 * @param  req_slot_id_param               req_slot_id_param to the FINISH request.
 *
 * @retval RETURN_SUCCESS               The FINISH is sent and the FINISH_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
libspdm_return_t libspdm_send_receive_finish(libspdm_context_t *spdm_context,
                                             uint32_t session_id,
                                             uint8_t req_slot_id_param);

/**
 * This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the PSK_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the PSK_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the PSK_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the PSK_EXCHANGE_RSP response.
 *
 * @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

libspdm_return_t libspdm_send_receive_psk_exchange(libspdm_context_t *spdm_context,
                                                   uint8_t measurement_hash_type,
                                                   uint8_t session_policy,
                                                   uint32_t *session_id,
                                                   uint8_t *heartbeat_period,
                                                   void *measurement_hash);

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

/**
 * This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the PSK_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the PSK_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the PSK_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the PSK_EXCHANGE_RSP response.
 * @param  requester_context_in          A buffer to hold the requester context as input, if not NULL.
 * @param  requester_context_in_size     The size of requester_context_in.
 *                                      It must be 32 bytes at least, but not exceed LIBSPDM_PSK_CONTEXT_LENGTH.
 * @param  requester_context             A buffer to hold the requester context, if not NULL.
 * @param  requester_context_size        On input, the size of requester_context buffer.
 *                                      On output, the size of data returned in requester_context buffer.
 *                                      It must be 32 bytes at least.
 * @param  responder_context             A buffer to hold the responder context, if not NULL.
 * @param  responder_context_size        On input, the size of requester_context buffer.
 *                                      On output, the size of data returned in requester_context buffer.
 *                                      It could be 0 if device does not support context.
 *
 * @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

libspdm_return_t libspdm_send_receive_psk_exchange_ex(libspdm_context_t *spdm_context,
                                                      uint8_t measurement_hash_type,
                                                      uint8_t session_policy,
                                                      uint32_t *session_id,
                                                      uint8_t *heartbeat_period,
                                                      void *measurement_hash,
                                                      const void *requester_context_in,
                                                      size_t requester_context_in_size,
                                                      void *requester_context,
                                                      size_t *requester_context_size,
                                                      void *responder_context,
                                                      size_t *responder_context_size);

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

/**
 * This function sends PSK_FINISH and receives PSK_FINISH_RSP for SPDM PSK finish.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    session_id to the PSK_FINISH request.
 *
 * @retval RETURN_SUCCESS               The PSK_FINISH is sent and the PSK_FINISH_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

libspdm_return_t libspdm_send_receive_psk_finish(libspdm_context_t *spdm_context,
                                                 uint32_t session_id);

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

/**
 * This function sends END_SESSION and receives END_SESSION_ACK for SPDM session end.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    session_id to the END_SESSION request.
 * @param  end_session_attributes         end_session_attributes to the END_SESSION_ACK request.
 *
 * @retval RETURN_SUCCESS               The END_SESSION is sent and the END_SESSION_ACK is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
libspdm_return_t libspdm_send_receive_end_session(libspdm_context_t *spdm_context,
                                                  uint32_t session_id,
                                                  uint8_t end_session_attributes);

/**
 * This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.
 *
 * This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
 * and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicate if the encapsulated request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  mut_auth_requested             Indicate of the mut_auth_requested through KEY_EXCHANGE or CHALLENG response.
 * @param  req_slot_id_param               req_slot_id_param from the RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER.
 *
 * @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
libspdm_return_t libspdm_encapsulated_request(libspdm_context_t *spdm_context,
                                              const uint32_t *session_id,
                                              uint8_t mut_auth_requested,
                                              uint8_t *req_slot_id_param);

/**
 * Process the SPDM encapsulated GET_DIGESTS request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_get_encap_response_digest(void *context,
                                                   size_t request_size,
                                                   void *request,
                                                   size_t *response_size,
                                                   void *response);

/**
 * Process the SPDM encapsulated GET_CERTIFICATE request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

libspdm_return_t libspdm_get_encap_response_certificate(void *context,
                                                        size_t request_size,
                                                        void *request,
                                                        size_t *response_size,
                                                        void *response);

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

/**
 * Process the SPDM encapsulated CHALLENGE request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_get_encap_response_challenge_auth(
    void *context, size_t request_size, void *request,
    size_t *response_size, void *response);

/**
 * Process the SPDM encapsulated KEY_UPDATE request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_get_encap_response_key_update(void *context,
                                                       size_t request_size,
                                                       void *request,
                                                       size_t *response_size,
                                                       void *response);

/**
 * Send an SPDM request to a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  request_size                  size in bytes of the request data buffer.
 * @param  request                      A pointer to a destination buffer to store the request.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *                                      For normal message, requester pointer point to transport_message + transport header size
 *                                      For secured message, requester pointer will point to the scratch buffer + transport header size in spdm_context.
 *
 * @retval RETURN_SUCCESS               The SPDM request is sent successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
 **/
libspdm_return_t libspdm_send_spdm_request(libspdm_context_t *spdm_context,
                                           const uint32_t *session_id,
                                           size_t request_size, void *request);

/**
 * Receive an SPDM response from a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the response is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  response_size                 size in bytes of the response data buffer.
 * @param  response                     A pointer to a destination buffer to store the response.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *                                      For normal message, response pointer still point to original transport_message.
 *                                      For secured message, response pointer will point to the scratch buffer in spdm_context.
 *
 * @retval RETURN_SUCCESS               The SPDM response is received successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
 **/
libspdm_return_t libspdm_receive_spdm_response(libspdm_context_t *spdm_context,
                                               const uint32_t *session_id,
                                               size_t *response_size,
                                               void **response);

#endif
