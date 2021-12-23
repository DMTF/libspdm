/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_RESPONDER_LIB_INTERNAL_H__
#define __SPDM_RESPONDER_LIB_INTERNAL_H__

#include "library/spdm_responder_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "internal/libspdm_common_lib.h"

/**
  Process the SPDM request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
typedef return_status (*spdm_get_spdm_response_func)(
    IN void *spdm_context, IN uintn request_size, IN void *request,
    IN OUT uintn *response_size, OUT void *response);

/**
  Build the response when the response state is incorrect.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_code                  The SPDM request code.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_responder_handle_response_state(IN void *spdm_context,
                           IN uint8_t request_code,
                           IN OUT uintn *response_size,
                           OUT void *response);

/**
  Process the SPDM RESPONSE_IF_READY request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_respond_if_ready(IN void *spdm_context,
                         IN uintn request_size,
                         IN void *request,
                         IN OUT uintn *response_size,
                         OUT void *response);

/**
  Process the SPDM GET_VERSION request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_version(IN void *spdm_context,
                    IN uintn request_size, IN void *request,
                    IN OUT uintn *response_size,
                    OUT void *response);

/**
  Process the SPDM GET_CAPABILITIES request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_capabilities(IN void *spdm_context,
                         IN uintn request_size,
                         IN void *request,
                         IN OUT uintn *response_size,
                         OUT void *response);

/**
  Process the SPDM NEGOTIATE_ALGORITHMS request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_algorithms(IN void *spdm_context,
                       IN uintn request_size,
                       IN void *request,
                       IN OUT uintn *response_size,
                       OUT void *response);

/**
  Process the SPDM GET_DIGESTS request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

return_status spdm_get_response_digests(IN void *spdm_context,
                    IN uintn request_size, IN void *request,
                    IN OUT uintn *response_size,
                    OUT void *response);

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

/**
  Process the SPDM GET_CERTIFICATE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

return_status spdm_get_response_certificate(IN void *spdm_context,
                        IN uintn request_size,
                        IN void *request,
                        IN OUT uintn *response_size,
                        OUT void *response);

#endif /* ENABLE_SPDM_GET_CERTIFICATE*/

/**
  Process the SPDM CHALLENGE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

return_status spdm_get_response_challenge_auth(IN void *spdm_context,
                           IN uintn request_size,
                           IN void *request,
                           IN OUT uintn *response_size,
                           OUT void *response);

#endif /* #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

/**
  Process the SPDM GET_MEASUREMENT request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

return_status spdm_get_response_measurements(IN void *spdm_context,
                         IN uintn request_size,
                         IN void *request,
                         IN OUT uintn *response_size,
                         OUT void *response);

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

/**
  Process the SPDM KEY_EXCHANGE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_key_exchange(IN void *spdm_context,
                         IN uintn request_size,
                         IN void *request,
                         IN OUT uintn *response_size,
                         OUT void *response);

/**
  Process the SPDM FINISH request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_finish(IN void *spdm_context,
                       IN uintn request_size, IN void *request,
                       IN OUT uintn *response_size,
                       OUT void *response);

/**
  Process the SPDM PSK_EXCHANGE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_psk_exchange(IN void *spdm_context,
                         IN uintn request_size,
                         IN void *request,
                         IN OUT uintn *response_size,
                         OUT void *response);

/**
  Process the SPDM PSK_FINISH request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_psk_finish(IN void *spdm_context,
                       IN uintn request_size,
                       IN void *request,
                       IN OUT uintn *response_size,
                       OUT void *response);

/**
  Process the SPDM END_SESSION request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_end_session(IN void *spdm_context,
                        IN uintn request_size,
                        IN void *request,
                        IN OUT uintn *response_size,
                        OUT void *response);

/**
  Process the SPDM HEARTBEAT request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_heartbeat(IN void *spdm_context,
                      IN uintn request_size,
                      IN void *request,
                      IN OUT uintn *response_size,
                      OUT void *response);

/**
  Process the SPDM KEY_UPDATE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_key_update(IN void *spdm_context,
                       IN uintn request_size,
                       IN void *request,
                       IN OUT uintn *response_size,
                       OUT void *response);

/**
  Process the SPDM ENCAPSULATED_REQUEST request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_encapsulated_request(
    IN void *spdm_context, IN uintn request_size, IN void *request,
    IN OUT uintn *response_size, OUT void *response);

/**
  Process the SPDM ENCAPSULATED_RESPONSE_ACK request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_encapsulated_response_ack(
    IN void *spdm_context, IN uintn request_size, IN void *request,
    IN OUT uintn *response_size, OUT void *response);

/**
  Get the SPDM encapsulated GET_DIGESTS request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_get_encap_request_get_digest(IN spdm_context_t *spdm_context,
                  IN OUT uintn *encap_request_size,
                  OUT void *encap_request);

/**
  Process the SPDM encapsulated DIGESTS response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

return_status spdm_process_encap_response_digest(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT boolean *need_continue);

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

/**
  Get the SPDM encapsulated GET_CERTIFICATE request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_get_encap_request_get_certificate(IN spdm_context_t *spdm_context,
                       IN OUT uintn *encap_request_size,
                       OUT void *encap_request);

/**
  Process the SPDM encapsulated CERTIFICATE response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_process_encap_response_certificate(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT boolean *need_continue);

/**
  Get the SPDM encapsulated CHALLENGE request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status spdm_get_encap_request_challenge(IN spdm_context_t *spdm_context,
                           IN OUT uintn *encap_request_size,
                           OUT void *encap_request);

/**
  Process the SPDM encapsulated CHALLENGE_AUTH response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_process_encap_response_challenge_auth(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT boolean *need_continue);

/**
  Get the SPDM encapsulated KEY_UPDATE request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_get_encap_request_key_update(IN spdm_context_t *spdm_context,
                  IN OUT uintn *encap_request_size,
                  OUT void *encap_request);

/**
  Process the SPDM encapsulated KEY_UPDATE response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_process_encap_response_key_update(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT boolean *need_continue);

/**
  Return the GET_SPDM_RESPONSE function via request code.

  @param  request_code                  The SPDM request code.

  @return GET_SPDM_RESPONSE function according to the request code.
**/
spdm_get_spdm_response_func
spdm_get_response_func_via_request_code(IN uint8_t request_code);

/**
  This function initializes the mut_auth encapsulated state.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  mut_auth_requested             Indicate of the mut_auth_requested through KEY_EXCHANGE response.
**/
void spdm_init_mut_auth_encap_state(IN spdm_context_t *spdm_context,
                    IN uint8_t mut_auth_requested);

/**
  This function initializes the basic_mut_auth encapsulated state.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_init_basic_mut_auth_encap_state(IN spdm_context_t *spdm_context);

/**
  This function handles the encap error response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  error_code                    Indicate the error code.

  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_handle_encap_error_response_main(
    IN spdm_context_t *spdm_context, IN uint8_t error_code);

/**
  Set session_state to an SPDM secured message context and trigger callback.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicate the SPDM session ID.
  @param  session_state                 Indicate the SPDM session state.
*/
void spdm_set_session_state(IN spdm_context_t *spdm_context,
                IN uint32_t session_id,
                IN libspdm_session_state_t session_state);

/**
  Set connection_state to an SPDM context and trigger callback.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  connection_state              Indicate the SPDM connection state.
*/
void spdm_set_connection_state(IN spdm_context_t *spdm_context,
                   IN libspdm_connection_state_t connection_state);

#endif
