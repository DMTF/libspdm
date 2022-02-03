/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_COMMON_LIB_H__
#define __SPDM_COMMON_LIB_H__

#ifndef LIBSPDM_CONFIG
#include "library/spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#include "hal/base.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "hal/library/cryptlib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "library/spdm_device_secret_lib.h"


/* Connection: When a host sends messgages to a device, they create a connection.
 *             The host can and only can create one connection with one device.
 *             The host may create multiple connections with multiple devices at same time.
 *             A connection can be unique identified by the connected device.
 *             The message exchange in a connection is plain text.*/

/* Session: In one connection with one device, a host may create multiple sessions.
 *          The session starts with via KEY_EXCHANGE or PSK_EXCHANGE, and step with END_SESSION.
 *          A session can be unique identified by a session ID, returned from the device.
 *          The message exchange in a session is cipher text.*/


#define LIBSPDM_STATUS_SUCCESS 0
#define LIBSPDM_STATUS_ERROR BIT31
#define LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES (LIBSPDM_STATUS_ERROR + 0x10)
#define LIBSPDM_STATUS_ERROR_DEVICE_ERROR (LIBSPDM_STATUS_ERROR + 0x11)
#define LIBSPDM_STATUS_ERROR_TCG_EXTEND_TPM_PCR (LIBSPDM_STATUS_ERROR + 0x20)
#define LIBSPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE (LIBSPDM_STATUS_ERROR + 0x21)
#define LIBSPDM_STATUS_ERROR_CHALLENGE_FAILURE (LIBSPDM_STATUS_ERROR + 0x30)
#define LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE (LIBSPDM_STATUS_ERROR + 0x31)
#define LIBSPDM_STATUS_ERROR_NO_CERT_PROVISION (LIBSPDM_STATUS_ERROR + 0x32)
#define LIBSPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE (LIBSPDM_STATUS_ERROR + 0x40)
#define LIBSPDM_STATUS_ERROR_NO_MUTUAL_AUTH (LIBSPDM_STATUS_ERROR + 0x41)

typedef enum {

    /* SPDM parameter*/

    LIBSPDM_DATA_SPDM_VERSION,
    LIBSPDM_DATA_SECURED_MESSAGE_VERSION,

    /* SPDM capability*/

    LIBSPDM_DATA_CAPABILITY_FLAGS,
    LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
    LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE,
    LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE,

    /* SPDM algorithm setting*/

    LIBSPDM_DATA_MEASUREMENT_SPEC,
    LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
    LIBSPDM_DATA_BASE_ASYM_ALGO,
    LIBSPDM_DATA_BASE_HASH_ALGO,
    LIBSPDM_DATA_DHE_NAME_GROUP,
    LIBSPDM_DATA_AEAD_CIPHER_SUITE,
    LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
    LIBSPDM_DATA_KEY_SCHEDULE,
    LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,

    /* Connection State*/

    LIBSPDM_DATA_CONNECTION_STATE,

    /* response_state*/

    LIBSPDM_DATA_RESPONSE_STATE,

    /* Certificate info*/

    LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
    LIBSPDM_DATA_LOCAL_SLOT_COUNT,
    LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
    LIBSPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
    LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_HEARTBEAT_PERIOD,

    /* Negotiated result*/

    LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
    LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,

    /* Pre-shared key Hint
     * If PSK is present, then PSK_EXCHANGE is used.
     * Otherwise, the KEY_EXCHANGE is used.*/

    LIBSPDM_DATA_PSK_HINT,

    /* SessionData*/

    LIBSPDM_DATA_SESSION_USE_PSK,
    LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES,
    LIBSPDM_DATA_SESSION_POLICY,

    /* App context data that can be used by the application
     * during callback functions such libspdm_device_send_message_func.*/

    LIBSPDM_DATA_APP_CONTEXT_DATA,

    /* MAX*/

    LIBSPDM_DATA_MAX
} libspdm_data_type_t;

typedef enum {
    LIBSPDM_DATA_LOCATION_LOCAL,
    LIBSPDM_DATA_LOCATION_CONNECTION,
    LIBSPDM_DATA_LOCATION_SESSION,
    LIBSPDM_DATA_LOCATION_MAX
} libspdm_data_location_t;

typedef struct {
    libspdm_data_location_t location;
    /* data_type specific:
     *   session_id for the negoatiated key.
     *   SlotId for the certificate.
     *   req_slot_id + measurement_hash_type for LIBSPDM_DATA_MUT_AUTH_REQUESTED*/
    uint8_t additional_data[4];
} libspdm_data_parameter_t;

typedef enum {

    /* Before GET_VERSION/VERSION*/

    LIBSPDM_CONNECTION_STATE_NOT_STARTED,

    /* After GET_VERSION/VERSION*/

    LIBSPDM_CONNECTION_STATE_AFTER_VERSION,

    /* After GET_CAPABILITIES/CAPABILITIES*/

    LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES,

    /* After NEGOTIATE_ALGORITHMS/ALGORITHMS*/

    LIBSPDM_CONNECTION_STATE_NEGOTIATED,

    /* After GET_DIGESTS/DIGESTS*/

    LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS,

    /* After GET_CERTIFICATE/CERTIFICATE*/

    LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE,

    /* After CHALLENGE/CHALLENGE_AUTH, and ENCAP CALLENGE/CHALLENG_AUTH if MUT_AUTH is enabled.*/

    LIBSPDM_CONNECTION_STATE_AUTHENTICATED,

    /* MAX*/

    LIBSPDM_CONNECTION_STATE_MAX
} libspdm_connection_state_t;

typedef enum {

    /* Normal response.*/

    LIBSPDM_RESPONSE_STATE_NORMAL,

    /* Other component is busy.*/

    LIBSPDM_RESPONSE_STATE_BUSY,

    /* Hardware is not ready.*/

    LIBSPDM_RESPONSE_STATE_NOT_READY,

    /* Firmware Update is done. Need resync.*/

    LIBSPDM_RESPONSE_STATE_NEED_RESYNC,

    /* Processing Encapsulated message.*/

    LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP,

    /* MAX*/

    LIBSPDM_RESPONSE_STATE_MAX
} libspdm_response_state_t;

/**
 * Set an SPDM context data.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  data_type                     Type of the SPDM context data.
 * @param  parameter                    Type specific parameter of the SPDM context data.
 * @param  data                         A pointer to the SPDM context data.
 * @param  data_size                     size in bytes of the SPDM context data.
 *
 * @retval RETURN_SUCCESS               The SPDM context data is set successfully.
 * @retval RETURN_INVALID_PARAMETER     The data is NULL or the data_type is zero.
 * @retval RETURN_UNSUPPORTED           The data_type is unsupported.
 * @retval RETURN_ACCESS_DENIED         The data_type cannot be set.
 * @retval RETURN_NOT_READY             data is not ready to set.
 **/
return_status libspdm_set_data(IN void *spdm_context,
                               IN libspdm_data_type_t data_type,
                               IN libspdm_data_parameter_t *parameter, IN void *data,
                               IN uintn data_size);

/**
 * Get an SPDM context data.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  data_type                     Type of the SPDM context data.
 * @param  parameter                    Type specific parameter of the SPDM context data.
 * @param  data                         A pointer to the SPDM context data.
 * @param  data_size                     size in bytes of the SPDM context data.
 *                                     On input, it means the size in bytes of data buffer.
 *                                     On output, it means the size in bytes of copied data buffer if RETURN_SUCCESS,
 *                                     and means the size in bytes of desired data buffer if RETURN_BUFFER_TOO_SMALL.
 *
 * @retval RETURN_SUCCESS               The SPDM context data is set successfully.
 * @retval RETURN_INVALID_PARAMETER     The data_size is NULL or the data is NULL and *data_size is not zero.
 * @retval RETURN_UNSUPPORTED           The data_type is unsupported.
 * @retval RETURN_NOT_FOUND             The data_type cannot be found.
 * @retval RETURN_NOT_READY             The data is not ready to return.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
return_status libspdm_get_data(IN void *spdm_context,
                               IN libspdm_data_type_t data_type,
                               IN libspdm_data_parameter_t *parameter,
                               IN OUT void *data, IN OUT uintn *data_size);

/**
 * Get the last error of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return Last error of an SPDM context.
 */
uint32_t libspdm_get_last_error(IN void *spdm_context);

/**
 * Get the last SPDM error struct of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  last_spdm_error                Last SPDM error struct of an SPDM context.
 */
void libspdm_get_last_spdm_error_struct(IN void *spdm_context,
                                        OUT libspdm_error_struct_t *last_spdm_error);

/**
 * Set the last SPDM error struct of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  last_spdm_error                Last SPDM error struct of an SPDM context.
 */
void libspdm_set_last_spdm_error_struct(IN void *spdm_context,
                                        IN libspdm_error_struct_t *last_spdm_error);

/**
 * Initialize an SPDM context.
 *
 * The size in bytes of the spdm_context can be returned by libspdm_get_context_size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS       context is initialized.
 * @retval RETURN_DEVICE_ERROR  context initialization failed.
 */
return_status libspdm_init_context(IN void *context);

/**
 * Reset an SPDM context.
 *
 * The size in bytes of the spdm_context can be returned by libspdm_get_context_size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 */
void libspdm_reset_context(IN void *context);

/**
 * Return the size in bytes of the SPDM context.
 *
 * @return the size in bytes of the SPDM context.
 **/
uintn libspdm_get_context_size(void);

/**
 * Send an SPDM transport layer message to a device.
 *
 * The message is an SPDM message with transport layer wrapper,
 * or a secured SPDM message with transport layer wrapper.
 *
 * For requester, the message is a transport layer SPDM request.
 * For responder, the message is a transport layer SPDM response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 * @param  timeout                      The timeout, in 100ns units, to use for the execution
 *                                     of the message. A timeout value of 0
 *                                     means that this function will wait indefinitely for the
 *                                     message to execute. If timeout is greater
 *                                     than zero, then this function will return RETURN_TIMEOUT if the
 *                                     time required to execute the message is greater
 *                                     than timeout.
 *
 * @retval RETURN_SUCCESS               The SPDM message is sent successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is sent to the device.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 * @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
 *                                     to execute.
 **/
typedef return_status (*libspdm_device_send_message_func)(IN void *spdm_context,
                                                          IN uintn message_size,
                                                          IN void *message,
                                                          IN uint64_t timeout);

/**
 * Receive an SPDM transport layer message from a device.
 *
 * The message is an SPDM message with transport layer wrapper,
 * or a secured SPDM message with transport layer wrapper.
 *
 * For requester, the message is a transport layer SPDM response.
 * For responder, the message is a transport layer SPDM request.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 * @param  timeout                      The timeout, in 100ns units, to use for the execution
 *                                     of the message. A timeout value of 0
 *                                     means that this function will wait indefinitely for the
 *                                     message to execute. If timeout is greater
 *                                     than zero, then this function will return RETURN_TIMEOUT if the
 *                                     time required to execute the message is greater
 *                                     than timeout.
 *
 * @retval RETURN_SUCCESS               The SPDM message is received successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is received from the device.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL, message_size is NULL or
 *                                     the *message_size is zero.
 * @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
 *                                     to execute.
 **/
typedef return_status (*libspdm_device_receive_message_func)(
    IN void *spdm_context, IN OUT uintn *message_size, IN OUT void *message,
    IN uint64_t timeout);

/**
 * Register SPDM device input/output functions.
 *
 * This function must be called after libspdm_init_context, and before any SPDM communication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  send_message                  The fuction to send an SPDM transport layer message.
 * @param  receive_message               The fuction to receive an SPDM transport layer message.
 **/
void libspdm_register_device_io_func(
    IN void *spdm_context, IN libspdm_device_send_message_func send_message,
    IN libspdm_device_receive_message_func receive_message);

/**
 * Encode an SPDM or APP message to a transport layer message.
 *
 * For normal SPDM message, it adds the transport layer wrapper.
 * For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
 * For secured APP message, it encrypts a secured message then adds the transport layer wrapper.
 *
 * The APP message is encoded to a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
typedef return_status (*libspdm_transport_encode_message_func)(
    IN void *spdm_context, IN uint32_t *session_id, IN bool is_app_message,
    IN bool is_requester, IN uintn spdm_message_size,
    IN void *spdm_message, IN OUT uintn *transport_message_size,
    OUT void *transport_message);

/**
 * Decode an SPDM or APP message from a transport layer message.
 *
 * For normal SPDM message, it removes the transport layer wrapper,
 * For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 * For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 *
 * The APP message is decoded from a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *
 * @retval RETURN_SUCCESS               The message is decoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 * @retval RETURN_UNSUPPORTED           The transport_message is unsupported.
 **/
typedef return_status (*libspdm_transport_decode_message_func)(
    IN void *spdm_context, OUT uint32_t **session_id,
    OUT bool *is_app_message, IN bool is_requester,
    IN uintn transport_message_size, IN void *transport_message,
    IN OUT uintn *message_size, OUT void *message);

/**
 * Register SPDM transport layer encode/decode functions for SPDM or APP messages.
 *
 * This function must be called after libspdm_init_context, and before any SPDM communication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  transport_encode_message       The fuction to encode an SPDM or APP message to a transport layer message.
 * @param  transport_decode_message       The fuction to decode an SPDM or APP message from a transport layer message.
 **/
void libspdm_register_transport_layer_func(
    IN void *spdm_context,
    IN libspdm_transport_encode_message_func transport_encode_message,
    IN libspdm_transport_decode_message_func transport_decode_message);

/**
 * Verify a SPDM cert chain in a slot.
 *
 * This function shall verify:
 *  1) The integrity of the certificate chain. (Root Cert Hash->Root Cert->Cert Chain)
 *  2) The trust anchor. (Root Cert Hash/Root cert matches the trust anchor)
 *
 * The function shall check the negotiated hash algorithm to check root cert hash.
 * The function shall check the negotiated (req) asym algorithm to determine if it is right cert chain.
 *
 * The function returns error if either of above is not satisfied.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_id                       The number of slot for the certificate chain.
 * @param  cert_chain_size               Indicate the size in bytes of the certificate chain.
 * @param  cert_chain                    A pointer to the buffer storing the certificate chain
 *                                      returned from GET_CERTIFICATE. It starts with spdm_cert_chain_t.
 * @param  trust_anchor                  A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
 * @param  trust_anchor_size             A buffer to hold the trust_anchor_size, if not NULL.
 *
 * @retval RETURN_SUCCESS                The cert chain verification pass.
 * @retval RETURN_SECURIY_VIOLATION      The cert chain verification fail.
 **/
typedef return_status (*libspdm_verify_spdm_cert_chain_func)(
    IN void *spdm_context, IN uint8_t slot_id,
    IN uintn cert_chain_size, IN void *cert_chain,
    OUT void **trust_anchor OPTIONAL,
    OUT uintn *trust_anchor_size OPTIONAL);

/**
 * Register SPDM certificate verification functions for SPDM GET_CERTIFICATE in requester or responder.
 * It is called after GET_CERTIFICATE gets a full certificate chain from peer.
 *
 * If it is NOT registered, the default verification in SPDM lib will be used. It verifies:
 *    1) The integrity of the certificate chain, (Root Cert Hash->Root Cert->Cert Chain), according to X.509.
 *  2) The trust anchor, according LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT or LIBSPDM_DATA_PEER_PUBLIC_CERT_CHAIN.
 * If it is registered, SPDM lib will use this function to verify the certificate.
 *
 * This function must be called after libspdm_init_context, and before any SPDM communication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  verify_certificate            The fuction to verify an SPDM certificate after GET_CERTIFICATE.
 **/
void libspdm_register_verify_spdm_cert_chain_func(
    IN void *spdm_context,
    IN libspdm_verify_spdm_cert_chain_func verify_spdm_cert_chain);

/**
 * Reset message A cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_a(IN void *spdm_context);

/**
 * Reset message B cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_b(IN void *spdm_context);

/**
 * Reset message C cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_c(IN void *spdm_context);

/**
 * Reset message MutB cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_mut_b(IN void *spdm_context);

/**
 * Reset message MutC cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_mut_c(IN void *spdm_context);

/**
 * Reset message M cache in SPDM context.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 **/
void libspdm_reset_message_m(IN void *context, IN void *session_info);

/**
 * Reset message K cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_info              A pointer to the SPDM session context.
 **/
void libspdm_reset_message_k(IN void *context, IN void *spdm_session_info);

/**
 * Reset message F cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_info              A pointer to the SPDM session context.
 **/
void libspdm_reset_message_f(IN void *context, IN void *spdm_session_info);

/**
 * Append message A cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_a(IN void *spdm_context, IN void *message,
                                       IN uintn message_size);

/**
 * Append message B cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_b(IN void *spdm_context, IN void *message,
                                       IN uintn message_size);

/**
 * Append message C cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_c(IN void *spdm_context, IN void *message,
                                       IN uintn message_size);

/**
 * Append message MutB cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_mut_b(IN void *spdm_context, IN void *message,
                                           IN uintn message_size);

/**
 * Append message MutC cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_mut_c(IN void *spdm_context, IN void *message,
                                           IN uintn message_size);

/**
 * Append message M cache in SPDM context.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_m(IN void *context, IN void *session_info,
                                       IN void *message, IN uintn message_size);

/**
 * Append message K cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_info              A pointer to the SPDM session context.
 * @param  is_requester                  Indicate of the key generation for a requester or a responder.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_k(IN void *context, IN void *spdm_session_info,
                                       IN bool is_requester, IN void *message,
                                       IN uintn message_size);

/**
 * Append message F cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_info              A pointer to the SPDM session context.
 * @param  is_requester                  Indicate of the key generation for a requester or a responder.
 * @param  message                      message buffer.
 * @param  message_size                  size in bytes of message buffer.
 *
 * @return RETURN_SUCCESS          message is appended.
 * @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
 **/
return_status libspdm_append_message_f(IN void *context, IN void *spdm_session_info,
                                       IN bool is_requester, IN void *message,
                                       IN uintn message_size);

/**
 * This function gets the session info via session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return session info.
 **/
void *libspdm_get_session_info_via_session_id(IN void *spdm_context,
                                              IN uint32_t session_id);

/**
 * This function gets the secured message context via session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return secured message context.
 **/
void *libspdm_get_secured_message_context_via_session_id(IN void *spdm_context,
                                                         IN uint32_t session_id);

/**
 * This function gets the secured message context via session ID.
 *
 * @param  spdm_session_info              A pointer to the SPDM context.
 *
 * @return secured message context.
 **/
void *
libspdm_get_secured_message_context_via_session_info(IN void *spdm_session_info);

/**
 * This function assigns a new session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return session info associated with this new session ID.
 **/
void *libspdm_assign_session_id(IN void *spdm_context, IN uint32_t session_id,
                                IN bool use_psk);

/**
 * This function frees a session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 **/
void libspdm_free_session_id(IN void *spdm_context, IN uint32_t session_id);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates current TH data with message A and message K.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
 * @param  th_data_buffer_size             size in bytes of the th_data_buffer
 * @param  th_data_buffer                 The buffer to store the th_data_buffer
 *
 * @retval RETURN_SUCCESS  current TH data is calculated.
 */
bool libspdm_calculate_th_for_exchange(
    IN void *spdm_context, IN void *spdm_session_info,
    IN uint8_t *cert_chain_buffer, OPTIONAL IN uintn cert_chain_buffer_size,
    OPTIONAL IN OUT uintn *th_data_buffer_size, OUT void *th_data_buffer);
#else
/*
 * This function calculates current TH hash with message A and message K.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hash_buffer_size             size in bytes of the th_hash_buffer
 * @param  th_hash_buffer                 The buffer to store the th_hash_buffer
 *
 * @retval RETURN_SUCCESS  current TH hash is calculated.
 */
bool libspdm_calculate_th_hash_for_exchange(
    IN void *context, IN void *spdm_session_info,
    OPTIONAL IN OUT uintn *th_hash_buffer_size, OUT void *th_hash_buffer);

/*
 * This function calculates current TH hmac with message A and message K, with response finished_key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
 * @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer
 *
 * @retval RETURN_SUCCESS  current TH hmac is calculated.
 */
bool libspdm_calculate_th_hmac_for_exchange_rsp(
    IN void *context, IN void *spdm_session_info, IN bool is_requester,
    OPTIONAL IN OUT uintn *th_hmac_buffer_size, OUT void *th_hmac_buffer);
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates current TH data with message A, message K and message F.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
 * @param  mut_cert_chain_buffer             Certitiface chain buffer with spdm_cert_chain_t header in mutual authentication.
 * @param  mut_cert_chain_buffer_size         size in bytes of the certitiface chain buffer in mutual authentication.
 * @param  th_data_buffer_size             size in bytes of the th_data_buffer
 * @param  th_data_buffer                 The buffer to store the th_data_buffer
 *
 * @retval RETURN_SUCCESS  current TH data is calculated.
 */
bool libspdm_calculate_th_for_finish(IN void *spdm_context,
                                        IN void *spdm_session_info,
                                        IN uint8_t *cert_chain_buffer,
                                        OPTIONAL IN uintn cert_chain_buffer_size,
                                        OPTIONAL IN uint8_t *mut_cert_chain_buffer,
                                        OPTIONAL IN uintn mut_cert_chain_buffer_size,
                                        OPTIONAL IN OUT uintn *th_data_buffer_size,
                                        OUT void *th_data_buffer);
#else
/*
 * This function calculates current TH hash with message A, message K and message F.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hash_buffer_size             size in bytes of the th_hash_buffer
 * @param  th_hash_buffer                 The buffer to store the th_hash_buffer
 *
 * @retval RETURN_SUCCESS  current TH hash is calculated.
 */
bool libspdm_calculate_th_hash_for_finish(IN void *spdm_context,
                                             IN void *spdm_session_info,
                                             OPTIONAL IN OUT uintn *th_hash_buffer_size,
                                             OUT void *th_hash_buffer);

/*
 * This function calculates current TH hmac with message A, message K and message F, with response finished_key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
 * @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer
 *
 * @retval RETURN_SUCCESS  current TH hmac is calculated.
 */
bool libspdm_calculate_th_hmac_for_finish_rsp(IN void *spdm_context,
                                                 IN void *spdm_session_info,
                                                 OPTIONAL IN OUT uintn *th_hmac_buffer_size,
                                                 OUT void *th_hmac_buffer);

/*
 * This function calculates current TH hmac with message A, message K and message F, with request finished_key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
 * @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer
 *
 * @retval RETURN_SUCCESS  current TH hmac is calculated.
 */
bool libspdm_calculate_th_hmac_for_finish_req(IN void *spdm_context,
                                                 IN void *spdm_session_info,
                                                 OPTIONAL IN OUT uintn *th_hmac_buffer_size,
                                                 OUT void *th_hmac_buffer);
#endif

/*
 * This function calculates th1 hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  is_requester                  Indicate of the key generation for a requester or a responder.
 * @param  th1_hash_data                  th1 hash
 *
 * @retval RETURN_SUCCESS  th1 hash is calculated.
 */
return_status libspdm_calculate_th1_hash(IN void *spdm_context,
                                         IN void *spdm_session_info,
                                         IN bool is_requester,
                                         OUT uint8_t *th1_hash_data);

/*
 * This function calculates th2 hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  is_requester                  Indicate of the key generation for a requester or a responder.
 * @param  th1_hash_data                  th2 hash
 *
 * @retval RETURN_SUCCESS  th2 hash is calculated.
 */
return_status libspdm_calculate_th2_hash(IN void *spdm_context,
                                         IN void *spdm_session_info,
                                         IN bool is_requester,
                                         OUT uint8_t *th2_hash_data);

/**
 * This function returns peer certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.
 *
 * @retval true  Peer certificate chain buffer including spdm_cert_chain_t header is returned.
 * @retval false Peer certificate chain buffer including spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_peer_cert_chain_buffer(IN void *spdm_context,
                                           OUT void **cert_chain_buffer,
                                           OUT uintn *cert_chain_buffer_size);

/**
 * This function returns peer certificate chain data without spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size            size in bytes of the certitiface chain data.
 *
 * @retval true  Peer certificate chain data without spdm_cert_chain_t header is returned.
 * @retval false Peer certificate chain data without spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_peer_cert_chain_data(IN void *spdm_context,
                                         OUT void **cert_chain_data,
                                         OUT uintn *cert_chain_data_size);

/**
 * This function returns local used certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.
 *
 * @retval true  Local used certificate chain buffer including spdm_cert_chain_t header is returned.
 * @retval false Local used certificate chain buffer including spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_local_cert_chain_buffer(IN void *spdm_context,
                                            OUT void **cert_chain_buffer,
                                            OUT uintn *cert_chain_buffer_size);

/**
 * This function returns local used certificate chain data without spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size            size in bytes of the certitiface chain data.
 *
 * @retval true  Local used certificate chain data without spdm_cert_chain_t header is returned.
 * @retval false Local used certificate chain data without spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_local_cert_chain_data(IN void *spdm_context,
                                          OUT void **cert_chain_data,
                                          OUT uintn *cert_chain_data_size);

/**
 * Reads a 24-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 24-bit value that may be unaligned.
 *
 * @return The 24-bit value read from buffer.
 **/
uint32_t libspdm_read_uint24(IN uint8_t *buffer);

/**
 * Writes a 24-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 24-bit value that may be unaligned.
 * @param  value   24-bit value to write to buffer.
 *
 * @return The 24-bit value to write to buffer.
 **/
void libspdm_write_uint24(IN uint8_t *buffer, IN uint32_t value);

#endif
