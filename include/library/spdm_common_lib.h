/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_COMMON_LIB_H
#define SPDM_COMMON_LIB_H

#ifndef LIBSPDM_CONFIG
#include "library/spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#if defined(LIBSPDM_ENABLE_SET_CERTIFICATE_CAP) && \
    !defined(LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP)
#ifdef _MSC_VER
#pragma message("LIBSPDM_ENABLE_SET_CERTIFICATE_CAP is deprecated. Use " \
    "LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP instead. This warning will be removed with " \
    "the next release.")
#else
#warning LIBSPDM_ENABLE_SET_CERTIFICATE_CAP is deprecated. Use \
    LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP instead. This warning will be removed with \
    the next release.
#endif /* _MSC_VER */
#endif /* defined(LIBSPDM_ENABLE_SET_CERTIFICATE_CAP) */

#if defined(LIBSPDM_ENABLE_CHUNK_CAP) && !defined(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP)
#ifdef _MSC_VER
#pragma message("LIBSPDM_ENABLE_CHUNK_CAP is deprecated. Use LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP " \
    "instead. This warning will be removed with the next release.")
#else
#warning LIBSPDM_ENABLE_CHUNK_CAP is deprecated. Use LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP \
    instead. This warning will be removed with the next release.
#endif /* _MSC_VER */
#endif /* defined(LIBSPDM_ENABLE_CHUNK_CAP) */

#include "hal/base.h"
#include "library/spdm_secured_message_lib.h"
#include "library/spdm_return_status.h"

/* Connection: When a host sends messgages to a device, they create a connection.
 *             The host can and only can create one connection with one device.
 *             The host may create multiple connections with multiple devices at same time.
 *             A connection can be unique identified by the connected device.
 *             The message exchange in a connection is plain text.*/

/* Session: In one connection with one device, a host may create multiple sessions.
 *          The session starts with via KEY_EXCHANGE or PSK_EXCHANGE, and step with END_SESSION.
 *          A session can be unique identified by a session ID, returned from the device.
 *          The message exchange in a session is cipher text.*/

typedef enum {

    /* SPDM parameter*/

    LIBSPDM_DATA_SPDM_VERSION,
    LIBSPDM_DATA_SECURED_MESSAGE_VERSION,

    /* SPDM capability*/

    LIBSPDM_DATA_CAPABILITY_FLAGS,
    LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
    LIBSPDM_DATA_CAPABILITY_RTT_US,
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
    /* LIBSPDM_DATA_LOCAL_SLOT_COUNT is deprecated. Do not use it. Reserved only. */
    LIBSPDM_DATA_LOCAL_SLOT_COUNT,
    LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
    LIBSPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
    LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_HEARTBEAT_PERIOD,

    /* Negotiated result*/

    LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
    LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
    LIBSPDM_DATA_PEER_SLOT_MASK,
    LIBSPDM_DATA_PEER_TOTAL_DIGEST_BUFFER,

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

    /**
     * The LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY 0x00000001 control to generate SPDM_ERROR_CODE_DECRYPT_ERROR response or drop the request silently.
     * If the 0x00000001 is not set, generate SPDM_ERROR_CODE_DECRYPT_ERROR response.
     * If the 0x00000001 set, drop the request silently.
     **/
    LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY,

    /* VCA cached for CACHE_CAP in 1.2 for transcript.*/
    LIBSPDM_DATA_VCA_CACHE,
    /* MAX*/

    LIBSPDM_DATA_MAX
} libspdm_data_type_t;

/**
 * It controls to generate SPDM_ERROR_CODE_DECRYPT_ERROR response or drop the request silently.
 * If the 0x1 is not set, generate SPDM_ERROR_CODE_DECRYPT_ERROR response.
 * If the 0x1 set, drop the request silently.
 **/
#define LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR 0x1

#define LIBSPDM_MSG_LOG_STATUS_BUFFER_FULL 1
#define LIBSPDM_MSG_LOG_MODE_ENABLE 1

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
libspdm_return_t libspdm_set_data(void *spdm_context,
                                  libspdm_data_type_t data_type,
                                  const libspdm_data_parameter_t *parameter, void *data,
                                  size_t data_size);

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
libspdm_return_t libspdm_get_data(void *spdm_context,
                                  libspdm_data_type_t data_type,
                                  const libspdm_data_parameter_t *parameter,
                                  void *data, size_t *data_size);

/**
 * Get the last SPDM error struct of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  last_spdm_error                Last SPDM error struct of an SPDM context.
 */
void libspdm_get_last_spdm_error_struct(void *spdm_context,
                                        libspdm_error_struct_t *last_spdm_error);

/**
 * Set the last SPDM error struct of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  last_spdm_error                Last SPDM error struct of an SPDM context.
 */
void libspdm_set_last_spdm_error_struct(void *spdm_context,
                                        libspdm_error_struct_t *last_spdm_error);

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
libspdm_return_t libspdm_init_context(void *context);

/**
 * Reset an SPDM context.
 *
 * The size in bytes of the spdm_context can be returned by libspdm_get_context_size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 */
void libspdm_reset_context(void *context);

/**
 * Return the size in bytes of the SPDM context.
 *
 * @return the size in bytes of the SPDM context.
 **/
size_t libspdm_get_context_size(void);

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
 *                                     The message pointer shall be inside of
 *                                     [msg_buf_ptr, msg_buf_ptr + max_msg_size] from
 *                                     acquired sender_buffer.
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
 * @retval RETURN_TIMEOUT              A timeout occurred while waiting for the SPDM message
 *                                     to execute.
 **/
typedef libspdm_return_t (*libspdm_device_send_message_func)(void *spdm_context,
                                                             size_t message_size,
                                                             const void *message,
                                                             uint64_t timeout);

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
 *                                     On input, the message pointer shall be msg_buf_ptr from
 *                                     acquired receiver_buffer.
 *                                     On output, the message pointer shall be inside of
 *                                     [msg_buf_ptr, msg_buf_ptr + max_msg_size] from
 *                                     acquired receiver_buffer.
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
 * @retval RETURN_TIMEOUT              A timeout occurred while waiting for the SPDM message
 *                                     to execute.
 **/
typedef libspdm_return_t (*libspdm_device_receive_message_func)(
    void *spdm_context, size_t *message_size, void **message,
    uint64_t timeout);

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
    void *spdm_context, libspdm_device_send_message_func send_message,
    libspdm_device_receive_message_func receive_message);

/**
 * Acquire a device sender buffer for transport layer message.
 *
 * The max_msg_size must be larger than
 * MAX (non-secure Transport Message Header Size +
 *          SPDM_CAPABILITIES.DataTransferSize +
 *          max alignment pad size (transport specific),
 *      secure Transport Message Header Size +
 *          sizeof(spdm_secured_message_a_data_header1_t) +
 *          length of sequence_number (transport specific) +
 *          sizeof(spdm_secured_message_a_data_header2_t) +
 *          sizeof(spdm_secured_message_cipher_header_t) +
 *          App Message Header Size (transport specific) +
 *          SPDM_CAPABILITIES.DataTransferSize +
 *          maximum random data size (transport specific) +
 *          AEAD MAC size (16) +
 *          max alignment pad size (transport specific))
 *
 *   For MCTP,
 *          Transport Message Header Size = sizeof(mctp_message_header_t)
 *          length of sequence_number = 2
 *          App Message Header Size = sizeof(mctp_message_header_t)
 *          maximum random data size = MCTP_MAX_RANDOM_NUMBER_COUNT
 *          max alignment pad size = 0
 *   For PCI_DOE,
 *          Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *          length of sequence_number = 0
 *          App Message Header Size = 0
 *          maximum random data size = 0
 *          max alignment pad size = 3
 *
 * @param  context                       A pointer to the SPDM context.
 * @param  max_msg_size                  size in bytes of the maximum size of sender buffer.
 * @param  msg_buf_ptr                   A pointer to a sender buffer.
 *
 * @retval RETURN_SUCCESS               The sender buffer is acquired.
 **/
typedef libspdm_return_t (*libspdm_device_acquire_sender_buffer_func)(
    void *context, size_t *max_msg_size, void **msg_buf_ptr);

/**
 * Release a device sender buffer for transport layer message.
 *
 * @param  context                       A pointer to the SPDM context.
 * @param  msg_buf_ptr                   A pointer to a sender buffer.
 *
 * @retval RETURN_SUCCESS               The sender buffer is Released.
 **/
typedef void (*libspdm_device_release_sender_buffer_func)(
    void *context, const void *msg_buf_ptr);

/**
 * Acquire a device receiver buffer for transport layer message.
 *
 * The max_msg_size must be larger than
 * MAX (non-secure Transport Message Header Size +
 *          SPDM_CAPABILITIES.DataTransferSize +
 *          max alignment pad size (transport specific),
 *      secure Transport Message Header Size +
 *          sizeof(spdm_secured_message_a_data_header1_t) +
 *          length of sequence_number (transport specific) +
 *          sizeof(spdm_secured_message_a_data_header2_t) +
 *          sizeof(spdm_secured_message_cipher_header_t) +
 *          App Message Header Size (transport specific) +
 *          SPDM_CAPABILITIES.DataTransferSize +
 *          maximum random data size (transport specific) +
 *          AEAD MAC size (16) +
 *          max alignment pad size (transport specific))
 *
 *   For MCTP,
 *          Transport Message Header Size = sizeof(mctp_message_header_t)
 *          length of sequence_number = 2
 *          App Message Header Size = sizeof(mctp_message_header_t)
 *          maximum random data size = MCTP_MAX_RANDOM_NUMBER_COUNT
 *          max alignment pad size = 0
 *   For PCI_DOE,
 *          Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *          length of sequence_number = 0
 *          App Message Header Size = 0
 *          maximum random data size = 0
 *          max alignment pad size = 3
 *
 * @param  context                       A pointer to the SPDM context.
 * @param  max_msg_size                  size in bytes of the maximum size of receiver buffer.
 * @param  msg_buf_pt                    A pointer to a receiver buffer.
 *
 * @retval RETURN_SUCCESS               The receiver buffer is acquired.
 **/
typedef libspdm_return_t (*libspdm_device_acquire_receiver_buffer_func)(
    void *context, size_t *max_msg_size, void **msg_buf_ptr);

/**
 * Release a device receiver buffer for transport layer message.
 *
 * @param  context                       A pointer to the SPDM context.
 * @param  msg_buf_ptr                   A pointer to a receiver buffer.
 *
 * @retval RETURN_SUCCESS               The receiver buffer is Released.
 **/
typedef void (*libspdm_device_release_receiver_buffer_func)(
    void *context, const void *msg_buf_ptr);

/**
 * Register SPDM device buffer management functions.
 *
 * This function must be called after libspdm_init_context, and before any SPDM communication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  acquire_sender_buffer         The fuction to acquire transport layer sender buffer.
 * @param  release_sender_buffer         The fuction to release transport layer sender buffer.
 * @param  acquire_receiver_buffer       The fuction to acquire transport layer receiver buffer.
 * @param  release_receiver_buffer       The fuction to release transport layer receiver buffer.
 **/
void libspdm_register_device_buffer_func(
    void *spdm_context,
    libspdm_device_acquire_sender_buffer_func acquire_sender_buffer,
    libspdm_device_release_sender_buffer_func release_sender_buffer,
    libspdm_device_acquire_receiver_buffer_func acquire_receiver_buffer,
    libspdm_device_release_receiver_buffer_func release_receiver_buffer);

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
 *                                      For normal message, it shall point to the acquired sender buffer.
 *                                      For secured message, it shall point to the scratch buffer in spdm_context.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *                                      On input, it shall be msg_buf_ptr from sender buffer.
 *                                      On output, it will point to acquired sender buffer.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
typedef libspdm_return_t (*libspdm_transport_encode_message_func)(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    bool is_requester, size_t message_size,
    void *message, size_t *transport_message_size,
    void **transport_message);

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
 *                                      For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                      On input, it shall point to the scratch buffer in spdm_context.
 *                                      On output, for normal message, it will point to the original receiver buffer.
 *                                      On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval RETURN_SUCCESS               The message is decoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 * @retval RETURN_UNSUPPORTED           The transport_message is unsupported.
 **/
typedef libspdm_return_t (*libspdm_transport_decode_message_func)(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_requester,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message);

/**
 * Return the maximum transport layer message header size.
 *   Transport Message Header Size + sizeof(spdm_secured_message_cipher_header_t))
 *
 *   For MCTP, Transport Message Header Size = sizeof(mctp_message_header_t)
 *   For PCI_DOE, Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return size of maximum transport layer message header size
 **/
typedef uint32_t (*libspdm_transport_get_header_size_func)(
    void *spdm_context);

/**
 * Register SPDM transport layer encode/decode functions for SPDM or APP messages.
 *
 * This function must be called after libspdm_init_context, and before any SPDM communication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  transport_encode_message       The fuction to encode an SPDM or APP message to a transport layer message.
 * @param  transport_decode_message       The fuction to decode an SPDM or APP message from a transport layer message.
 * @param  transport_get_header_size      The fuction to get the maximum transport layer message header size.
 **/
void libspdm_register_transport_layer_func(
    void *spdm_context,
    libspdm_transport_encode_message_func transport_encode_message,
    libspdm_transport_decode_message_func transport_decode_message,
    libspdm_transport_get_header_size_func transport_get_header_size);

/**
 * Get the size of required scratch buffer.
 *
 * The SPDM integrator must call libspdm_get_sizeof_required_scratch_buffer to get the size,
 * then allocate enough scratch buffer and call libspdm_set_scratch_buffer().
 *
 * @param  context                  A pointer to the SPDM context.
 *
 * @return the size of required scratch buffer.
 **/
size_t libspdm_get_sizeof_required_scratch_buffer (
    void *context);

/**
 * Set the scratch buffer.
 *
 * The size of scratch buffer must be larger than the value returned in
 * libspdm_get_sizeof_required_scratch_buffer().
 *
 * This function must be called after libspdm_init_context, and before any SPDM communication.
 *
 * @param  context                  A pointer to the SPDM context.
 * @param  scratch_buffer           Buffer address of the scratch buffer.
 * @param  scratch_buffer_size      Size of the scratch buffer.
 *
 **/
void libspdm_set_scratch_buffer (
    void *context,
    void *scratch_buffer,
    size_t scratch_buffer_size);

/**
 * Get the scratch buffer.
 *
 * @param  context                  A pointer to the SPDM context.
 * @param  scratch_buffer           Buffer address of the scratch buffer.
 * @param  scratch_buffer_size      Size of the scratch buffer.
 *
 **/
void libspdm_get_scratch_buffer (
    void *spdm_context,
    void **scratch_buffer,
    size_t *scratch_buffer_size);

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
typedef bool (*libspdm_verify_spdm_cert_chain_func)(
    void *spdm_context, uint8_t slot_id,
    size_t cert_chain_size, const void *cert_chain,
    const void **trust_anchor,
    size_t *trust_anchor_size);

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
    void *spdm_context,
    const libspdm_verify_spdm_cert_chain_func verify_spdm_cert_chain);

/**
 * Reset message A cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_a(void *spdm_context);

/**
 * Reset message B cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_b(void *spdm_context);

/**
 * Reset message C cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_c(void *spdm_context);

/**
 * Reset message MutB cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_mut_b(void *spdm_context);

/**
 * Reset message MutC cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 **/
void libspdm_reset_message_mut_c(void *spdm_context);

/**
 * Reset message M cache in SPDM context.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 **/
void libspdm_reset_message_m(void *context, void *session_info);

/**
 * Reset message K cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_info              A pointer to the SPDM session context.
 **/
void libspdm_reset_message_k(void *context, void *spdm_session_info);

/**
 * Reset message F cache in SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_info              A pointer to the SPDM session context.
 **/
void libspdm_reset_message_f(void *context, void *spdm_session_info);

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
libspdm_return_t libspdm_append_message_a(void *spdm_context, const void *message,
                                          size_t message_size);

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
libspdm_return_t libspdm_append_message_b(void *spdm_context, const void *message,
                                          size_t message_size);

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
libspdm_return_t libspdm_append_message_c(void *spdm_context, const void *message,
                                          size_t message_size);

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
libspdm_return_t libspdm_append_message_mut_b(void *spdm_context, const void *message,
                                              size_t message_size);

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
libspdm_return_t libspdm_append_message_mut_c(void *spdm_context, const void *message,
                                              size_t message_size);

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
libspdm_return_t libspdm_append_message_m(void *context, void *session_info,
                                          const void *message, size_t message_size);

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
libspdm_return_t libspdm_append_message_k(void *context, void *spdm_session_info,
                                          bool is_requester, const void *message,
                                          size_t message_size);

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
libspdm_return_t libspdm_append_message_f(void *context, void *spdm_session_info,
                                          bool is_requester, const void *message,
                                          size_t message_size);

/**
 * This function gets the session info via session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return session info.
 **/
void *libspdm_get_session_info_via_session_id(void *spdm_context,
                                              uint32_t session_id);

/**
 * This function gets the secured message context via session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return secured message context.
 **/
void *libspdm_get_secured_message_context_via_session_id(void *spdm_context,
                                                         uint32_t session_id);

/**
 * This function gets the secured message context via session ID.
 *
 * @param  spdm_session_info              A pointer to the SPDM context.
 *
 * @return secured message context.
 **/
void *
libspdm_get_secured_message_context_via_session_info(void *spdm_session_info);

/**
 * This function assigns a new session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return session info associated with this new session ID.
 **/
void *libspdm_assign_session_id(void *spdm_context, uint32_t session_id,
                                bool use_psk);

/**
 * This function frees a session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 **/
void libspdm_free_session_id(void *spdm_context, uint32_t session_id);

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
    void *spdm_context, void *spdm_session_info,
    const uint8_t *cert_chain_buffer, size_t cert_chain_buffer_size,
    size_t *th_data_buffer_size, void *th_data_buffer);
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
    void *context, void *spdm_session_info,
    size_t *th_hash_buffer_size, void *th_hash_buffer);

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
    void *context, void *spdm_session_info, bool is_requester,
    size_t *th_hmac_buffer_size, void *th_hmac_buffer);
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
bool libspdm_calculate_th_for_finish(void *spdm_context,
                                     void *spdm_session_info,
                                     const uint8_t *cert_chain_buffer,
                                     size_t cert_chain_buffer_size,
                                     const uint8_t *mut_cert_chain_buffer,
                                     size_t mut_cert_chain_buffer_size,
                                     size_t *th_data_buffer_size,
                                     void *th_data_buffer);
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
bool libspdm_calculate_th_hash_for_finish(void *spdm_context,
                                          void *spdm_session_info,
                                          size_t *th_hash_buffer_size,
                                          void *th_hash_buffer);

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
bool libspdm_calculate_th_hmac_for_finish_rsp(void *spdm_context,
                                              void *spdm_session_info,
                                              size_t *th_hmac_buffer_size,
                                              void *th_hmac_buffer);

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
bool libspdm_calculate_th_hmac_for_finish_req(void *spdm_context,
                                              void *spdm_session_info,
                                              size_t *th_hmac_buffer_size,
                                              void *th_hmac_buffer);
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
bool libspdm_calculate_th1_hash(void *spdm_context,
                                void *spdm_session_info,
                                bool is_requester,
                                uint8_t *th1_hash_data);

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
bool libspdm_calculate_th2_hash(void *spdm_context,
                                void *spdm_session_info,
                                bool is_requester,
                                uint8_t *th2_hash_data);

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
bool libspdm_get_peer_cert_chain_buffer(void *spdm_context,
                                        const void **cert_chain_buffer,
                                        size_t *cert_chain_buffer_size);

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
bool libspdm_get_peer_cert_chain_data(void *spdm_context,
                                      const void **cert_chain_data,
                                      size_t *cert_chain_data_size);

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
bool libspdm_get_local_cert_chain_buffer(void *spdm_context,
                                         const void **cert_chain_buffer,
                                         size_t *cert_chain_buffer_size);

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
bool libspdm_get_local_cert_chain_data(void *spdm_context,
                                       const void **cert_chain_data,
                                       size_t *cert_chain_data_size);

/**
 * Reads a 24-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 24-bit value that may be unaligned.
 *
 * @return The 24-bit value read from buffer.
 **/
uint32_t libspdm_read_uint24(const uint8_t *buffer);

/**
 * Writes a 24-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 24-bit value that may be unaligned.
 * @param  value   24-bit value to write to buffer.
 **/
void libspdm_write_uint24(uint8_t *buffer, uint32_t value);

/**
 * Reads a 16-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 16-bit value that may be unaligned.
 *
 * @return The 16-bit value read from buffer.
 **/
uint16_t libspdm_read_uint16(const uint8_t *buffer);

/**
 * Writes a 16-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 16-bit value that may be unaligned.
 * @param  value   16-bit value to write to buffer.
 **/
void libspdm_write_uint16(uint8_t *buffer, uint16_t value);

/**
 * Reads a 32-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 32-bit value that may be unaligned.
 *
 * @return The 32-bit value read from buffer.
 **/
uint32_t libspdm_read_uint32(const uint8_t *buffer);

/**
 * Writes a 32-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 32-bit value that may be unaligned.
 * @param  value   32-bit value to write to buffer.
 **/
void libspdm_write_uint32(uint8_t *buffer, uint32_t value);

/**
 * Reads a 64-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 64-bit value that may be unaligned.
 *
 * @return The 64-bit value read from buffer.
 **/
uint64_t libspdm_read_uint64(const uint8_t *buffer);

/**
 * Writes a 64-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 64-bit value that may be unaligned.
 * @param  value   64-bit value to write to buffer.
 **/
void libspdm_write_uint64(uint8_t *buffer, uint64_t value);

#endif /* SPDM_COMMON_LIB_H */
