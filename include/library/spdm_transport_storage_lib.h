/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef STORAGE_TRANSPORT_LIB_H
#define STORAGE_TRANSPORT_LIB_H

#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"

#define LIBSPDM_STORAGE_SEQUENCE_NUMBER_COUNT 0
#define LIBSPDM_STORAGE_MAX_RANDOM_NUMBER_COUNT 0

/*
 * SPDM Storage transport binding header for request encoding as defined by
 * DSP0286. This header is not specific to any particular storage type, i.e
 * SCSI, NVMe or ATA. Instead, it is used to encode requests (host to controller),
 * to provide transport specific SPDM information. This information shall then
 * be used to generate the storage protocol specific command. Refer to the
 * storage specification for field sizes, offsets and application.
 *
 * As such, this header *shall not* be transmitted as a part of the libspdm
 * message, instead be used only as required to generate the storage specific
 * command(s).
 *
 * +-----------------+--------+-------------------+---------+--------+--+
 * |      TYPE       |Security|      Security     | INC_512 | Length |  |
 * |                 |Protocol| Protocol Specific |         |        |  |
 * +-----------------+--------+-------------------+---------+--------+  +
 * |Security Protocol|    1   |         2         |    1    |  4     |  |
 * +-----------------+--------+-------------------+---------+--------+--+
 *
 * This structure is publicly defined to provide transport encoding information
 * to the caller from transport_message buffer(s).
 */
#pragma pack(1)
typedef struct {
    uint8_t security_protocol;
    uint16_t security_protocol_specific;
    bool inc_512;
    uint32_t length;
} storage_spdm_transport_header;
#pragma pack()

#define LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE  (1 + 2 + 1 + 4)
#define LIBSPDM_STORAGE_TRANSPORT_TAIL_SIZE    (0)

#define LIBSPDM_STORAGE_CMD_DIRECTION_IF_SEND 0x01
#define LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV 0x02

/**
 * Decode an Security Protocol Command message to a normal message or secured message.
 *
 * @param  session_id                  Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  connection_id               Indicates the connection ID of the message.
 * @param  transport_message_size      size in bytes of the transport message data buffer.
 * @param  transport_message           A pointer to a source buffer to store the transport message.
 * @param  message_size                size in bytes of the message data buffer.
 * @param  message                     A pointer to a destination buffer to store the message.
 *
 * @retval RETURN_SUCCESS                      The message is encoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the transport_message_size is zero.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD    The message field is incorrect.
 **/
libspdm_return_t libspdm_storage_decode_message(uint32_t **session_id,
                                                uint8_t *connection_id,
                                                size_t transport_message_size,
                                                void *transport_message,
                                                size_t *message_size,
                                                void **message);
/**
 * Decode an SPDM or APP message from a storage transport layer message.
 *
 * For normal SPDM message, it removes the transport layer wrapper,
 * For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 * For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 *
 * The APP message is decoded from a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  session_id              Indicates if it is a secured message protected via SPDM session.
 *                                 If session_id is NULL, it is a normal message.
 *                                 If session_id is not NULL, it is a secured message.
 * @param  is_app_message          Indicates if it is an APP message or SPDM message.
 * @param  is_request_message      Indicates if it is a request message.
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 * @param  transport_message       A pointer to a source buffer to store the transport message.
 *                                 For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size            Size in bytes of the message data buffer.
 * @param  message                 A pointer to a destination buffer to store the message.
 *                                 On input, it shall point to the scratch buffer in spdm_context.
 *                                 On output, for normal message, it will point to the original receiver buffer.
 *                                 On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval RETURN_SUCCESS                      The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size is zero.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD    The message field is incorrect.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP      The transport_message is unsupported.
 **/
libspdm_return_t libspdm_transport_storage_decode_message(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_request_message,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message);


/**
 * Encode a normal message or secured message to a storage transport message.
 *
 * @param  session_id                  Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  connection_id               Indicates the connection ID of the message.
 * @param  message_size                size in bytes of the message data buffer.
 * @param  message                     A pointer to a destination buffer to store the message.
 * @param  transport_message_size      Size in bytes of the transport message data buffer.
 *                                     On return, length of the transport message.
 * @param  transport_message           A pointer to a source buffer to store the transport message.
 *
 * @retval RETURN_SUCCESS                      The message is encoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size/transport_message_size is zero.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD    The message field is incorrect.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL     Insufficient transport buffer size.
 **/
libspdm_return_t libspdm_storage_encode_message(const uint32_t *session_id,
                                                uint8_t connection_id,
                                                size_t message_size, void *message,
                                                size_t *transport_message_size,
                                                void **transport_message);

/**
 * Encode an SPDM or APP message into a transport layer message.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  session_id              Indicates if it is a secured message protected via SPDM session.
 *                                 If session_id is NULL, it is a normal message.
 *                                 If session_id is not NULL, it is a secured message.
 * @param  is_app_message          Indicates if it is an APP message or SPDM message.
 * @param  is_request_message      Indicates if it is a request message.
 * @param  message_size            Size in bytes of the message data buffer.
 * @param  message                 A pointer to a destination buffer to store the message.
 *                                 On input, it shall point to the scratch buffer in spdm_context.
 *                                 On output, for normal message, it will point to the original receiver buffer.
 *                                 On output, for secured message, it will point to the scratch buffer in spdm_context.
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 * @param  transport_message       A pointer to a source buffer to store the transport message.
 *                                 For normal message or secured message, it shall point to acquired receiver buffer.
 *
 * @retval RETURN_SUCCESS                      The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size is zero.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD    The message field is incorrect.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP      The transport_message is unsupported.
 **/
libspdm_return_t libspdm_transport_storage_encode_message(
    void *spdm_context, const uint32_t *session_id,
    bool is_app_message,
    bool is_request_message, size_t message_size, void *message,
    size_t *transport_message_size, void **transport_message);

/**
 * Decode a storage transport management command
 *
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 * @param  transport_message       A pointer to an encoded transport message buffer.
 * @param  transport_command       Storage transport command contained in transport message
 * @param  length                  On return, this specifies allocation length
 *                                 or transfer length. Depending of if the
 *                                 message was an IF_RECV or IF_SEND respectively.
 *
 * @retval RETURN_SUCCESS                      The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size is zero.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD    The message field is incorrect.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP      The transport_message is unsupported.
 **/
libspdm_return_t libspdm_transport_storage_decode_management_cmd(
    size_t transport_message_size,
    const void *transport_message,
    uint8_t *transport_command,
    uint32_t *length);

/**
 * Encode a storage transport management command, supports only Discovery and
 * Pending Info.
 *
 * @param  cmd_direction           Specify the direction of the command IF_SEND/RECV
 * @param  transport_operation     Transport operation type, Discovery/Pending Info
 * @param  connection_id           SPDM Connection ID
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 *                                 On return, the length of the encoded message
 * @param  allocation_length       Storage buffer allocation length
 * @param  transport_message       A pointer to a transport message buffer.
 *
 * @retval RETURN_SUCCESS                      The message is encoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size is zero.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD    The message field is incorrect.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL     Insufficient transport buffer size
 **/
libspdm_return_t libspdm_transport_storage_encode_management_cmd(
    uint8_t cmd_direction, uint8_t transport_operation,
    uint8_t connection_id, size_t *transport_message_size,
    size_t *allocation_length, void *transport_message);

/**
 * Encode a storage transport discovery response. As defined by the DMTF DSP0286
 *
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 *                                 On return, the size of the response
 * @param  transport_message       A pointer to a source buffer to store the transport message.
 *
 * @retval RETURN_SUCCESS                      The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size is zero.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL     @transport_message is too small
 **/
libspdm_return_t libspdm_transport_storage_encode_discovery_response(
    size_t *transport_message_size,
    void *transport_message);

/**
 * Encode a storage transport pending response. As defined by the DMTF DSP0286
 *
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 *                                 On return, the size of the response
 * @param  transport_message       A pointer to a source buffer to store the transport message.
 * @param  response_pending        If true, the responder has a pending response
 * @param  pending_response_length Valid only if @response_pending is true,
 *                                 specifies the length of the pending message
 *                                 in bytes.
 *
 * @retval RETURN_SUCCESS                      The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE     The message is NULL or the message_size is zero.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL     @transport_message is too small
 **/
libspdm_return_t libspdm_transport_storage_encode_pending_info_response(
    size_t *transport_message_size,
    void *transport_message, bool response_pending,
    uint32_t pending_response_length);

#endif /* STORAGE_TRANSPORT_LIB_H */
