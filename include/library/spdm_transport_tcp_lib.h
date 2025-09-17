/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_TCP_TRANSPORT_LIB_H
#define SPDM_TCP_TRANSPORT_LIB_H

#include "library/spdm_common_lib.h"

/* Required sender/receive buffer in device io.
 * +-------+--------+---------------------------+------+--+------+---+--------+-----+
 * | TYPE  |TransHdr|      EncryptionHeader     |AppHdr|  |Random|MAC|AlignPad|FINAL|
 * |       |        |SessionId|SeqNum|Len|AppLen|      |  |      |   |        |     |
 * +-------+--------+---------------------------+------+  +------+---+--------+-----+
 * |  TCP  |    4   |    4    |   0  | 2 |   2  |   0  |  |   0  | 16|   3    |  31 |
 * +-------+--------+---------------------------+------+--+------+---+--------+-----+
 *
 */

/*
 * Encode an SPDM or APP message to a transport layer message.
 *
 * For normal SPDM message, it adds the transport layer wrapper.
 * For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
 * For secured APP message, it encrypts a secured message then adds the transport layer wrapper.
 *
 * The APP message is encoded to a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take TCP as example: APP message == TCP-SPDM-BINDING-HEADER + SPDM message
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
 **/
libspdm_return_t libspdm_transport_tcp_encode_message(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    bool is_requester, size_t message_size, void *message,
    size_t *transport_message_size, void **transport_message);

/**
 * Decode an SPDM or APP message from a transport layer message.
 *
 * For normal SPDM message, it removes the transport layer wrapper,
 * For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 * For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 *
 * The APP message is decoded from a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take TCP as example: APP message == TCP-SPDM-BINDING-HEADER + SPDM message (For out-of-session message)
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
 **/
libspdm_return_t libspdm_transport_tcp_decode_message(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_requester,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message);

/**
 * @brief Encode a SPDM-over-TCP message that contains no SPDM payload.
 *
 * This function builds a TCP binding header suitable for Role-Inquiry (0xBF) or
 * any error message (0xC0-0xFF). It does not append any SPDM data after the header.
 *
 * @param[in]      message_type            The message type to encode (e.g., 0xBF, 0xC0...0xFF).
 *                                         Must be SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY or an error message type.
 * @param[in,out]  transport_message_size  On input, size of the output buffer. On output, encoded size.
 * @param[in,out]  transport_message       On input, pointer to buffer to write the encoded message.
 *                                         On success, contains the encoded message header.
 *
 * @retval LIBSPDM_STATUS_SUCCESS            Encoding completed successfully.
 * @retval LIBSPDM_STATUS_INVALID_PARAMETER  Unsupported message type for this function.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL   Provided buffer is too small for header.
 */
libspdm_return_t libspdm_tcp_encode_discovery_message(uint8_t message_type,
                                                      size_t *transport_message_size,
                                                      void **transport_message);

/**
 * @brief Decode a SPDM-over-TCP discovery or error message (no SPDM payload).
 *
 * Validates header fields including binding version, payload length, and message type.
 *
 * @param[in]  transport_message_size   Size of the incoming buffer.
 * @param[in]  transport_message        Pointer to the incoming buffer.
 * @param[out] message_type             On success, receives the validated message type.
 *
 * @retval LIBSPDM_STATUS_SUCCESS             Decoding successful.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE    Buffer too small for TCP header.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP     Unsupported binding version.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD   Payload length is non-zero or message type invalid.
 */
libspdm_return_t libspdm_tcp_decode_discovery_message(size_t transport_message_size,
                                                      const void *transport_message,
                                                      uint8_t *message_type);

/**
 * Return the maximum transport layer message header size.
 *   Transport Message Header Size + sizeof(spdm_secured_message_cipher_header_t))
 *
 *   For TCP, Transport Message Header Size = sizeof(tcp_spdm_binding_header_t)
 *   For PCI_DOE, Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return size of maximum transport layer message header size
 **/
uint32_t libspdm_transport_tcp_get_header_size(
    void *spdm_context);

/**
 * Get sequence number in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @param sequence_number        The current sequence number used to encode or decode message.
 * @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
 *                             The size in byte of the output buffer shall be 8.
 *
 * @return size in byte of the sequence_number_buffer.
 *        It shall be no greater than 8.
 *        0 means no sequence number is required.
 **/
uint8_t libspdm_tcp_get_sequence_number(uint64_t sequence_number,
                                        uint8_t *sequence_number_buffer);

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no randum number is required.
 **/
uint32_t libspdm_tcp_get_max_random_number_count(void);

/**
 * This function translates the negotiated secured_message_version to a DSP0277 version.
 *
 * @param  secured_message_version  The version specified in binding specification and
 *                                  negotiated in KEY_EXCHANGE/KEY_EXCHANGE_RSP.
 *
 * @return The DSP0277 version specified in binding specification,
 *         which is bound to secured_message_version.
 */
spdm_version_number_t libspdm_tcp_get_secured_spdm_version(
    spdm_version_number_t secured_message_version);

#endif /* SPDM_TCP_TRANSPORT_LIB_H */
