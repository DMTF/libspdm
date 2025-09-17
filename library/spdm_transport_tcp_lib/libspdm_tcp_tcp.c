/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_tcp_lib.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm_tcp_binding.h"

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
                                        uint8_t *sequence_number_buffer)
{
    return SPDM_TCP_SEQUENCE_NUMBER_COUNT;
}

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no randum number is required.
 **/
uint32_t libspdm_tcp_get_max_random_number_count(void)
{
    return SPDM_TCP_MAX_RANDOM_NUMBER_COUNT;
}

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
    spdm_version_number_t secured_message_version)
{
    return SECURED_SPDM_VERSION_12;
}

/**
 * Encode a normal message or secured message to a transport message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 **/
libspdm_return_t libspdm_tcp_encode_message(const uint32_t *session_id, size_t message_size,
                                            void *message,
                                            size_t *transport_message_size,
                                            void **transport_message)
{
    uint32_t data32;
    spdm_tcp_binding_header_t *tcp_message_header;

    if (*transport_message_size <
        message_size + sizeof(spdm_tcp_binding_header_t)) {
        *transport_message_size = message_size +
                                  sizeof(spdm_tcp_binding_header_t);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    *transport_message_size =
        message_size + sizeof(spdm_tcp_binding_header_t);
    *transport_message = (uint8_t *)message - sizeof(spdm_tcp_binding_header_t);
    tcp_message_header = *transport_message;
    tcp_message_header->payload_length = (uint16_t)(*transport_message_size - 2);
    tcp_message_header->binding_version = 0x1;

    if (session_id != NULL) {
        tcp_message_header->message_type = SPDM_TCP_MESSAGE_TYPE_IN_SESSION;
        data32 = libspdm_read_uint32((const uint8_t *)message);
        LIBSPDM_ASSERT(*session_id == data32);
        if (*session_id != data32) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        tcp_message_header->message_type = SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION;
    }

    return LIBSPDM_STATUS_SUCCESS;
}


/**
 * Decode a transport message to a normal message or secured message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 **/
libspdm_return_t libspdm_tcp_decode_message(uint32_t **session_id,
                                            size_t transport_message_size,
                                            void *transport_message,
                                            size_t *message_size, void **message)
{
    const spdm_tcp_binding_header_t *tcp_message_header;

    LIBSPDM_ASSERT(transport_message_size > sizeof(spdm_tcp_binding_header_t));
    if (transport_message_size <= sizeof(spdm_tcp_binding_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    tcp_message_header = transport_message;

    switch (tcp_message_header->message_type) {
    case SPDM_TCP_MESSAGE_TYPE_IN_SESSION:
        LIBSPDM_ASSERT(session_id != NULL);
        if (session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (transport_message_size <=
            sizeof(spdm_tcp_binding_header_t) + sizeof(uint32_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        *session_id = (uint32_t *)((uint8_t *)transport_message +
                                   sizeof(spdm_tcp_binding_header_t));
        break;

    case SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION:
        if (session_id != NULL) {
            *session_id = NULL;
        }
        break;

    default:
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    *message_size = transport_message_size - sizeof(spdm_tcp_binding_header_t);
    *message = (uint8_t *)transport_message + sizeof(spdm_tcp_binding_header_t);

    return LIBSPDM_STATUS_SUCCESS;
}


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
 **/
libspdm_return_t libspdm_tcp_encode_discovery_message(uint8_t message_type,
                                                      size_t *transport_message_size,
                                                      void **transport_message)
{
    if ((message_type != SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY &&
         (message_type < SPDM_TCP_MESSAGE_TYPE_ERROR_TOO_LARGE ||
          message_type > SPDM_TCP_MESSAGE_TYPE_ERROR_RESERVED_MAX))){
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if (*transport_message_size < sizeof(spdm_tcp_binding_header_t)) {
        *transport_message_size = sizeof(spdm_tcp_binding_header_t);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    *transport_message_size = sizeof(spdm_tcp_binding_header_t);
    spdm_tcp_binding_header_t *tcp_header = (spdm_tcp_binding_header_t *)(*transport_message);

    tcp_header->payload_length = 0;
    tcp_header->binding_version = 0x01;
    tcp_header->message_type = message_type;

    return LIBSPDM_STATUS_SUCCESS;
}


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
 **/
libspdm_return_t libspdm_tcp_decode_discovery_message(size_t transport_message_size,
                                                      const void *transport_message,
                                                      uint8_t *message_type)
{
    if (transport_message_size < sizeof(spdm_tcp_binding_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    const spdm_tcp_binding_header_t *tcp_header = (const spdm_tcp_binding_header_t *)transport_message;

    if (tcp_header->binding_version != 0x01) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (tcp_header->payload_length != 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    uint8_t type = tcp_header->message_type;
    if (type != SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY &&
        (type < SPDM_TCP_MESSAGE_TYPE_ERROR_TOO_LARGE || type > SPDM_TCP_MESSAGE_TYPE_ERROR_RESERVED_MAX)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *message_type = type;

    return LIBSPDM_STATUS_SUCCESS;
}


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
    void *spdm_context)
{
    return sizeof(spdm_tcp_binding_header_t) + sizeof(spdm_secured_message_cipher_header_t);
}
