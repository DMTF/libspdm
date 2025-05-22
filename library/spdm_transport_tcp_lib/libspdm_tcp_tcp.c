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
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
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
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
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
