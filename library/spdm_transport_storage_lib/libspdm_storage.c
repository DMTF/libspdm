/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_storage_lib.h"
#include "industry_standard/spdm_storage_binding.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"

/**
 * This function translates the negotiated secured_message_version to a DSP0277 version.
 *
 * @param  secured_message_version  The version specified in binding specification and
 *                                  negotiated in KEY_EXCHANGE/KEY_EXCHANGE_RSP.
 *
 * @return The DSP0277 version specified in binding specification,
 *         which is bound to secured_message_version.
 */
spdm_version_number_t libspdm_storage_get_secured_spdm_version(
    spdm_version_number_t secured_message_version)
{
    return secured_message_version;
}

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no random number is required.
 **/
uint32_t libspdm_storage_get_max_random_number_count(void)
{
    return LIBSPDM_STORAGE_MAX_RANDOM_NUMBER_COUNT;
}

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
uint8_t libspdm_storage_get_sequence_number(uint64_t sequence_number,
                                            uint8_t *sequence_number_buffer)
{
    libspdm_copy_mem(sequence_number_buffer, LIBSPDM_STORAGE_SEQUENCE_NUMBER_COUNT,
                     &sequence_number, LIBSPDM_STORAGE_SEQUENCE_NUMBER_COUNT);
    return LIBSPDM_STORAGE_SEQUENCE_NUMBER_COUNT;
}

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
                                                void **message)
{
    const storage_spdm_transport_header *storage_header;
    uint32_t storage_length;
    uint16_t security_protocol_specific;
    uint8_t spsp0, spsp1, spdm_operation;

    LIBSPDM_ASSERT(transport_message_size >= sizeof(storage_spdm_transport_header));
    if (transport_message_size <= sizeof(storage_spdm_transport_header)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (transport_message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    storage_header = transport_message;
    if (storage_header->security_protocol != SPDM_STORAGE_SECURITY_PROTOCOL_DMTF) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
    security_protocol_specific  = libspdm_byte_swap_16(storage_header->security_protocol_specific);
#else
    security_protocol_specific  = storage_header->security_protocol_specific;
#endif
    spsp0 = security_protocol_specific & 0xFF;
    spsp1 = security_protocol_specific >> 8;

    if (spsp1 != 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (connection_id) {
        *connection_id = spsp0 & 0x03;
    }
    spdm_operation = (spsp0 & 0xFC) >> 2;

    switch (spdm_operation) {
    case SPDM_STORAGE_OPERATION_CODE_DISCOVERY:
    case SPDM_STORAGE_OPERATION_CODE_PENDING_INFO:
    case SPDM_STORAGE_OPERATION_CODE_MESSAGE:
        if (session_id != NULL) {
            *session_id = NULL;
        }
        break;
    case SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE:
        LIBSPDM_ASSERT(session_id != NULL);
        if (session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (transport_message_size <=
            sizeof(storage_spdm_transport_header) + sizeof(uint32_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        *session_id = (void *)((uint8_t *)transport_message +
                               sizeof(storage_spdm_transport_header));
        break;
    default:
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
    storage_length  = libspdm_byte_swap_32(storage_header->length);
#else
    storage_length  = storage_header->length;
#endif
    if (storage_length != transport_message_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    *message_size = transport_message_size - sizeof(storage_spdm_transport_header);
    *message = (uint8_t *)transport_message + sizeof(storage_spdm_transport_header);

    return LIBSPDM_STATUS_SUCCESS;
}

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
 * @param  session_id              On entry, indicates if it is a secured message protected via SPDM session.
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
    size_t *message_size, void **message)
{
    libspdm_return_t status;
    uint32_t *secured_message_session_id;
    uint8_t *secured_message;
    size_t secured_message_size;
    size_t secure_msg_reserved_bytes = sizeof(uint32_t);
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    libspdm_error_struct_t spdm_error;

    spdm_error.error_code = 0;
    spdm_error.session_id = 0;
    libspdm_set_last_spdm_error_struct(spdm_context, &spdm_error);

    spdm_secured_message_callbacks.version =
        LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number =
        libspdm_storage_get_sequence_number;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_storage_get_max_random_number_count;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_storage_get_secured_spdm_version;

    if ((session_id == NULL) || (is_app_message == NULL)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    *is_app_message = false;

    secured_message_session_id = NULL;

    if (!is_request_message) {
        /*
         * Storage response messages are not transport encoded, this is the SPDM
         * message, and shall be processed as such. Which also means that there
         * is no way from the response to determine if it's secure or not, instead
         * use internal state to determine.
         */
        /* Expecting a secured message */
        if (*session_id != NULL) {
            **session_id =
                *((uint32_t *)(((uint8_t *)transport_message) + secure_msg_reserved_bytes));

            secured_message_context =
                libspdm_get_secured_message_context_via_session_id(
                    spdm_context, **session_id);
            if (secured_message_context == NULL) {
                spdm_error.error_code = SPDM_ERROR_CODE_INVALID_SESSION;
                spdm_error.session_id = **session_id;
                libspdm_set_last_spdm_error_struct(spdm_context,
                                                   &spdm_error);
                return LIBSPDM_STATUS_UNSUPPORTED_CAP;
            }

            /*
             * Secured message to message
             *
             * DSP0286 specifies 4 reserved bytes at the start of a secured
             * message. Skip that for decoding.
             */
            status = libspdm_decode_secured_message(
                secured_message_context, **session_id,
                is_request_message, transport_message_size - secure_msg_reserved_bytes,
                ((uint8_t *)transport_message) + secure_msg_reserved_bytes,
                message_size, message, &spdm_secured_message_callbacks);


            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "libspdm_decode_secured_message - %xu\n", status));
                libspdm_secured_message_get_last_spdm_error_struct(
                    secured_message_context, &spdm_error);
                libspdm_set_last_spdm_error_struct(spdm_context,
                                                   &spdm_error);
                return status;
            }

        } else {
            *message_size = transport_message_size;
            *message = transport_message;
            *session_id = NULL;
        };
        return LIBSPDM_STATUS_SUCCESS;
    } else {
        /* Storage requests need to be transport encoded/decoded */
        status = libspdm_storage_decode_message(
            &secured_message_session_id, 0, transport_message_size,
            transport_message, &secured_message_size, (void **)&secured_message);

        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %xu\n", status));
            return status;
        }

        if (secured_message_session_id != NULL) {
            *session_id = secured_message_session_id;

            secured_message_context =
                libspdm_get_secured_message_context_via_session_id(
                    spdm_context, *secured_message_session_id);
            if (secured_message_context == NULL) {
                spdm_error.error_code = SPDM_ERROR_CODE_INVALID_SESSION;
                spdm_error.session_id = *secured_message_session_id;
                libspdm_set_last_spdm_error_struct(spdm_context,
                                                   &spdm_error);
                return LIBSPDM_STATUS_UNSUPPORTED_CAP;
            }

            /* Secured message to message*/
            status = libspdm_decode_secured_message(
                secured_message_context, *secured_message_session_id,
                is_request_message, secured_message_size, secured_message,
                message_size, message,
                &spdm_secured_message_callbacks);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "libspdm_decode_secured_message - %xu\n", status));
                libspdm_secured_message_get_last_spdm_error_struct(
                    secured_message_context, &spdm_error);
                libspdm_set_last_spdm_error_struct(spdm_context,
                                                   &spdm_error);
                return status;
            }
            return LIBSPDM_STATUS_SUCCESS;
        } else {
            /* get non-secured message*/
            status = libspdm_storage_decode_message(&secured_message_session_id,
                                                    0,
                                                    transport_message_size,
                                                    transport_message,
                                                    message_size, message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %xu\n",
                               status));
                return status;
            }
            LIBSPDM_ASSERT(secured_message_session_id == NULL);
            *session_id = NULL;
            return LIBSPDM_STATUS_SUCCESS;
        }
    }
}

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
                                                void **transport_message)
{
    uint32_t data32;
    storage_spdm_transport_header *storage_header;

    if (!transport_message_size || *transport_message_size == 0
        || message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    LIBSPDM_ASSERT(*transport_message_size >= sizeof(storage_spdm_transport_header));

    if (*transport_message_size < message_size + sizeof(storage_spdm_transport_header)) {
        *transport_message_size = message_size + sizeof(storage_spdm_transport_header);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (!message || !transport_message) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (connection_id & ~0x03) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *transport_message_size = message_size + sizeof(storage_spdm_transport_header);
    *transport_message = (uint8_t *)message - sizeof(storage_spdm_transport_header);
    storage_header = *transport_message;
    storage_header->inc_512 = false;

    storage_header->security_protocol = SPDM_STORAGE_SECURITY_PROTOCOL_DMTF;

    if (session_id != NULL) {
        storage_header->security_protocol_specific = SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE <<
                                                     2;
        storage_header->security_protocol_specific |= connection_id &
                                                      SPDM_STORAGE_MAX_CONNECTION_ID_MASK;
        data32 = libspdm_read_uint32((const uint8_t *)message);
        LIBSPDM_ASSERT(*session_id == data32);
        if (*session_id != data32) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        storage_header->security_protocol_specific = SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2;
        storage_header->security_protocol_specific |= connection_id &
                                                      SPDM_STORAGE_MAX_CONNECTION_ID_MASK;
    }

    storage_header->length = (uint32_t)*transport_message_size;

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
    storage_header->length = libspdm_byte_swap_32(storage_header->length);
    storage_header->security_protocol_specific = libspdm_byte_swap_16(
        storage_header->security_protocol_specific);
#endif

    return LIBSPDM_STATUS_SUCCESS;
}

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
    size_t *transport_message_size, void **transport_message)
{
    libspdm_return_t status;
    uint8_t *secured_message;
    size_t secured_message_size;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    size_t sec_trans_header_size;

    spdm_secured_message_callbacks.version =
        LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number =
        libspdm_storage_get_sequence_number;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_storage_get_max_random_number_count;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_storage_get_secured_spdm_version;

    if (is_app_message) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!transport_message_size || !transport_message
        || *transport_message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (session_id != NULL) {
        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *session_id);
        if (secured_message_context == NULL) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        /* Message to secured message*/
        sec_trans_header_size = is_request_message ?
                                sizeof(storage_spdm_transport_header): 0;
        /* DSP0286 Specifies 4 Reserved bytes at the start of a secured message */
        sec_trans_header_size += sizeof(uint32_t);
        secured_message = ((uint8_t *)(*transport_message)) + sec_trans_header_size;
        secured_message_size = *transport_message_size - sec_trans_header_size;
        status = libspdm_encode_secured_message(
            secured_message_context, *session_id, is_request_message,
            message_size, message, &secured_message_size,
            secured_message, &spdm_secured_message_callbacks);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_encode_secured_message - %xu\n", status));
            return status;
        }

        if (!is_request_message) {
            /*
             * Storage response messages are not transport encoded, instead it
             * is just the SPDM message response.
             */
            *transport_message_size = secured_message_size + sec_trans_header_size;
            /* Ensure we allow the 4 reserved bytes to be encapsulated */
            *transport_message = secured_message - sizeof(uint32_t);;
            return LIBSPDM_STATUS_SUCCESS;
        }

        /* secured message to secured storage message*/
        status = libspdm_storage_encode_message(
            session_id, 0, secured_message_size, secured_message,
            transport_message_size, transport_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %xu\n",
                           status));
            return status;
        }
    } else {
        if (!is_request_message) {
            /*
             * Storage response messages are not transport encoded, instead it
             * is just the SPDM message response.
             */
            *transport_message_size = message_size;
            *transport_message = message;
            return LIBSPDM_STATUS_SUCCESS;
        }

        /* SPDM message to normal storage message*/
        status = libspdm_storage_encode_message(NULL, 0,
                                                message_size, message,
                                                transport_message_size,
                                                transport_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %xu\n",
                           status));
            return status;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

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
    size_t *allocation_length, void *transport_message)
{
    storage_spdm_transport_header *storage_header;

    if (!transport_message_size || !allocation_length
        || *transport_message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (*transport_message_size < sizeof(storage_spdm_transport_header)) {
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (connection_id & ~0x03) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (!(cmd_direction == LIBSPDM_STORAGE_CMD_DIRECTION_IF_SEND ||
          cmd_direction == LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    switch (transport_operation) {
    case SPDM_STORAGE_OPERATION_CODE_DISCOVERY:
        if (cmd_direction == LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV) {
            *allocation_length = sizeof(spdm_storage_discovery_response_t);
            if (*transport_message_size < sizeof(spdm_storage_discovery_response_t)) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }
        }
        break;
    case SPDM_STORAGE_OPERATION_CODE_PENDING_INFO:
        if (cmd_direction == LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV) {
            *allocation_length = sizeof(spdm_storage_pending_info_response_t);
            if (*transport_message_size < sizeof(spdm_storage_pending_info_response_t)) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }
        }
        break;
    default:
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *transport_message_size = sizeof(storage_spdm_transport_header);
    libspdm_zero_mem(transport_message, *transport_message_size);

    storage_header = transport_message;
    storage_header->security_protocol = SPDM_STORAGE_SECURITY_PROTOCOL_DMTF;
    storage_header->security_protocol_specific = transport_operation << 2;
    storage_header->security_protocol_specific |= connection_id &
                                                  SPDM_STORAGE_MAX_CONNECTION_ID_MASK;
    storage_header->inc_512 = false;
    storage_header->length = (uint32_t)*transport_message_size;

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
    storage_header->length = libspdm_byte_swap_32(storage_header->length);
    storage_header->security_protocol_specific = libspdm_byte_swap_16(
        storage_header->security_protocol_specific);
#endif

    return LIBSPDM_STATUS_SUCCESS;
}

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
    void *transport_message)
{
    spdm_storage_discovery_response_t *discovery_response;

    if (!transport_message || !transport_message_size
        || *transport_message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (*transport_message_size < sizeof(spdm_storage_discovery_response_t)) {
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (!transport_message) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    *transport_message_size = sizeof(spdm_storage_discovery_response_t);
    libspdm_zero_mem(transport_message, *transport_message_size);
    discovery_response = transport_message;

    discovery_response->data_length = (uint16_t)*transport_message_size;
    discovery_response->storage_binding_version = SPDM_STORAGE_SECURITY_BINDING_VERSION;
    /* 1 supported connection (0's based) */
    discovery_response->connection_parameters = 0;
    discovery_response->supported_operations = (1 << SPDM_STORAGE_OPERATION_CODE_DISCOVERY)
                                               | (1 << SPDM_STORAGE_OPERATION_CODE_PENDING_INFO)
                                               | (1 << SPDM_STORAGE_OPERATION_CODE_MESSAGE)
                                               | (1 <<
                                                  SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE);

    return LIBSPDM_STATUS_SUCCESS;
}

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
    uint32_t pending_response_length)
{
    spdm_storage_pending_info_response_t *pending_info_response;

    if (!transport_message || !transport_message_size
        || *transport_message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (*transport_message_size < sizeof(spdm_storage_pending_info_response_t)) {
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    *transport_message_size = sizeof(spdm_storage_pending_info_response_t);
    libspdm_zero_mem(transport_message, *transport_message_size);
    pending_info_response = transport_message;

    pending_info_response->data_length = (uint16_t)*transport_message_size;
    pending_info_response->storage_binding_version = SPDM_STORAGE_SECURITY_BINDING_VERSION;

    if (response_pending) {
        pending_info_response->pending_info_flag = (1 << 0);
        pending_info_response->response_length = pending_response_length;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Decode a storage transport management command
 *
 * @param  transport_message_size  Size in bytes of the transport message data buffer.
 * @param  transport_message       A pointer to an encoded transport message buffer.
 * @param  transport_command       Storage transport command contained in transport message
 * @param  length                  On return, this specifies allocation length
 *                                 or transfer length. Depending on if the
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
    uint32_t *length)
{
    const storage_spdm_transport_header *storage_header;
    uint16_t security_protocol_specific;
    uint8_t spsp0, spsp1, spdm_operation;

    if (!transport_message || transport_message_size == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    LIBSPDM_ASSERT(transport_message_size >= sizeof(storage_spdm_transport_header));

    if (transport_message_size < sizeof(storage_spdm_transport_header)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    storage_header = transport_message;
    if (storage_header->security_protocol != SPDM_STORAGE_SECURITY_PROTOCOL_DMTF) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
    security_protocol_specific = libspdm_byte_swap_16(storage_header->security_protocol_specific);
#else
    security_protocol_specific = storage_header->security_protocol_specific;
#endif
    spsp0 = security_protocol_specific & 0xFF;
    spsp1 = security_protocol_specific >> 8;

    if (spsp1 != 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    spdm_operation = (spsp0 & 0xFC) >> 2;

    switch (spdm_operation) {
    case SPDM_STORAGE_OPERATION_CODE_DISCOVERY:
    case SPDM_STORAGE_OPERATION_CODE_PENDING_INFO:
    case SPDM_STORAGE_OPERATION_CODE_MESSAGE:
    case SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE:
        *transport_command = spdm_operation;
        break;
    default:
        *transport_command = 0;
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
    *length  = libspdm_byte_swap_32(storage_header->length);
#else
    *length  = storage_header->length;
#endif
    return LIBSPDM_STATUS_SUCCESS;
}
