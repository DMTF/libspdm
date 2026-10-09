/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

/* Forward declaration - resolved at link time from the integrator's malloc implementation. */
extern void *allocate_pool(size_t size);

/**
 * Calculate the size of a GET_MEASUREMENTS request based on SPDM version and attributes.
 *
 * @param spdm_version  The SPDM version byte (e.g., SPDM_MESSAGE_VERSION_10).
 * @param attributes    The param1 field of the GET_MEASUREMENTS request header.
 *
 * @return The size of the GET_MEASUREMENTS request in bytes.
 **/
static size_t libspdm_get_measurement_request_msg_size(uint8_t spdm_version, uint8_t attributes)
{
    bool signature_requested;

    signature_requested = (attributes &
                           SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0;

    if (signature_requested) {
        if (spdm_version >= SPDM_MESSAGE_VERSION_13) {
            return sizeof(spdm_get_measurements_request_t) + SPDM_REQ_CONTEXT_SIZE;
        } else if (spdm_version >= SPDM_MESSAGE_VERSION_11) {
            return sizeof(spdm_get_measurements_request_t);
        } else {
            /* SPDM 1.0: no slot_id_param field */
            return sizeof(spdm_get_measurements_request_t) -
                   sizeof(((spdm_get_measurements_request_t *)0)->slot_id_param);
        }
    } else {
        if (spdm_version >= SPDM_MESSAGE_VERSION_13) {
            return sizeof(spdm_message_header_t) + SPDM_REQ_CONTEXT_SIZE;
        } else {
            return sizeof(spdm_message_header_t);
        }
    }
}

/**
 * Skip past the VCA (Version, Capabilities, Algorithms) messages at the start of
 * a measurement transaction data buffer for SPDM 1.2 and later.
 *
 * @param data             The buffer containing the transaction data.
 * @param data_size        The size of the buffer.
 * @param spdm_version    Output: the negotiated SPDM version from the VCA.
 * @param offset_out       Output: the offset past the end of VCA data.
 *
 * @return LIBSPDM_STATUS_SUCCESS on success, or an error status.
 **/
static libspdm_return_t libspdm_skip_vca(
    const uint8_t *data, size_t data_size,
    uint8_t *spdm_version, size_t *offset_out)
{
    size_t offset;
    const spdm_message_header_t *header;
    uint8_t version_count;
    size_t version_msg_size;
    uint16_t length;
    size_t caps_size;

    offset = 0;

    /* GET_VERSION request: always sizeof(spdm_message_header_t) = 4 bytes */
    if (offset + sizeof(spdm_message_header_t) > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    header = (const spdm_message_header_t *)(data + offset);
    if (header->request_response_code != SPDM_GET_VERSION) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    offset += sizeof(spdm_message_header_t);

    /* VERSION response: 4 (header) + 1 (reserved) + 1 (version_count) + 2*count (entries) */
    if (offset + 6 > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    header = (const spdm_message_header_t *)(data + offset);
    if (header->request_response_code != SPDM_VERSION) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    version_count = data[offset + 5];
    version_msg_size = 6 + 2 * (size_t)version_count;
    if (offset + version_msg_size > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    offset += version_msg_size;

    /* GET_CAPABILITIES request: sizeof(spdm_get_capabilities_request_t) = 20 bytes for 1.2+ */
    if (offset + sizeof(spdm_get_capabilities_request_t) > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    header = (const spdm_message_header_t *)(data + offset);
    if (header->request_response_code != SPDM_GET_CAPABILITIES) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    *spdm_version = header->spdm_version;
    offset += sizeof(spdm_get_capabilities_request_t);

    /* CAPABILITIES response: 20 bytes base + optional supported_algorithms block (1.3+) */
    if (offset + sizeof(spdm_capabilities_response_t) > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    header = (const spdm_message_header_t *)(data + offset);
    if (header->request_response_code != SPDM_CAPABILITIES) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    caps_size = sizeof(spdm_capabilities_response_t);
    if (header->param1 & SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS) {
        /* The supported_algorithms block follows the base struct.
         * It has a length field at offset 2 within the block. */
        if (offset + caps_size + 4 > data_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        length = libspdm_read_uint16(data + offset + caps_size + 2);
        if (length < 4 || offset + caps_size + length > data_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        caps_size += length;
    }
    offset += caps_size;

    /* NEGOTIATE_ALGORITHMS request: use the length field at offset 4 */
    if (offset + 6 > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    header = (const spdm_message_header_t *)(data + offset);
    if (header->request_response_code != SPDM_NEGOTIATE_ALGORITHMS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    length = libspdm_read_uint16(data + offset + 4);
    if (length < sizeof(spdm_message_header_t) || offset + length > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    offset += length;

    /* ALGORITHMS response: use the length field at offset 4 */
    if (offset + 6 > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    header = (const spdm_message_header_t *)(data + offset);
    if (header->request_response_code != SPDM_ALGORITHMS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    length = libspdm_read_uint16(data + offset + 4);
    if (length < sizeof(spdm_message_header_t) || offset + length > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    offset += length;

    *offset_out = offset;
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Advance past a MEASUREMENTS response in the buffer.
 *
 * @param data                The transaction data buffer.
 * @param data_size           The size of the buffer.
 * @param offset              The current offset (start of the MEASUREMENTS response).
 * @param spdm_version        The negotiated SPDM version.
 * @param signature_requested Whether the corresponding request had SignatureRequested set.
 * @param record_out          Output: pointer to the measurement record data (may be NULL if 0 length).
 * @param record_length_out   Output: the measurement record length.
 * @param num_blocks_out      Output: the number_of_blocks field from the response.
 * @param next_offset_out     Output: the offset past this response.
 *
 * @return LIBSPDM_STATUS_SUCCESS on success, or an error status.
 **/
static libspdm_return_t libspdm_parse_measurements_response(
    const uint8_t *data, size_t data_size, size_t offset,
    uint8_t spdm_version, bool signature_requested,
    const uint8_t **record_out, uint32_t *record_length_out,
    uint8_t *num_blocks_out, size_t *next_offset_out)
{
    const spdm_measurements_response_t *response;
    uint32_t record_length;
    size_t ptr;
    uint16_t opaque_length;

    if (offset + sizeof(spdm_measurements_response_t) > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    response = (const spdm_measurements_response_t *)(data + offset);
    if (response->header.request_response_code != SPDM_MEASUREMENTS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *num_blocks_out = response->number_of_blocks;
    record_length = libspdm_read_uint24(response->measurement_record_length);
    *record_length_out = record_length;

    ptr = offset + sizeof(spdm_measurements_response_t);

    /* Measurement record */
    if (ptr + record_length > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (record_length > 0) {
        *record_out = data + ptr;
    } else {
        *record_out = NULL;
    }
    ptr += record_length;

    /* Nonce (always present in MEASUREMENTS response) */
    if (ptr + SPDM_NONCE_SIZE > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    ptr += SPDM_NONCE_SIZE;

    /* Opaque length + data */
    if (ptr + sizeof(uint16_t) > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    opaque_length = libspdm_read_uint16(data + ptr);
    ptr += sizeof(uint16_t);
    if (ptr + opaque_length > data_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    ptr += opaque_length;

    /* Requester context (SPDM 1.3+) */
    if (spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (ptr + SPDM_REQ_CONTEXT_SIZE > data_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        ptr += SPDM_REQ_CONTEXT_SIZE;
    }

    if (signature_requested) {
        /* Signature is the last field. We do not need to know its size
         * since this must be the final response in the transcript. */
        *next_offset_out = data_size;
    } else {
        *next_offset_out = ptr;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Walk measurement blocks within a measurement record, validating structure and counting blocks.
 *
 * @param record         Pointer to the measurement record data.
 * @param record_length  Length of the measurement record.
 * @param block_count    Output: the number of measurement blocks found.
 *
 * @return LIBSPDM_STATUS_SUCCESS on success, or an error status.
 **/
static libspdm_return_t libspdm_count_measurement_blocks(
    const uint8_t *record, uint32_t record_length, size_t *block_count)
{
    size_t offset;
    const spdm_measurement_block_common_header_t *block;
    size_t block_size;
    size_t count;

    offset = 0;
    count = 0;

    while (offset < record_length) {
        if (offset + sizeof(spdm_measurement_block_common_header_t) > record_length) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        block = (const spdm_measurement_block_common_header_t *)(record + offset);
        block_size = sizeof(spdm_measurement_block_common_header_t) + block->measurement_size;
        if (offset + block_size > record_length) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        count++;
        offset += block_size;
    }

    if (offset != record_length) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *block_count = count;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_parse_measurement_transaction_data(
    void *data, size_t data_size,
    spdm_measurement_block_common_header_t **measurements,
    size_t *measurement_count)
{
    const uint8_t *buf;
    size_t offset;
    uint8_t spdm_version;
    libspdm_return_t status;
    const spdm_message_header_t *first_header;
    const spdm_message_header_t *req_header;
    uint8_t attributes;
    bool signature_requested;
    size_t req_size;
    const uint8_t *record;
    uint32_t record_length;
    uint8_t num_blocks;
    size_t next_offset;
    size_t block_count;

    size_t total_blocks;
    size_t total_record_size;
    size_t pass_offset;
    size_t meas_start;
    uint8_t *out_buf;
    size_t copy_offset;

    /* Validate parameters */
    if (data == NULL || measurements == NULL || measurement_count == NULL || data_size == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    buf = (const uint8_t *)data;
    *measurements = NULL;
    *measurement_count = 0;

    /* Check first message to determine if VCA is present */
    if (data_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    first_header = (const spdm_message_header_t *)buf;

    if (first_header->request_response_code == SPDM_GET_VERSION) {
        /* VCA is present (SPDM 1.2+). Skip past it and get negotiated version. */
        status = libspdm_skip_vca(buf, data_size, &spdm_version, &offset);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (first_header->request_response_code == SPDM_GET_MEASUREMENTS) {
        /* No VCA (SPDM 1.0 or 1.1). Version is in the first message header. */
        spdm_version = first_header->spdm_version;
        offset = 0;
    } else {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    meas_start = offset;

    /*
     * First pass: Walk through all GET_MEASUREMENTS/MEASUREMENTS pairs
     * to count total measurement blocks and total measurement record size.
     */
    total_blocks = 0;
    total_record_size = 0;
    pass_offset = meas_start;

    while (pass_offset < data_size) {
        /* Parse GET_MEASUREMENTS request header */
        if (pass_offset + sizeof(spdm_message_header_t) > data_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        req_header = (const spdm_message_header_t *)(buf + pass_offset);
        if (req_header->request_response_code != SPDM_GET_MEASUREMENTS) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        attributes = req_header->param1;
        signature_requested = (attributes &
                               SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0;

        req_size = libspdm_get_measurement_request_msg_size(spdm_version, attributes);
        if (pass_offset + req_size > data_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        pass_offset += req_size;

        /* Check if a MEASUREMENTS response follows. If the next message is not
         * a MEASUREMENTS response (e.g., another GET_MEASUREMENTS request, or
         * end of buffer), treat this as an unpaired request and skip it. */
        if (pass_offset + sizeof(spdm_message_header_t) > data_size) {
            break;
        }
        req_header = (const spdm_message_header_t *)(buf + pass_offset);
        if (req_header->request_response_code != SPDM_MEASUREMENTS) {
            continue;
        }

        /* Parse MEASUREMENTS response */
        status = libspdm_parse_measurements_response(
            buf, data_size, pass_offset, spdm_version, signature_requested,
            &record, &record_length, &num_blocks, &next_offset);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

        /* Validate and count measurement blocks within this response's record */
        if (record_length > 0 && record != NULL) {
            status = libspdm_count_measurement_blocks(record, record_length, &block_count);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
            if (block_count != num_blocks) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            total_blocks += block_count;
            total_record_size += record_length;
        }

        pass_offset = next_offset;
    }

    /* If no measurement blocks were found, return success with empty output */
    if (total_blocks == 0 || total_record_size == 0) {
        *measurements = NULL;
        *measurement_count = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    /* Allocate output buffer for concatenated measurement blocks */
    out_buf = (uint8_t *)allocate_pool(total_record_size);
    if (out_buf == NULL) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    /*
     * Second pass: Copy measurement records into the output buffer.
     * The first pass already validated everything, so we can skip validation.
     */
    pass_offset = meas_start;
    copy_offset = 0;

    while (pass_offset < data_size) {
        req_header = (const spdm_message_header_t *)(buf + pass_offset);
        attributes = req_header->param1;
        signature_requested = (attributes &
                               SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0;

        req_size = libspdm_get_measurement_request_msg_size(spdm_version, attributes);
        pass_offset += req_size;

        /* Skip unpaired requests (same logic as first pass) */
        if (pass_offset + sizeof(spdm_message_header_t) > data_size) {
            break;
        }
        req_header = (const spdm_message_header_t *)(buf + pass_offset);
        if (req_header->request_response_code != SPDM_MEASUREMENTS) {
            continue;
        }

        /* Parse response (already validated) */
        status = libspdm_parse_measurements_response(
            buf, data_size, pass_offset, spdm_version, signature_requested,
            &record, &record_length, &num_blocks, &next_offset);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            /* Should not happen since first pass validated. */
            return status;
        }

        if (record_length > 0 && record != NULL) {
            libspdm_copy_mem(out_buf + copy_offset, total_record_size - copy_offset,
                             record, record_length);
            copy_offset += record_length;
        }

        pass_offset = next_offset;
    }

    *measurements = (spdm_measurement_block_common_header_t *)out_buf;
    *measurement_count = total_blocks;
    return LIBSPDM_STATUS_SUCCESS;
}
