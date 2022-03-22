/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

#define LIBSPDM_ALTERNATIVE_DEFAULT_SLOT_ID 2
#define LIBSPDM_LARGE_MEASUREMENT_SIZE ((1 << 24) - 1)

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
static uint8_t m_libspdm_local_psk_hint[32];

size_t libspdm_test_get_measurement_request_size(const void *spdm_context,
                                                 const void *buffer,
                                                 size_t buffer_size)
{
    const spdm_get_measurements_request_t *spdm_request;
    size_t message_size;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code !=
        SPDM_GET_MEASUREMENTS) {
        return buffer_size;
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            if (buffer_size <
                sizeof(spdm_get_measurements_request_t)) {
                return buffer_size;
            }
            message_size = sizeof(spdm_get_measurements_request_t);
        } else {
            if (buffer_size <
                sizeof(spdm_get_measurements_request_t) -
                sizeof(spdm_request->slot_id_param)) {
                return buffer_size;
            }
            message_size = sizeof(spdm_get_measurements_request_t) -
                           sizeof(spdm_request->slot_id_param);
        }
    } else {
        /* already checked before if buffer_size < sizeof(spdm_message_header_t)*/
        message_size = sizeof(spdm_message_header_t);
    }

    /* Good message, return actual size*/
    return message_size;
}

return_status libspdm_requester_get_measurements_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    size_t header_size;
    size_t message_size;
    uint32_t *session_id;
    libspdm_session_info_t *session_info;
    bool is_app_message;
    uint8_t *app_message;
    size_t app_message_size;

    spdm_test_context = libspdm_get_test_context();
    header_size = sizeof(libspdm_test_message_header_t);
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;
    case 0x2:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x3:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x4:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x5:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x6:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x7:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x8:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x9: {
        static size_t sub_index = 0;
        if (sub_index == 0) {
            m_libspdm_local_buffer_size = 0;
            message_size = libspdm_test_get_measurement_request_size(
                spdm_context, (uint8_t *)request + header_size,
                request_size - header_size);
            libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                             (uint8_t *)request + header_size,
                             message_size);
            m_libspdm_local_buffer_size += message_size;
            sub_index++;
        }
    }
        return RETURN_SUCCESS;
    case 0xA:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0xB:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0xC:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0xD:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0xE:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0xF:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x10:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x11:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x12:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x13:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x14:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x15:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x16:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x17:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x18:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x19:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x1A:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x1B:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x1C:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x1D:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x1E:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x1F:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x20:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x21:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x22:
        m_libspdm_local_buffer_size = 0;
        session_id = NULL;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, 0xFFFFFFFF);
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Request (0x%x):\n",
                       request_size));
        libspdm_dump_hex(request, request_size);
        libspdm_transport_test_decode_message(
            spdm_context, &session_id, &is_app_message,
            false, request_size, (uint8_t *)request,
            &app_message_size, (void **)&app_message);
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         app_message, app_message_size - 3);
        m_libspdm_local_buffer_size += app_message_size - 3;
        return RETURN_SUCCESS;
    case 0x23:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_measurement_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

return_status libspdm_requester_get_measurements_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    return_status status;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x3: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x5: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x6: {
        static size_t sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index1++;
        } else if (sub_index1 == 1) {
            spdm_measurements_response_t *spdm_response;
            uint8_t *ptr;
            uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
            size_t sig_size;
            size_t measurment_sig_size;
            spdm_measurement_block_dmtf_t *measurment_block;
            size_t spdm_response_size;
            size_t transport_header_size;

            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_libspdm_use_asym_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_libspdm_use_hash_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm
            .measurement_hash_algo =
                m_libspdm_use_measurement_hash_algo;
            measurment_sig_size =
                SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            spdm_response_size = sizeof(spdm_measurements_response_t) +
                                 sizeof(spdm_measurement_block_dmtf_t) +
                                 libspdm_get_measurement_hash_size(
                m_libspdm_use_measurement_hash_algo) +
                                 measurment_sig_size;
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_MEASUREMENTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->number_of_blocks = 1;
            libspdm_write_uint24(
                spdm_response->measurement_record_length,
                (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                           libspdm_get_measurement_hash_size(
                               m_libspdm_use_measurement_hash_algo)));
            measurment_block = (void *)(spdm_response + 1);
            libspdm_set_mem(measurment_block,
                            sizeof(spdm_measurement_block_dmtf_t) +
                            libspdm_get_measurement_hash_size(
                                m_libspdm_use_measurement_hash_algo),
                            1);
            measurment_block->measurement_block_common_header
            .measurement_specification =
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
            measurment_block->measurement_block_common_header
            .measurement_size = (uint16_t)(
                sizeof(spdm_measurement_block_dmtf_header_t) +
                libspdm_get_measurement_hash_size(
                    m_libspdm_use_measurement_hash_algo));
            ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                           measurment_sig_size);
            libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
            ptr += SPDM_NONCE_SIZE;
            *(uint16_t *)ptr = 0;
            ptr += sizeof(uint16_t);
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             spdm_response, (size_t)ptr - (size_t)spdm_response);
            m_libspdm_local_buffer_size +=
                ((size_t)ptr - (size_t)spdm_response);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                           m_libspdm_local_buffer_size));
            libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                             m_libspdm_local_buffer_size, hash_data);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                           libspdm_get_hash_size(m_libspdm_use_hash_algo)));
            libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
            sig_size =
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            libspdm_responder_data_sign(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    SPDM_MEASUREMENTS,
                    m_libspdm_use_asym_algo,
                    m_libspdm_use_hash_algo,
                    false, m_libspdm_local_buffer,
                    m_libspdm_local_buffer_size, ptr,
                    &sig_size);
            ptr += sig_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);
        }
    }
        return RETURN_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 1;
        spdm_response->extend_error_data.request_code =
            SPDM_GET_MEASUREMENTS;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x9: {
        static size_t sub_index2 = 0;
        if (sub_index2 == 0) {
            spdm_error_response_data_response_not_ready_t
            *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 1;
            spdm_response->extend_error_data.request_code =
                SPDM_GET_MEASUREMENTS;
            spdm_response->extend_error_data.token = 1;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index2++;
        } else if (sub_index2 == 1) {
            spdm_measurements_response_t *spdm_response;
            uint8_t *ptr;
            uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
            size_t sig_size;
            size_t measurment_sig_size;
            spdm_measurement_block_dmtf_t *measurment_block;
            size_t spdm_response_size;
            size_t transport_header_size;

            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_libspdm_use_asym_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_libspdm_use_hash_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm
            .measurement_hash_algo =
                m_libspdm_use_measurement_hash_algo;
            measurment_sig_size =
                SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            spdm_response_size = sizeof(spdm_measurements_response_t) +
                                 sizeof(spdm_measurement_block_dmtf_t) +
                                 libspdm_get_measurement_hash_size(
                m_libspdm_use_measurement_hash_algo) +
                                 measurment_sig_size;
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_MEASUREMENTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->number_of_blocks = 1;
            libspdm_write_uint24(
                spdm_response->measurement_record_length,
                (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                           libspdm_get_measurement_hash_size(
                               m_libspdm_use_measurement_hash_algo)));
            measurment_block = (void *)(spdm_response + 1);
            libspdm_set_mem(measurment_block,
                            sizeof(spdm_measurement_block_dmtf_t) +
                            libspdm_get_measurement_hash_size(
                                m_libspdm_use_measurement_hash_algo),
                            1);
            measurment_block->measurement_block_common_header
            .measurement_specification =
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
            measurment_block->measurement_block_common_header
            .measurement_size = (uint16_t)(
                sizeof(spdm_measurement_block_dmtf_header_t) +
                libspdm_get_measurement_hash_size(
                    m_libspdm_use_measurement_hash_algo));
            ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                           measurment_sig_size);
            libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
            ptr += SPDM_NONCE_SIZE;
            *(uint16_t *)ptr = 0;
            ptr += sizeof(uint16_t);
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             spdm_response, (size_t)ptr - (size_t)spdm_response);
            m_libspdm_local_buffer_size +=
                ((size_t)ptr - (size_t)spdm_response);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                           m_libspdm_local_buffer_size));
            libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                             m_libspdm_local_buffer_size, hash_data);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                           libspdm_get_hash_size(m_libspdm_use_hash_algo)));
            libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
            sig_size =
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            libspdm_responder_data_sign(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    SPDM_MEASUREMENTS,
                    m_libspdm_use_asym_algo,
                    m_libspdm_use_hash_algo,
                    false, m_libspdm_local_buffer,
                    m_libspdm_local_buffer_size, ptr,
                    &sig_size);
            ptr += sig_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);
        }
    }
        return RETURN_SUCCESS;

    case 0xA: {
        spdm_measurements_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t *ptr;
        spdm_response_size =
            sizeof(spdm_measurements_response_t)
            + SPDM_NONCE_SIZE + sizeof(uint16_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 0;
        libspdm_write_uint24(spdm_response->measurement_record_length, 0);

        ptr = (uint8_t *)spdm_response +
              sizeof(spdm_measurements_response_t);
        libspdm_get_random_number(SPDM_NONCE_SIZE,ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0xB: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t *ptr;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             SPDM_NONCE_SIZE + sizeof(uint16_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));

        ptr = (uint8_t *)spdm_response +
              sizeof(spdm_measurements_response_t) +
              sizeof(spdm_measurement_block_dmtf_t) +
              libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE,ptr);
        *(uint16_t *)(ptr + SPDM_NONCE_SIZE) = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0xC: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;

        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_set_mem(ptr, sig_size, 0);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0xD: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_get_random_number(sig_size, ptr);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0xE: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0xF: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_MEASUREMENTS + 1;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x10: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = LIBSPDM_ALTERNATIVE_DEFAULT_SLOT_ID;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x11: {
        static size_t sub_index0x11 = 0;

        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        spdm_response_size = sizeof(spdm_measurements_response_t);

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 1;
        spdm_response->header.param2 = 0;
        if (sub_index0x11 == 0) {
            spdm_response_size = sizeof(spdm_measurements_response_t) +
                                 sizeof(spdm_measurement_block_dmtf_t) +
                                 libspdm_get_measurement_hash_size(
                m_libspdm_use_measurement_hash_algo);
            spdm_response->number_of_blocks = 1;
            libspdm_write_uint24(
                spdm_response->measurement_record_length,
                (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                           libspdm_get_measurement_hash_size(
                               m_libspdm_use_measurement_hash_algo)));
            measurment_block = (void *)(spdm_response + 1);
            libspdm_set_mem(measurment_block,
                            sizeof(spdm_measurement_block_dmtf_t) +
                            libspdm_get_measurement_hash_size(
                                m_libspdm_use_measurement_hash_algo),
                            1);
            measurment_block->measurement_block_common_header
            .measurement_specification =
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
            measurment_block->measurement_block_common_header
            .measurement_size = (uint16_t)(
                sizeof(spdm_measurement_block_dmtf_header_t) +
                libspdm_get_measurement_hash_size(
                    m_libspdm_use_measurement_hash_algo));
        } else if (sub_index0x11 == 1) {
            spdm_response_size = sizeof(spdm_measurements_response_t);
            spdm_response->number_of_blocks = 1;
            libspdm_write_uint24(
                spdm_response->measurement_record_length, 0);
        } else if (sub_index0x11 == 2) {
            spdm_response_size = sizeof(spdm_measurements_response_t) +
                                 sizeof(spdm_measurement_block_dmtf_t) +
                                 libspdm_get_measurement_hash_size(
                m_libspdm_use_measurement_hash_algo);
            spdm_response->number_of_blocks = 0;
            libspdm_write_uint24(
                spdm_response->measurement_record_length,
                (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                           libspdm_get_measurement_hash_size(
                               m_libspdm_use_measurement_hash_algo)));
            measurment_block = (void *)(spdm_response + 1);
            libspdm_set_mem(measurment_block,
                            sizeof(spdm_measurement_block_dmtf_t) +
                            libspdm_get_measurement_hash_size(
                                m_libspdm_use_measurement_hash_algo),
                            1);
            measurment_block->measurement_block_common_header
            .measurement_specification =
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
            measurment_block->measurement_block_common_header
            .measurement_size = (uint16_t)(
                sizeof(spdm_measurement_block_dmtf_header_t) +
                libspdm_get_measurement_hash_size(
                    m_libspdm_use_measurement_hash_algo));
        }
        sub_index0x11++;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x12: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        uint8_t *large_spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        size_t count;

        large_spdm_response =
            (uint8_t *)malloc(sizeof(spdm_measurements_response_t) +
                              LIBSPDM_LARGE_MEASUREMENT_SIZE);

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)large_spdm_response;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = MAX_UINT8;
        libspdm_write_uint24(spdm_response->measurement_record_length,
                             (uint32_t)(LIBSPDM_LARGE_MEASUREMENT_SIZE));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block, LIBSPDM_LARGE_MEASUREMENT_SIZE, 1);
        for (count = 0; count < spdm_response->number_of_blocks;
             count++) {
            measurment_block->measurement_block_common_header.index =
                (uint8_t)(count + 1);
            measurment_block->measurement_block_common_header
            .measurement_specification =
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
            measurment_block->measurement_block_common_header
            .measurement_size = MAX_UINT16;
            spdm_response_size += (size_t)(
                sizeof(spdm_measurement_block_common_header_t) +
                MAX_UINT16);
        }

        spdm_response = (void *)((uint8_t *)(*response) + transport_header_size);
        if (spdm_response_size >  (size_t)(*response) + *response_size - (size_t)spdm_response) {
            spdm_response_size =  (size_t)(*response) + *response_size - (size_t)spdm_response;
        }
        libspdm_copy_mem (spdm_response, spdm_response_size,
                          large_spdm_response, spdm_response_size);

        status = libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false, spdm_response_size,
            spdm_response, response_size, response);

        free(large_spdm_response);
    }
        return status;

    case 0x13: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header.index = 1;
        measurment_block->measurement_block_common_header
        .measurement_specification = BIT0 | BIT1;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x14: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header.index = 1;
        measurment_block->measurement_block_common_header
        .measurement_specification = BIT2 | BIT1;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x15: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header.index = 1;
        measurment_block->measurement_block_common_header
        .measurement_specification =
            (uint8_t)(m_libspdm_use_measurement_spec << 1);
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x16: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t *ptr;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             SPDM_NONCE_SIZE + sizeof(uint16_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        *(uint16_t *)((uint8_t *)spdm_response +
                      sizeof(spdm_measurements_response_t) +
                      sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(
                          m_libspdm_use_measurement_hash_algo)) = 0;
        ptr = (uint8_t *)spdm_response + spdm_response_size - SPDM_NONCE_SIZE - sizeof(uint16_t);
        libspdm_get_random_number(SPDM_NONCE_SIZE,ptr);
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x17: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             SPDM_NONCE_SIZE +
                             sizeof(uint16_t) + SPDM_MAX_OPAQUE_DATA_SIZE;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* adding extra fields: opaque_length, opaque_data*/
        ptr = (void *)((uint8_t *)spdm_response +
                       sizeof(spdm_measurements_response_t) +
                       sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        libspdm_get_random_number (SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = SPDM_MAX_OPAQUE_DATA_SIZE; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, SPDM_MAX_OPAQUE_DATA_SIZE, 255);
        ptr += SPDM_MAX_OPAQUE_DATA_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x18: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             sizeof(uint16_t) +
                             (SPDM_MAX_OPAQUE_DATA_SIZE + 1);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* adding extra fields: opaque_length, opaque_data*/
        ptr = (void *)((uint8_t *)spdm_response +
                       sizeof(spdm_measurements_response_t) +
                       sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* libspdm_get_random_number (SPDM_NONCE_SIZE, ptr);
         * ptr += SPDM_NONCE_SIZE;*/
        *(uint16_t *)ptr =
            (SPDM_MAX_OPAQUE_DATA_SIZE + 1); /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, (SPDM_MAX_OPAQUE_DATA_SIZE + 1), 255);
        ptr += (SPDM_MAX_OPAQUE_DATA_SIZE + 1);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x19: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t opaque_size_test = SPDM_MAX_OPAQUE_DATA_SIZE;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + opaque_size_test +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint16_t *)ptr = opaque_size_test; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, opaque_size_test, 255);
        ptr += opaque_size_test;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x1A: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        size_t MissingBytes;
        uint16_t opaque_size_test = SPDM_MAX_OPAQUE_DATA_SIZE;

        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        MissingBytes = sig_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) +
            (opaque_size_test - MissingBytes) +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint16_t *)ptr = opaque_size_test; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, opaque_size_test - MissingBytes, 255);
        ptr += (opaque_size_test - MissingBytes);

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x1B: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        size_t MissingBytes;
        uint16_t opaque_size_test = SPDM_MAX_OPAQUE_DATA_SIZE;

        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        MissingBytes = sig_size + 1;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) +
            (opaque_size_test - MissingBytes) +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint16_t *)ptr = opaque_size_test; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, opaque_size_test - MissingBytes, 255);
        ptr += (opaque_size_test - MissingBytes);

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x1C: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t opaque_size_test = SPDM_MAX_OPAQUE_DATA_SIZE / 2;
        uint16_t opaque_informed_size = opaque_size_test - 1;

        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + opaque_size_test +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint16_t *)ptr = opaque_informed_size; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, opaque_size_test, 255);
        ptr += (opaque_size_test);

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x1D: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t opaque_size_test = SPDM_MAX_OPAQUE_DATA_SIZE / 2;
        uint16_t opaque_informed_size = opaque_size_test - 1;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             SPDM_NONCE_SIZE +
                             sizeof(uint16_t) + opaque_size_test;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* adding extra fields: opaque_length, opaque_data*/
        ptr = (void *)((uint8_t *)spdm_response +
                       sizeof(spdm_measurements_response_t) +
                       sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        libspdm_get_random_number (SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = opaque_informed_size; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, opaque_size_test, 255);
        ptr += opaque_size_test;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x1E: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t opaque_size_test = MAX_UINT16;
        uint16_t opaque_informed_size = SPDM_MAX_OPAQUE_DATA_SIZE / 2;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             sizeof(uint16_t) + opaque_size_test;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* adding extra fields: NONCE, opaque_length, opaque_data*/
        ptr = (void *)((uint8_t *)spdm_response +
                       sizeof(spdm_measurements_response_t) +
                       sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* libspdm_get_random_number (SPDM_NONCE_SIZE, ptr);
         * ptr += SPDM_NONCE_SIZE;*/
        *(uint16_t *)ptr = opaque_informed_size; /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, opaque_size_test, 255);
        ptr += opaque_size_test;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x1F: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t opaque_size_test = MAX_UINT16;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             SPDM_NONCE_SIZE + sizeof(uint16_t) +
                             opaque_size_test;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        /* adding extra fields: NONCE, opaque_length, opaque_data*/
        ptr = (void *)((uint8_t *)spdm_response +
                       sizeof(spdm_measurements_response_t) +
                       sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = (opaque_size_test); /* opaque_length*/
        ptr += sizeof(uint16_t);
        libspdm_set_mem(ptr, (opaque_size_test), 255);
        ptr += (opaque_size_test);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x20: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t *ptr;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             2 * (sizeof(spdm_measurement_block_dmtf_t) +
                                  libspdm_get_measurement_hash_size(
                                      m_libspdm_use_measurement_hash_algo)) +
                             SPDM_NONCE_SIZE;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 2;
        *(uint32_t *)spdm_response->measurement_record_length =
            2 * ((uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                            libspdm_get_measurement_hash_size(
                                m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        2 * (sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
                                 m_libspdm_use_measurement_hash_algo)),
                        1);
        measurment_block->measurement_block_common_header.index = 1;
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        measurment_block =
            (void *)(((uint8_t *)measurment_block) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(
                          m_libspdm_use_measurement_hash_algo)));
        measurment_block->measurement_block_common_header.index = 2;
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr =  (uint8_t *)spdm_response + spdm_response_size - SPDM_NONCE_SIZE;
        libspdm_get_random_number(SPDM_NONCE_SIZE,ptr);
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    case 0x21:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem (spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return RETURN_SUCCESS;
    case 0x22: {
        spdm_measurements_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t measurment_sig_size;
        spdm_measurement_block_dmtf_t *measurment_block;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        measurment_sig_size =
            SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
            libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             sizeof(spdm_measurement_block_dmtf_t) +
                             libspdm_get_measurement_hash_size(
            m_libspdm_use_measurement_hash_algo) +
                             measurment_sig_size;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(
            spdm_response->measurement_record_length,
            (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(
                            m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header
        .measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(
                           m_libspdm_use_measurement_hash_algo));
        ptr = (void *)((uint8_t *)spdm_response + spdm_response_size -
                       measurment_sig_size);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%x):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_MEASUREMENTS,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
    }
        return RETURN_SUCCESS;

    case 0x23: {
        spdm_measurements_response_t *spdm_response;
        spdm_measurement_block_dmtf_t *measurment_block;
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        size_t temp_buf_size;
        uint8_t *ptr;
        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        temp_buf_size = sizeof(spdm_measurements_response_t) +
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo) +
                        SPDM_NONCE_SIZE + sizeof(uint16_t);
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(spdm_response->measurement_record_length,
                             (uint32_t)(sizeof(spdm_measurement_block_dmtf_t) +
                                        libspdm_get_measurement_hash_size(
                                            m_libspdm_use_measurement_hash_algo)));
        measurment_block = (void *)(spdm_response + 1);
        libspdm_set_mem(measurment_block,
                        sizeof(spdm_measurement_block_dmtf_t) +
                        libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo),
                        1);
        measurment_block->measurement_block_common_header.measurement_specification =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        measurment_block->measurement_block_common_header.measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo));

        ptr = (uint8_t *)spdm_response +
              sizeof(spdm_measurements_response_t) +
              sizeof(spdm_measurement_block_dmtf_t) +
              libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE,ptr);
        *(uint16_t *)(ptr + SPDM_NONCE_SIZE) = 0;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         temp_buf, temp_buf_size);
        m_libspdm_local_buffer_size += temp_buf_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, temp_buf_size,
                                              temp_buf, response_size,
                                              response);
    }
        return RETURN_SUCCESS;

    default:
        return RETURN_DEVICE_ERROR;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case1(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 2: Successful response to get a measurement with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case2(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 3: Error case, attempt to get measurements before GET_DIGESTS, GET_CAPABILITIES, and NEGOTIATE_ALGORITHMS
 * Expected Behavior: get a RETURN_UNSUPPORTED return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case3(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_UNSUPPORTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 4: Error case, always get an error response with code SPDM_ERROR_CODE_INVALID_REQUEST
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case4(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 5: Error case, always get an error response with code SPDM_ERROR_CODE_BUSY
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case5(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_NO_RESPONSE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 6: Successfully get one measurement block (signed), after getting SPDM_ERROR_CODE_BUSY on first attempt
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case6(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 7: Error case, get an error response with code SPDM_ERROR_CODE_REQUEST_RESYNCH
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case7(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 8: Error case, always get an error response with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case8(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 9: Successfully get one measurement block (signed), after getting SPDM_ERROR_CODE_RESPONSE_NOT_READY on first attempt
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case9(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 10: Successful response to get total number of measurements, without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct number_of_blocks, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case10(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_blocks;
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    status = libspdm_get_measurement(
        spdm_context, NULL, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        0, NULL, &number_of_blocks, NULL, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(number_of_blocks, 4);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t));
#endif
    free(data);
}

/**
 * Test 11: Successful response to get a measurement block, without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case11(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t));
#endif
    free(data);
}

/**
 * Test 12: Error case, signature is invalid (all bytes are 0)
 * Expected Behavior: get a RETURN_SECURITY_VIOLATION return code
 **/
void libspdm_test_requester_get_measurements_case12(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 13: Error case, signature is invalid (random)
 * Expected Behavior: get a RETURN_SECURITY_VIOLATION return code
 **/
void libspdm_test_requester_get_measurements_case13(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 14: Error case, request a signed response, but response is malformed (signature absent)
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_requester_get_measurements_case14(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 15: Error case, response with wrong response code
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_requester_get_measurements_case15(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 16: SlotID verificaton, the response's SlotID should match the request
 * Expected Behavior: get a RETURN_SUCCESS return code if the fields match, RETURN_DEVICE_ERROR otherwise. Either way, transcript.message_m should be empty
 **/
void libspdm_test_requester_get_measurements_case16(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t SlotIDs[] = { 0, 1, 2, 3, 0xF };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    for (int i = 0; i < sizeof(SlotIDs) / sizeof(SlotIDs[0]); i++) {
        measurement_record_length = sizeof(measurement_record);
        libspdm_reset_message_m(spdm_context, NULL);
        status = libspdm_get_measurement(spdm_context, NULL,
                                         request_attribute, 1, SlotIDs[i],
                                         NULL, &number_of_block,
                                         &measurement_record_length,
                                         measurement_record);
        if (SlotIDs[i] == LIBSPDM_ALTERNATIVE_DEFAULT_SLOT_ID) {
            assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            assert_int_equal(
                spdm_context->transcript.message_m.buffer_size,
                0);
#endif
        } else if (SlotIDs[i] == 0xF) {
            assert_int_equal(status, RETURN_INVALID_PARAMETER);
        } else {
            assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            assert_int_equal(
                spdm_context->transcript.message_m.buffer_size,
                0);
#endif
        }
    }
    free(data);
}

/**
 * Test 17: Error case, response to get total number of measurements, but response number_of_blocks and/or measurement_record_length are non 0
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_requester_get_measurements_case17(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_blocks;
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    for (int i = 0; i < 3; i++) {
        /* i=0 => both number_of_blocks and measurement_record_length are non 0
         * i=1 => only number_of_blocks is non 0
         * i=2 => only is measurement_record_length is non 0*/
        status = libspdm_get_measurement(
            spdm_context, NULL, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            0, NULL, &number_of_blocks, NULL, NULL);
        assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                         0);
#endif
    }
    free(data);
}

/**
 * Test 18: Successful response to get a measurement block, without signature. Measurement block is the largest possible.
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case18(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     LIBSPDM_LARGE_MEASUREMENT_SIZE);
#endif
    free(data);
}

/**
 * Test 19: Error case, measurement_specification field in response has 2 bits set (bit 0 is one of them)
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 **/
void libspdm_test_requester_get_measurements_case19(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
/* #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT*/
    /* assert_int_equal (spdm_context->transcript.message_m.buffer_size, 0);*/
/* #endif*/
    free(data);
}

/**
 * Test 20: Error case, measurement_specification field in response has 2 bits set (bit 0 is not one of them)
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 **/
void libspdm_test_requester_get_measurements_case20(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
/* #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT*/
    /* assert_int_equal (spdm_context->transcript.message_m.buffer_size, 0);*/
/* #endif*/
    free(data);
}

/**
 * Test 21: Error case, measurement_specification field in response does not "match the selected measurement specification in the ALGORITHMS message"
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 **/
void libspdm_test_requester_get_measurements_case21(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
/* #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT*/
    /* assert_int_equal (spdm_context->transcript.message_m.buffer_size, 0);*/
/* #endif*/
    free(data);
}

/**
 * Test 22: request a large number of unsigned measurements before requesting a signature
 * Expected Behavior: RETURN_SUCCESS return code and correct transcript.message_m.buffer_size while transcript.message_m has room; RETURN_DEVICE_ERROR otherwise
 **/
void libspdm_test_requester_get_measurements_case22(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    size_t NumberOfMessages;
#define TOTAL_MESSAGES 100

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    for (NumberOfMessages = 1; NumberOfMessages <= TOTAL_MESSAGES;
         NumberOfMessages++) {
        status = libspdm_get_measurement(spdm_context, NULL,
                                         request_attribute, 1, 0,
                                         NULL, &number_of_block,
                                         &measurement_record_length,
                                         measurement_record);
        /* It may fail due to transcript.message_m overflow*/
        if (status == RETURN_SUCCESS) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            assert_int_equal(
                spdm_context->transcript.message_m.buffer_size,
                NumberOfMessages *
                (sizeof(spdm_message_header_t) +
                 sizeof(spdm_measurements_response_t) +
                 sizeof(spdm_measurement_block_dmtf_t) +
                 libspdm_get_measurement_hash_size(
                     m_libspdm_use_measurement_hash_algo) +
                 SPDM_NONCE_SIZE +
                 sizeof(uint16_t)));
#endif
        } else {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            assert_int_equal(
                spdm_context->transcript.message_m.buffer_size,
                0);
#endif
            break;
        }
    }
    free(data);
}

/**
 * Test 23: Successful response to get a measurement block, without signature. response contains opaque data
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case23(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     SPDM_NONCE_SIZE +
                     sizeof(uint16_t) + SPDM_MAX_OPAQUE_DATA_SIZE);
#endif
    free(data);
}

/**
 * Test 24: Error case, reponse contains opaque data larger than the maximum allowed
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case24(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data);
}

/**
 * Test 25: Successful response to get a measurement block, with signature. response contains opaque data
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case25(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 26: Error case, request with signature, but response opaque data is S bytes shorter than informed
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case26(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data);
}

/**
 * Test 27: Error case, request with signature, but response opaque data is (S+1) bytes shorter than informed
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case27(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data);
}

/**
 * Test 28: Error case, request with signature, but response opaque data is 1 byte longer than informed
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case28(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t ExpectedBufferSize;
#endif
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    ExpectedBufferSize = 0;
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     ExpectedBufferSize);
#endif
    free(data);
}

/**
 * Test 29: request measurement without signature, but response opaque data is 1 byte longer than informed
 * Expected Behavior: extra byte should just be ignored. Get a RETURN_SUCCESS return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case29(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     SPDM_NONCE_SIZE +
                     sizeof(uint16_t) +
                     SPDM_MAX_OPAQUE_DATA_SIZE / 2 - 1);
#endif
    free(data);
}

/**
 * Test 30: request measurement without signature, response opaque data contains MAXUINT16 bytes, but informed opaque data size is valid
 * Expected Behavior: extra bytes should just be ignored. Get a RETURN_SUCCESS return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case30(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     sizeof(uint16_t) +
                     SPDM_MAX_OPAQUE_DATA_SIZE / 2);
#endif
    free(data);
}

/**
 * Test 31: Error case, reponse contains opaque data larger than the maximum allowed. MAXUINT16 is used
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case31(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     sizeof(uint16_t) + MAX_UINT16);
#endif
    free(data);
}

/**
 * Test 32: Successful response to get all measurement blocks, without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m.buffer_size
 **/
void libspdm_test_requester_get_measurements_case32(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(
        spdm_context, NULL, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
        0, NULL, &number_of_block, &measurement_record_length,
        measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     2 * (sizeof(spdm_measurement_block_dmtf_t) +
                          libspdm_get_measurement_hash_size(
                              m_libspdm_use_measurement_hash_algo)) +
                     sizeof(uint16_t) + SPDM_NONCE_SIZE);
#endif
    free(data);
}

/**
 * Test 33: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_measurements_case33(void **state) {
    return_status status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
        libspdm_reset_message_m(spdm_context, NULL);

        measurement_record_length = sizeof(measurement_record);
        status = libspdm_get_measurement (spdm_context, NULL, request_attribute, 1, 0, NULL,
                                          &number_of_block, &measurement_record_length,
                                          measurement_record);
        /* assert_int_equal (status, RETURN_DEVICE_ERROR);*/
        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        /* assert_int_equal (spdm_context->transcript.message_m.buffer_size, 0);*/
        LIBSPDM_ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_m.buffer_size, 0,
                                       error_code);
#endif

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }

    free(data);
}

/**
 * Test 34: Successful response to get a session based measurement with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty session_transcript.message_m
 **/
void libspdm_test_requester_get_measurements_case34(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;
    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, &session_id, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 35: a request message is successfully sent and a response message is successfully received.
 * Buffer M already has arbitrary data. No signature is requested.
 * Expected Behavior: requester returns the status RETURN_SUCCESS and a MEASUREMENTS message is
 * received, buffer M appends the exchanged GET_MEASUREMENTS and MEASUREMENTS messages.
 **/
void libspdm_test_requester_get_measurements_case35(void **state)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t arbitrary_size;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0; /*do not request signature*/

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /*filling M buffer with arbitrary data*/
    arbitrary_size = 18;
    libspdm_set_mem(spdm_context->transcript.message_m.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_m.buffer_size = arbitrary_size;
#endif

    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement(spdm_context, NULL, request_attribute, 1,
                                     0, NULL, &number_of_block,
                                     &measurement_record_length,
                                     measurement_record);
    assert_int_equal(status, RETURN_SUCCESS);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     arbitrary_size + m_libspdm_local_buffer_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%x):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->transcript.message_m.buffer + arbitrary_size,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#endif
    free(data);
}

libspdm_test_context_t m_libspdm_requester_get_measurements_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_requester_get_measurements_test_send_message,
    libspdm_requester_get_measurements_test_receive_message,
};

int libspdm_requester_get_measurements_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_measurements_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case1),
        /* Successful response to get measurement with signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case9),
        /* Successful response to get total measurement number without signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case10),
        /* Successful response to get one measurement without signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case11),
        /* error: request signature, but response contains null signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case12),
        /* error: request signature, but response contains wrong non-null signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case13),
        /* error: request signature, but response does not contain signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case14),
        /* error: wrong response code*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case15),
        /* error: SlotID mismatch*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case16),
        /* error: get total measurement number (no signature), but there is a measurement block*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case17),
        /* Large measurement block
         * cmocka_unit_test(libspdm_test_requester_get_measurements_case18),    test triggers runtime assert because the transmitted packet is larger than the 4096-byte buffer
         * error: measurement_specification has 2 bits set (bit 0 is one of them)*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case19),
        /* error: measurement_specification has 2 bits set (bit 0 is not one of them)*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case20),
        /* error: measurement_specification does not "match the selected measurement specification in the ALGORITHMS message"*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case21),
        /* request a large number of measurement blocks before requesting a signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case22),
        /* Successful response to get one measurement with opaque data without signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case23),
        /* error: get one measurement with opaque data larger than 1024, without signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case24),
        /* Successful response to get one measurement with opaque data with signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case25),
        /* error: response to get one measurement with opaque data with signature, opaque data is S bytes shorter than announced*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case26),
        /* error: response to get one measurement with opaque data with signature, opaque data is S+1 bytes shorter than announced*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case27),
        /* error: response to get one measurement with opaque data with signature, opaque data is 1 byte longer than announced*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case28),
        /* response to get one measurement with opaque data without signature, opaque data is 1 byte longer than announced*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case29),
        /* response to get one measurement with opaque data without signature, opaque data has MAX_UINT16, but opaque data size is valid
         * cmocka_unit_test(libspdm_test_requester_get_measurements_case30),    test triggers runtime assert because the transmitted packet is larger than the 4096-byte buffer
         * error: get one measurement with opaque data too large, without signature
         * cmocka_unit_test(libspdm_test_requester_get_measurements_case31),    test triggers runtime assert because the transmitted packet is larger than the 4096-byte buffer
         * Successful response to get all measurements without signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case32),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case33),
        /* Successful response to get a session based measurement with signature*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case34),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_requester_get_measurements_case35),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_get_measurements_test_context);

    return cmocka_run_group_tests(spdm_requester_get_measurements_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
