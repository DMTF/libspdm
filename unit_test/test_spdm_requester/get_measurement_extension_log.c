/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000

uint8_t m_libspdm_mel_test[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
size_t m_libspdm_mel_len;
uint8_t m_libspdm_mel_number;

void generate_mel_entry_test()
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    uint32_t mel_index;
    spdm_mel_entry_dmtf_t *mel_entry;
    size_t mel_entry_size;
    uint8_t rom_infomational[] = "ROM";

    /*generate MEL*/
    libspdm_zero_mem(m_libspdm_mel_test, sizeof(m_libspdm_mel_test));
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;

    measurement_extension_log->number_of_entries = 0;
    measurement_extension_log->mel_entries_len = 0;
    measurement_extension_log->reserved = 0;

    m_libspdm_mel_len = sizeof(spdm_measurement_extension_log_dmtf_t);
    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                          sizeof(spdm_measurement_extension_log_dmtf_t));

    mel_index = 0;
    mel_entry_size = 0;

    while (1)
    {
        if((m_libspdm_mel_len + sizeof(spdm_mel_entry_dmtf_t) + sizeof(rom_infomational)) >
           sizeof(m_libspdm_mel_test)) {
            break;
        }

        mel_entry->mel_index = mel_index;
        mel_entry->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;

        libspdm_write_uint24(mel_entry->reserved, 0);
        mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION |
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
        mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
            sizeof(rom_infomational);
        libspdm_copy_mem((void *)(mel_entry + 1), sizeof(rom_infomational),
                         rom_infomational, sizeof(rom_infomational));

        mel_entry_size = (sizeof(spdm_mel_entry_dmtf_t) + sizeof(rom_infomational));
        m_libspdm_mel_len += mel_entry_size;

        measurement_extension_log->number_of_entries = mel_index;
        measurement_extension_log->mel_entries_len += (uint32_t)mel_entry_size;
        measurement_extension_log->reserved = 0;

        mel_entry = (spdm_mel_entry_dmtf_t *)
                    ((uint8_t *)mel_entry + sizeof(spdm_mel_entry_dmtf_t)+
                     mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);

        mel_index++;
    }
}

/*generate different long mel according to the m_libspdm_mel_number*/
void libspdm_generate_long_mel(uint32_t measurement_hash_algo)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry1;
    spdm_mel_entry_dmtf_t *mel_entry2;
    spdm_mel_entry_dmtf_t *mel_entry3;
    spdm_mel_entry_dmtf_t *mel_entry;
    uint8_t index;

    uint8_t rom_informational[] = "ROM";
    uint8_t bootfv_informational[] = "Boot FW";
    uint32_t version = 0x0100030A;

    /*generate MEL*/
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;

    measurement_extension_log->number_of_entries = m_libspdm_mel_number;
    measurement_extension_log->mel_entries_len =
        measurement_extension_log->number_of_entries * sizeof(spdm_mel_entry_dmtf_t) +
        sizeof(rom_informational) - 1 + sizeof(bootfv_informational) - 1 +
        sizeof(version) * (m_libspdm_mel_number - 2);
    measurement_extension_log->reserved = 0;

    /*MEL Entry 1: informational ROM */
    mel_entry1 = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                           sizeof(spdm_measurement_extension_log_dmtf_t));
    mel_entry1->mel_index = 1;
    mel_entry1->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    libspdm_write_uint24(mel_entry1->reserved, 0);
    mel_entry1->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    mel_entry1->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        sizeof(rom_informational) - 1;
    libspdm_copy_mem((void *)(mel_entry1 + 1), sizeof(rom_informational) - 1,
                     rom_informational, sizeof(rom_informational) - 1);

    /*MEL Entry 2: informational Boot FW */
    mel_entry2 = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry1 + 1) +
                                           sizeof(rom_informational) - 1);
    mel_entry2->mel_index = 2;
    mel_entry2->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    libspdm_write_uint24(mel_entry2->reserved, 0);
    mel_entry2->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    mel_entry2->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        sizeof(bootfv_informational) - 1;
    libspdm_copy_mem((void *)(mel_entry2 + 1), sizeof(bootfv_informational) - 1,
                     bootfv_informational, sizeof(bootfv_informational) - 1);

    /*MEL Entry 3: version 0x0100030A */
    mel_entry3 = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry2 + 1) +
                                           sizeof(bootfv_informational) - 1);
    mel_entry3->mel_index = 3;
    mel_entry3->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    libspdm_write_uint24(mel_entry3->reserved, 0);
    mel_entry3->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    mel_entry3->measurement_block_dmtf_header.dmtf_spec_measurement_value_size = sizeof(version);
    libspdm_copy_mem((void *)(mel_entry3 + 1), sizeof(version), &version, sizeof(version));

    /*MEL Entry 4 -> m_libspdm_mel_number: version 0x0100030A */
    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry3 + 1) +
                                          sizeof(version));
    for (index = 4; index <= m_libspdm_mel_number; index++) {
        mel_entry->mel_index = index;
        mel_entry->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
        libspdm_write_uint24(mel_entry->reserved, 0);
        mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION |
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
        mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
            sizeof(version);
        libspdm_copy_mem((void *)(mel_entry + 1), sizeof(version), &version, sizeof(version));
        mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry + 1) + sizeof(version));
    }
}

libspdm_return_t libspdm_requester_get_measurement_extension_log_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
    case 0x3:
    case 0x4:
    case 0x5:
    case 0x6:
    case 0x7:
    case 0x8:
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_measurement_extension_log_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t portion_length;
        uint32_t remainder_length;
        size_t count;
        static size_t calling_index = 0;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;

        spdm_mel = NULL;
        m_libspdm_mel_len = 0;

        libspdm_measurement_extension_log_collection(
            spdm_context,
            m_libspdm_use_mel_spec,
            m_libspdm_use_measurement_spec,
            m_libspdm_use_measurement_hash_algo,
            (void **)&spdm_mel, &m_libspdm_mel_len);

        count = (m_libspdm_mel_len + LIBSPDM_MAX_MEL_BLOCK_LEN - 1) / LIBSPDM_MAX_MEL_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
            remainder_length =
                (uint32_t)(m_libspdm_mel_len -
                           LIBSPDM_MAX_MEL_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint32_t)(
                m_libspdm_mel_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_measurement_extension_log_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel +
                         LIBSPDM_MAX_MEL_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3: {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t portion_length;
        uint32_t remainder_length;
        size_t count;
        static size_t calling_index = 0;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;
        spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
        size_t mel_new_len;
        size_t mel_send_len;

        spdm_mel = NULL;
        m_libspdm_mel_len = 0;
        mel_new_len = 0;
        mel_send_len = 0;
        m_libspdm_mel_number = 3;

        libspdm_generate_long_mel(m_libspdm_use_measurement_hash_algo);

        measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
        m_libspdm_mel_len = (size_t)(measurement_extension_log->mel_entries_len) +
                            sizeof(spdm_measurement_extension_log_dmtf_t);

        if (calling_index == 1) {
            m_libspdm_mel_number = 4;
            libspdm_generate_long_mel(m_libspdm_use_measurement_hash_algo);
            measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
            mel_new_len = (size_t)(measurement_extension_log->mel_entries_len) +
                          sizeof(spdm_measurement_extension_log_dmtf_t);
        }

        mel_send_len = (m_libspdm_mel_len > mel_new_len) ? m_libspdm_mel_len : mel_new_len;

        count = (mel_send_len + LIBSPDM_MAX_MEL_BLOCK_LEN - 1) / LIBSPDM_MAX_MEL_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
            remainder_length =
                (uint32_t)(mel_send_len -
                           LIBSPDM_MAX_MEL_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint32_t)(
                m_libspdm_mel_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1));
            remainder_length = (uint32_t)(
                mel_send_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1) -
                portion_length);
        }

        spdm_response_size =
            sizeof(spdm_measurement_extension_log_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel +
                         LIBSPDM_MAX_MEL_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4: {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t portion_length;
        uint32_t remainder_length;
        size_t count;
        static size_t calling_index = 0;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;
        spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
        size_t mel_new_len;
        size_t mel_send_len;

        spdm_mel = NULL;
        m_libspdm_mel_len = 0;
        mel_new_len = 0;
        mel_send_len = 0;
        m_libspdm_mel_number = 100;

        libspdm_generate_long_mel(m_libspdm_use_measurement_hash_algo);

        measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
        m_libspdm_mel_len = (size_t)(measurement_extension_log->mel_entries_len) +
                            sizeof(spdm_measurement_extension_log_dmtf_t);

        if (calling_index == 1) {
            m_libspdm_mel_number = 105;
            libspdm_generate_long_mel(m_libspdm_use_measurement_hash_algo);
            measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
            mel_new_len = (size_t)(measurement_extension_log->mel_entries_len) +
                          sizeof(spdm_measurement_extension_log_dmtf_t);
        }

        mel_send_len = (m_libspdm_mel_len > mel_new_len) ? m_libspdm_mel_len : mel_new_len;

        count = (m_libspdm_mel_len + LIBSPDM_MAX_MEL_BLOCK_LEN - 1) / LIBSPDM_MAX_MEL_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
            remainder_length =
                (uint32_t)(mel_send_len -
                           LIBSPDM_MAX_MEL_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint32_t)(
                m_libspdm_mel_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1));
            remainder_length = (uint32_t)(
                mel_send_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1) -
                portion_length);
        }

        spdm_response_size =
            sizeof(spdm_measurement_extension_log_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel +
                         LIBSPDM_MAX_MEL_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5: {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t portion_length;
        uint32_t remainder_length;
        size_t count;
        static size_t calling_index = 0;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;
        spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
        size_t mel_new_len;
        size_t mel_send_len;

        spdm_mel = NULL;
        m_libspdm_mel_len = 0;
        mel_new_len = 0;
        mel_send_len = 0;
        m_libspdm_mel_number = 100;

        libspdm_generate_long_mel(m_libspdm_use_measurement_hash_algo);

        measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
        m_libspdm_mel_len = (size_t)(measurement_extension_log->mel_entries_len) +
                            sizeof(spdm_measurement_extension_log_dmtf_t);

        if (calling_index == 1) {
            m_libspdm_mel_number = 200;
            libspdm_generate_long_mel(m_libspdm_use_measurement_hash_algo);
            measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;
            mel_new_len = (size_t)(measurement_extension_log->mel_entries_len) +
                          sizeof(spdm_measurement_extension_log_dmtf_t);
        }

        mel_send_len = (m_libspdm_mel_len > mel_new_len) ? m_libspdm_mel_len : mel_new_len;

        count = (m_libspdm_mel_len + LIBSPDM_MAX_MEL_BLOCK_LEN - 1) / LIBSPDM_MAX_MEL_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
            remainder_length =
                (uint32_t)(mel_send_len -
                           LIBSPDM_MAX_MEL_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint32_t)(
                m_libspdm_mel_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1));
            remainder_length = (uint32_t)(
                mel_send_len -
                LIBSPDM_MAX_MEL_BLOCK_LEN * (count - 1) -
                portion_length);
        }

        spdm_response_size =
            sizeof(spdm_measurement_extension_log_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel +
                         LIBSPDM_MAX_MEL_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
    {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t portion_length;
        uint32_t remainder_length;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;

        static size_t count = 0;
        static size_t calling_index = 0;

        if (calling_index == 0) {
            count = (m_libspdm_mel_len / LIBSPDM_MAX_MEL_BLOCK_LEN) + 1;
        }

        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        if(m_libspdm_mel_len > LIBSPDM_MAX_MEL_BLOCK_LEN) {
            portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
            remainder_length =
                (uint32_t)(m_libspdm_mel_len - LIBSPDM_MAX_MEL_BLOCK_LEN);
        } else {
            portion_length  = (uint32_t)m_libspdm_mel_len;
            remainder_length = 0;
        }

        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;

        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel +
                         LIBSPDM_MAX_MEL_BLOCK_LEN * calling_index,
                         portion_length);

        spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) + portion_length;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        m_libspdm_mel_len -= portion_length;;
        calling_index++;

        if (calling_index == count) {
            calling_index = 0;
            m_libspdm_mel_len = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7:
    {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;

        static size_t calling_index = 0;

        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        if (calling_index == 0) {
            spdm_response->portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
            spdm_response->remainder_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
        } else {
            /* The total amount of messages actually sent by the responder is less than the negotiated total mel len*/
            spdm_response->portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN / 2;
            spdm_response->remainder_length = 0;
        }

        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel,
                         LIBSPDM_MAX_MEL_BLOCK_LEN);

        spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) +
                             LIBSPDM_MAX_MEL_BLOCK_LEN;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        calling_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
    {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;

        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        /* Portion_length is greater than the LIBSPDM_MAX_MEL_BLOCK_LEN */
        spdm_response->portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN + 1;
        spdm_response->remainder_length = 0;

        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel,
                         LIBSPDM_MAX_MEL_BLOCK_LEN);

        spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) +
                             LIBSPDM_MAX_MEL_BLOCK_LEN;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9:
    {
        spdm_measurement_extension_log_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        spdm_measurement_extension_log_dmtf_t *spdm_mel;

        spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel_test;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        /* The total MEL length is larger than SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE*/
        spdm_response->portion_length = LIBSPDM_MAX_MEL_BLOCK_LEN;
        spdm_response->remainder_length = SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE;

        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)spdm_mel,
                         LIBSPDM_MAX_MEL_BLOCK_LEN);

        spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) +
                             LIBSPDM_MAX_MEL_BLOCK_LEN;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a LIBSPDM_STATUS_SEND_FAIL, with no MEL messages received
 **/
void libspdm_test_requester_get_measurement_extension_log_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    libspdm_reset_message_b(spdm_context);

    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 2: Normal case, request a MEL, the MEL size remains unchanged
 * Expected Behavior: receives a valid MEL
 **/
void libspdm_test_requester_get_measurement_extension_log_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_mel_size, m_libspdm_mel_len);
}

/**
 * Test 3: Normal case, request a MEL, the MEL size become more bigger when get MEL
 * The original MEL number is 3, the new MEL number is 4.
 * Expected Behavior: receives a valid MEL, and the MEL size is same with the before MEL size.
 **/
void libspdm_test_requester_get_measurement_extension_log_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_mel_size, m_libspdm_mel_len);
}

/**
 * Test 4: Normal case, request a MEL, the MEL size become more bigger when get MEL
 * The original MEL number is 100, the new MEL number is 105.
 * Expected Behavior: receives a valid MEL, and the MEL size is same with the before MEL size.
 **/
void libspdm_test_requester_get_measurement_extension_log_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_mel_size, m_libspdm_mel_len);
}

/**
 * Test 5: Normal case, request a MEL, the MEL size become more bigger when get MEL
 * The original MEL number is 100, the new MEL number is 200.
 * Expected Behavior: receives a valid MEL, and the MEL size is same with the before MEL size.
 **/
void libspdm_test_requester_get_measurement_extension_log_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_mel_size, m_libspdm_mel_len);
}

/**
 * Test 6: Normal case, request a LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE MEL
 * Expected Behavior: receives a valid MEL
 **/
void libspdm_test_requester_get_measurement_extension_log_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    generate_mel_entry_test();
    mel_buffer_size = m_libspdm_mel_len;

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_mel_size, mel_buffer_size);
    assert_memory_equal(m_libspdm_mel_test, (void *)spdm_mel, spdm_mel_size);
}

/**
 * Test 7: The total amount of messages actually sent by the responder is less than the negotiated total mel len.
 * Expected Behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
void libspdm_test_requester_get_measurement_extension_log_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    generate_mel_entry_test();

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 8: Portion_length is greater than the LIBSPDM_MAX_MEL_BLOCK_LEN
 * Expected Behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
void libspdm_test_requester_get_measurement_extension_log_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    generate_mel_entry_test();

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 9: The total MEL length is larger than SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE
 * Expected Behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
void libspdm_test_requester_get_measurement_extension_log_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    generate_mel_entry_test();

    status = libspdm_get_measurement_extension_log(spdm_context, NULL,
                                                   &spdm_mel_size, spdm_mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

int libspdm_requester_get_measurement_extension_log_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_measurement_extension_log_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case1),
        /* Successful response, the MEL size remains unchanged*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case2),
        /* Successful response, the MEL size become more bigger when get MEL. MEL number change from 3 to 4*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case3),
        /* Successful response, the MEL size become more bigger when get MEL. MEL number change from 100 to 105*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case4),
        /* Successful response, the MEL size become more bigger when get MEL. MEL number change from 100 to 200*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case5),
        /* Successful response , LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case6),
        /* Failed response , The total amount of messages actually sent by the responder is less than the negotiated total mel len*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case7),
        /* Failed response , Portion_length is greater than the LIBSPDM_MAX_MEL_BLOCK_LEN*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case8),
        /* Failed response , The total MEL length is larger than SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE*/
        cmocka_unit_test(libspdm_test_requester_get_measurement_extension_log_case9),

    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        libspdm_requester_get_measurement_extension_log_test_send_message,
        libspdm_requester_get_measurement_extension_log_test_receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(spdm_requester_get_measurement_extension_log_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
