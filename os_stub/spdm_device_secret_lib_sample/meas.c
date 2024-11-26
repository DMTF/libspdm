/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP)

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000
uint8_t m_libspdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) */

#if (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP)
void libspdm_generate_mel(uint32_t measurement_hash_algo)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry1;
    spdm_mel_entry_dmtf_t *mel_entry2;
    spdm_mel_entry_dmtf_t *mel_entry3;

    uint8_t rom_informational[] = "ROM";
    uint8_t bootfv_informational[] = "Boot FW";
    uint32_t version = 0x0100030A;

    /*generate MEL*/
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;

    measurement_extension_log->number_of_entries = 3;
    measurement_extension_log->mel_entries_len =
        measurement_extension_log->number_of_entries * sizeof(spdm_mel_entry_dmtf_t) +
        sizeof(rom_informational) - 1 + sizeof(bootfv_informational) - 1 + sizeof(version);
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
}
#endif /*(LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP)*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/**
 * Fill image hash measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_image_hash_block (
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    size_t hash_size;
    uint8_t data[LIBSPDM_MEASUREMENT_RAW_DATA_SIZE];
    bool result;

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);

    measurement_block->measurement_block_common_header
    .index = measurements_index;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_set_mem(data, sizeof(data), (uint8_t)(measurements_index));

    if (!use_bit_stream) {
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
            (measurements_index - 1);
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
            (uint16_t)hash_size;

        measurement_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)hash_size);

        result = libspdm_measurement_hash_all(
            measurement_hash_algo, data,
            sizeof(data),
            (void *)(measurement_block + 1));
        if (!result) {
            return 0;
        }

        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;

    } else {
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
            (measurements_index - 1) |
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
            (uint16_t)sizeof(data);

        measurement_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)sizeof(data));

        libspdm_copy_mem((void *)(measurement_block + 1), sizeof(data), data, sizeof(data));

        return sizeof(spdm_measurement_block_dmtf_t) + sizeof(data);
    }
}

/**
 * Fill svn measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_svn_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    spdm_measurements_secure_version_number_t svn;

    measurement_block->measurement_block_common_header
    .index = LIBSPDM_MEASUREMENT_INDEX_SVN;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    svn = 0x7;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(svn);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(svn));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(svn), (void *)&svn, sizeof(svn));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(svn);
}

/**
 * Fill HEM measurement block.
 *
 * @param  measurement_block          A pointer to store measurement block.
 * @param  measurement_hash_algo      Indicates the measurement hash algorithm.
 *                                    It must align with measurement_hash_alg
 *                                    (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_hem_block (
    spdm_measurement_block_dmtf_t *measurement_block, uint32_t measurement_hash_algo
    )
{
    size_t hash_size;
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry;
    uint32_t index;
    uint8_t *verify_hem;

    if (measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) {
        return 0;
    }

    libspdm_generate_mel(measurement_hash_algo);

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
    }

    /*MEL*/
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;

    /*generate measurement block*/
    measurement_block->measurement_block_common_header
    .index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HASH_EXTEND_MEASUREMENT;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)hash_size;

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)hash_size);

    verify_hem = malloc(measurement_extension_log->mel_entries_len + hash_size);
    if (verify_hem == NULL) {
        return 0;
    }

    libspdm_zero_mem(verify_hem, measurement_extension_log->mel_entries_len + hash_size);
    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                          sizeof(spdm_measurement_extension_log_dmtf_t));
    for (index = 0; index < measurement_extension_log->number_of_entries; index++) {
        libspdm_copy_mem(
            verify_hem + hash_size,
            measurement_extension_log->mel_entries_len,
            mel_entry,
            sizeof(spdm_mel_entry_dmtf_t) +
            mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);

        if (!libspdm_measurement_hash_all(
                measurement_hash_algo,
                verify_hem,
                hash_size + sizeof(spdm_mel_entry_dmtf_t) +
                mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size,
                verify_hem
                )) {
            free(verify_hem);
            return 0;
        }
        mel_entry = (spdm_mel_entry_dmtf_t *)
                    ((uint8_t *)mel_entry + sizeof(spdm_mel_entry_dmtf_t)+
                     mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
    }

    libspdm_copy_mem((void *)(measurement_block + 1), hash_size, verify_hem, hash_size);
    free(verify_hem);
    return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
}

/**
 * Fill manifest measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_manifest_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    uint8_t data[LIBSPDM_MEASUREMENT_MANIFEST_SIZE];

    measurement_block->measurement_block_common_header
    .index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_set_mem(data, sizeof(data),
                    (uint8_t)SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST);

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(data);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(data));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(data), data, sizeof(data));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(data);
}

/**
 * Fill device mode measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_device_mode_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    spdm_measurements_device_mode_t device_mode;

    measurement_block->measurement_block_common_header
    .index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    device_mode.operational_mode_capabilities =
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_MANUFACTURING_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_VALIDATION_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RECOVERY_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RMA_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_DECOMMISSIONED_MODE;
    device_mode.operational_mode_state =
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE;
    device_mode.device_mode_capabilities =
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG;
    device_mode.device_mode_state =
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(device_mode);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(device_mode));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(device_mode),
                     (void *)&device_mode, sizeof(device_mode));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(device_mode);
}

libspdm_return_t libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *measurements_count,
    void *measurements,
    size_t *measurements_size)
{
    spdm_measurement_block_dmtf_t *measurement_block;
    size_t hash_size;
    uint8_t index;
    size_t total_size_needed;
    bool use_bit_stream;
    size_t measurement_block_size;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    LIBSPDM_ASSERT(hash_size != 0);

    use_bit_stream = false;
    if ((measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) ||
        ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED) !=
         0)) {
        use_bit_stream = true;
    }

    if (measurements_index ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
        goto successful_return;
    } else if (measurements_index ==
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* Calculate total_size_needed based on hash algo selected.
         * If we have an hash algo, then the first HASH_NUMBER elements will be
         * hash values, otherwise HASH_NUMBER raw bitstream values.*/
        if (!use_bit_stream) {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + hash_size);
        } else {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_RAW_DATA_SIZE);
        }
        /* Next one - SVN is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) +
             sizeof(spdm_measurements_secure_version_number_t));
        /* Next one - HEM is always digest data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + hash_size);
        /* Next one - manifest is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_MANIFEST_SIZE);
        /* Next one - device_mode is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + sizeof(spdm_measurements_device_mode_t));

        LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
        if (total_size_needed > *measurements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *measurements_size = total_size_needed;
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
        measurement_block = measurements;

        /* The first HASH_NUMBER blocks may be hash values or raw bitstream*/
        for (index = 1; index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER; index++) {
            measurement_block_size = libspdm_fill_measurement_image_hash_block (use_bit_stream,
                                                                                measurement_hash_algo,
                                                                                index,
                                                                                measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - SVN is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_svn_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - HEM is always digest data.*/
        {
            measurement_block_size = libspdm_fill_measurement_hem_block (measurement_block,
                                                                         measurement_hash_algo);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - manifest is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_manifest_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - device_mode is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_device_mode_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }

        goto successful_return;
    } else {
        /* One Index */
        if (measurements_index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER) {
            if (!use_bit_stream) {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    hash_size;
            } else {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    LIBSPDM_MEASUREMENT_RAW_DATA_SIZE;
            }
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_image_hash_block (use_bit_stream,
                                                                                measurement_hash_algo,
                                                                                measurements_index,
                                                                                measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == LIBSPDM_MEASUREMENT_INDEX_SVN) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                sizeof(spdm_measurements_secure_version_number_t);
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_svn_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == LIBSPDM_MEASUREMENT_INDEX_HEM) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) + hash_size;
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_hem_block (measurement_block,
                                                                         measurement_hash_algo);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index ==
                   SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                LIBSPDM_MEASUREMENT_MANIFEST_SIZE;
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_manifest_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                sizeof(spdm_measurements_device_mode_t);
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_device_mode_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else {
            *measurements_count = 0;
            return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
        }
    }

successful_return:
    if ((content_changed != NULL) &&
        ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_12)) {
        /* return content change*/
        if ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
            0) {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED;
        } else {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

size_t libspdm_secret_lib_meas_opaque_data_size;

bool libspdm_measurement_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_meas_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_meas_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}

bool libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash,
    uint32_t measurement_summary_hash_size)
{
    uint8_t measurement_data[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t index;
    spdm_measurement_block_dmtf_t *cached_measurement_block;
    size_t measurement_data_size;
    size_t measurement_block_size;
    uint8_t device_measurement[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t device_measurement_count;
    size_t device_measurement_size;
    libspdm_return_t status;
    bool result;

    switch (measurement_summary_hash_type) {
    case SPDM_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        break;

    case SPDM_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_REQUEST_ALL_MEASUREMENTS_HASH:
        if (measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
            return false;
        }

        /* get all measurement data*/
        device_measurement_size = sizeof(device_measurement);
        status = libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_version, measurement_specification,
            measurement_hash_algo,
            0xFF, /* Get all measurements*/
            0,
            NULL,
            &device_measurement_count, device_measurement,
            &device_measurement_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }

        /* double confirm that MeasurementData internal size is correct*/
        measurement_data_size = 0;
        cached_measurement_block = (void *)device_measurement;
        for (index = 0; index < device_measurement_count; index++) {
            measurement_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            LIBSPDM_ASSERT(cached_measurement_block
                           ->measurement_block_common_header
                           .measurement_size ==
                           sizeof(spdm_measurement_block_dmtf_header_t) +
                           cached_measurement_block
                           ->measurement_block_dmtf_header
                           .dmtf_spec_measurement_value_size);
            measurement_data_size +=
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            cached_measurement_block =
                (void *)((size_t)cached_measurement_block +
                         measurement_block_size);
        }

        LIBSPDM_ASSERT(measurement_data_size <=
                       LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE);

        /* get required data and hash them*/
        cached_measurement_block = (void *)device_measurement;
        measurement_data_size = 0;
        for (index = 0; index < device_measurement_count; index++) {
            measurement_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            /* filter unneeded data*/
            if ((measurement_summary_hash_type ==
                 SPDM_REQUEST_ALL_MEASUREMENTS_HASH) ||
                ((cached_measurement_block
                  ->measurement_block_dmtf_header
                  .dmtf_spec_measurement_value_type &
                  SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) ==
                 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
                libspdm_copy_mem(&measurement_data[measurement_data_size],
                                 sizeof(measurement_data)
                                 - (&measurement_data[measurement_data_size] - measurement_data),
                                 cached_measurement_block,
                                 sizeof(cached_measurement_block->
                                        measurement_block_common_header) +
                                 cached_measurement_block->measurement_block_common_header
                                 .measurement_size);
                measurement_data_size +=
                    sizeof(cached_measurement_block->measurement_block_common_header) +
                    cached_measurement_block
                    ->measurement_block_common_header
                    .measurement_size;
            }
            cached_measurement_block =
                (void *)((size_t)cached_measurement_block +
                         measurement_block_size);
        }

        result = libspdm_hash_all(base_hash_algo, measurement_data,
                                  measurement_data_size, measurement_summary_hash);
        if (!result) {
            return false;
        }
        break;
    default:
        return false;
        break;
    }
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/*Collect the measurement extension log.*/
bool libspdm_measurement_extension_log_collection(
    void *spdm_context,
    uint8_t mel_specification,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    void **spdm_mel,
    size_t *spdm_mel_size)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (mel_specification != SPDM_MEL_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return false;
    }

    libspdm_generate_mel(measurement_hash_algo);

    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    *spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    *spdm_mel_size = (size_t)(measurement_extension_log->mel_entries_len) +
                     sizeof(spdm_measurement_extension_log_dmtf_t);
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
