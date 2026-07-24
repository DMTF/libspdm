/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"

size_t libspdm_get_opaque_data_version_selection_data_size(const libspdm_context_t *spdm_context)
{
    size_t size;

    if (spdm_context->local_context.secured_message_version.secured_message_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_version_selection_t);
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_version_selection_t);
    }
    /* Add Padding*/
    return (size + 3) & ~3;
}

size_t libspdm_get_opaque_data_supported_version_data_size(libspdm_context_t *spdm_context)
{
    size_t size;

    if (spdm_context->local_context.secured_message_version.secured_message_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) *
               spdm_context->local_context.secured_message_version.secured_message_version_count;
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) *
               spdm_context->local_context.secured_message_version.secured_message_version_count;
    }
    /* Add Padding*/
    return (size + 3) & ~3;
}

size_t libspdm_get_untrusted_opaque_data_supported_version_data_size(
    libspdm_context_t *spdm_context, uint8_t version_count)
{
    size_t size;

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) * version_count;
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) * version_count;
    }
    /* Add Padding*/
    return (size + 3) & ~3;
}

bool libspdm_get_element_from_opaque_data_with_element_id (libspdm_context_t *spdm_context,
                                                           size_t data_in_size, const void *data_in,
                                                           uint8_t element_id, uint8_t element_index,
                                                           uint8_t *total_matched_element_cnt,
                                                           const void **get_element_ptr, size_t *get_element_len)
{
    const secured_message_general_opaque_data_table_header_t *general_opaque_data_table_header;
    const spdm_general_opaque_data_table_header_t *spdm_general_opaque_data_table_header;
    const opaque_element_table_header_t *opaque_element_table_header;
    uint16_t opaque_element_data_len;

    bool result;
    uint8_t element_num;
    uint8_t index;
    uint8_t matched_element_cnt;
    size_t data_element_size;
    size_t current_element_len;
    size_t total_element_len;

    /*check parameter in*/
    if (element_id > SPDM_REGISTRY_ID_MAX) {
        return false;
    }
    if ((data_in_size == 0) || (data_in == NULL)) {
        return false;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (data_in_size < sizeof(spdm_general_opaque_data_table_header_t)) {
            return false;
        }
        if (spdm_general_opaque_data_table_header->total_elements < 1) {
            return false;
        }
        opaque_element_table_header = (const void *)(spdm_general_opaque_data_table_header + 1);

        element_num = spdm_general_opaque_data_table_header->total_elements;

        data_element_size = data_in_size - sizeof(spdm_general_opaque_data_table_header_t);
    } else {
        general_opaque_data_table_header = data_in;
        if (data_in_size < sizeof(secured_message_general_opaque_data_table_header_t)) {
            return false;
        }
        if ((general_opaque_data_table_header->spec_id != SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
            (general_opaque_data_table_header->opaque_version != SECURED_MESSAGE_OPAQUE_VERSION) ||
            (general_opaque_data_table_header->total_elements < 1)) {
            return false;
        }
        opaque_element_table_header = (const void *)(general_opaque_data_table_header + 1);

        element_num = general_opaque_data_table_header->total_elements;

        data_element_size = data_in_size -
                            sizeof(secured_message_general_opaque_data_table_header_t);
    }

    total_element_len = 0;
    result = false;

    /* find the Nth element with specific element_id, N = element_index. */
    matched_element_cnt = 0;
    for (index = 0; index < element_num; index++) {
        /*ensure the opaque_element_table_header is valid*/
        if (total_element_len + sizeof(opaque_element_table_header_t) >
            data_element_size) {
            return false;
        }

        /*check element header id*/
        if ((opaque_element_table_header->id > SPDM_REGISTRY_ID_MAX)) {
            return false;
        }

        if ((total_element_len + sizeof(opaque_element_table_header_t) +
             opaque_element_table_header->vendor_len + 2) > data_element_size) {
            return false;
        }

        opaque_element_data_len = libspdm_read_uint16(
            (const uint8_t *)opaque_element_table_header + sizeof(opaque_element_table_header_t) +
            opaque_element_table_header->vendor_len);

        current_element_len = sizeof(opaque_element_table_header_t) +
                              opaque_element_table_header->vendor_len + 2 + opaque_element_data_len;
        /* Add Padding*/
        current_element_len = (current_element_len + 3) & ~3;

        total_element_len += current_element_len;

        if (data_element_size < total_element_len) {
            return false;
        }

        if (opaque_element_table_header->id == element_id) {
            /*get element by element id*/
            if (matched_element_cnt == element_index) {
                *get_element_ptr = opaque_element_table_header;
                *get_element_len = current_element_len;
                result = true;
            }
            matched_element_cnt += 1;
        }

        /*move to next element*/
        opaque_element_table_header = (const opaque_element_table_header_t *)
                                      ((const uint8_t *)opaque_element_table_header +
                                       current_element_len);
    }

    /*ensure data size is right*/
    if (data_element_size != total_element_len) {
        return false;
    }

    *total_matched_element_cnt = matched_element_cnt;
    return result;
}

bool libspdm_get_sm_data_element_from_opaque_data (libspdm_context_t *spdm_context,
                                                   size_t data_in_size, const void *data_in,
                                                   uint8_t sm_data_id,
                                                   const void **get_element_ptr, size_t *get_element_len)
{
    const opaque_element_table_header_t *opaque_element_table_header;
    size_t opaque_element_len;
    const secured_message_opaque_element_table_header_t *secured_message_element_table_header;
    const secured_message_opaque_element_header_t *secured_message_element_header;
    bool result;
    uint8_t element_index;
    uint8_t element_num;
    uint8_t total_matched_element_cnt;

    /*check parameter in*/
    if ((data_in_size == 0) || (data_in == NULL)) {
        return false;
    }

    /*get the total matched element count*/
    result = libspdm_get_element_from_opaque_data_with_element_id(
        spdm_context, data_in_size, data_in,
        SPDM_REGISTRY_ID_DMTF, 0, &total_matched_element_cnt,
        (const void **) &opaque_element_table_header, &opaque_element_len);
    if (!result) {
        return false;
    }

    element_num = total_matched_element_cnt;
    for (element_index = 0; element_index < element_num; element_index++) {
        /*get element by element id*/
        result = libspdm_get_element_from_opaque_data_with_element_id(
            spdm_context, data_in_size, data_in,
            SPDM_REGISTRY_ID_DMTF, element_index, &total_matched_element_cnt,
            (const void **) &opaque_element_table_header, &opaque_element_len);
        if (!result) {
            return false;
        }

        secured_message_element_table_header = (const void *)opaque_element_table_header;
        if (secured_message_element_table_header->vendor_len == 0) {
            secured_message_element_header =
                (const void *)(secured_message_element_table_header + 1);
            if ((const uint8_t *)secured_message_element_header +
                sizeof(secured_message_opaque_element_header_t) >
                (const uint8_t *)data_in + data_in_size) {
                return false;
            }

            if ((secured_message_element_header->sm_data_id == sm_data_id) &&
                (secured_message_element_header->sm_data_version ==
                 SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION)) {
                *get_element_ptr = opaque_element_table_header;
                *get_element_len = opaque_element_len;
                return true;
            }
        }
    }

    return false;
}

bool libspdm_process_general_opaque_data_check(libspdm_context_t *spdm_context,
                                               size_t data_in_size,
                                               const void *data_in)
{
    const spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    const opaque_element_table_header_t
    *opaque_element_table_header;
    uint8_t element_num;
    uint8_t element_index;
    uint16_t opaque_element_data_len;
    size_t data_element_size;
    size_t current_element_len;
    size_t total_element_len;
    uint8_t zero_padding[4] = {0};

    total_element_len = 0;

    LIBSPDM_ASSERT(data_in_size <= SPDM_MAX_OPAQUE_DATA_SIZE);

    if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        if ((spdm_context->connection_info.algorithm.other_params_support &
             SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1) {
            /* Check byte alignment */
            if ((data_in_size & 3) != 0) {
                return false;
            }

            spdm_general_opaque_data_table_header = data_in;
            if (data_in_size < sizeof(spdm_general_opaque_data_table_header_t)) {
                return false;
            }
            if (spdm_general_opaque_data_table_header->total_elements < 1) {
                return false;
            }
            opaque_element_table_header = (const void *)(spdm_general_opaque_data_table_header + 1);

            element_num = spdm_general_opaque_data_table_header->total_elements;

            data_element_size = data_in_size - sizeof(spdm_general_opaque_data_table_header_t);

            for (element_index = 0; element_index < element_num; element_index++) {
                /*ensure the opaque_element_table_header is valid*/
                if (total_element_len + sizeof(opaque_element_table_header_t) +
                    sizeof(opaque_element_data_len) >
                    data_element_size) {
                    return false;
                }

                /*check element header id*/
                if (opaque_element_table_header->id > SPDM_REGISTRY_ID_MAX) {
                    return false;
                }

                /*ensure the vendor_id and opaque_element_data_len field are within the buffer*/
                if (total_element_len + sizeof(opaque_element_table_header_t) +
                    opaque_element_table_header->vendor_len +
                    sizeof(opaque_element_data_len) >
                    data_element_size) {
                    return false;
                }

                opaque_element_data_len = libspdm_read_uint16(
                    (const uint8_t *)(opaque_element_table_header + 1) +
                    opaque_element_table_header->vendor_len);

                current_element_len = sizeof(opaque_element_table_header_t) +
                                      opaque_element_table_header->vendor_len +
                                      sizeof(opaque_element_data_len) +
                                      opaque_element_data_len;

                /*ensure the element with padding is within the buffer before reading it*/
                if (total_element_len + ((current_element_len + 3) & ~3) >
                    data_element_size) {
                    return false;
                }

                if ((current_element_len & 3) != 0) {
                    if (!libspdm_consttime_is_mem_equal(zero_padding,
                                                        (uint8_t *)(size_t)
                                                        (opaque_element_table_header) +
                                                        current_element_len,
                                                        4 - (current_element_len & 3))) {
                        return false;
                    }
                }
                /* Add Padding*/
                current_element_len = (current_element_len + 3) & ~3;

                total_element_len += current_element_len;

                /*move to next element*/
                opaque_element_table_header =
                    (const opaque_element_table_header_t *)
                    ((const uint8_t *)opaque_element_table_header +
                     current_element_len);
            }
        }
    }

    return true;
}

/**
 * Process opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.
 *
 * @param  data_in_size                   size in bytes of the data_in.
 * @param  data_in                       A pointer to the buffer to store the opaque data version selection.
 **/
libspdm_return_t libspdm_process_opaque_data_version_selection_data(
    libspdm_context_t *spdm_context, size_t data_in_size, void *data_in,
    spdm_version_number_t *secured_message_version)
{
    const secured_message_opaque_element_table_header_t *opaque_element_table_header;
    const secured_message_opaque_element_version_selection_t *opaque_element_version_section;

    bool result;
    uint8_t secured_message_version_index;
    const void *get_element_ptr;
    size_t get_element_len;

    result = false;
    get_element_ptr = NULL;

    if (spdm_context->local_context.secured_message_version.secured_message_version_count == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    result = libspdm_get_sm_data_element_from_opaque_data(
        spdm_context, data_in_size, data_in,
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION,
        &get_element_ptr, &get_element_len);
    if ((!result) || (get_element_ptr == NULL)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"get element error!\n"));
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    opaque_element_table_header = (const secured_message_opaque_element_table_header_t*)
                                  get_element_ptr;

    /* Check for selection version data. */
    if ((opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_version_selection_t))) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    opaque_element_version_section = (const void *)(opaque_element_table_header + 1);

    if ((const uint8_t *)opaque_element_version_section +
        sizeof(secured_message_opaque_element_version_selection_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    for (secured_message_version_index = 0;
         secured_message_version_index <
         spdm_context->local_context.secured_message_version.secured_message_version_count;
         secured_message_version_index++) {
        if (libspdm_get_version_from_version_number(opaque_element_version_section->
                                                    selected_version)
            ==
            libspdm_get_version_from_version_number(
                spdm_context->local_context.secured_message_version.secured_message_version[
                    secured_message_version_index])) {
            libspdm_copy_mem(secured_message_version,
                             sizeof(spdm_version_number_t),
                             &(opaque_element_version_section->selected_version),
                             sizeof(spdm_version_number_t));
            return LIBSPDM_STATUS_SUCCESS;
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

/* Return the highest secured message version this endpoint offers in its local supported list, in
 * version-number form (e.g. SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT), or 0 if the
 * list is empty. The Requester uses this as the "version" to gate the AEADlimitOE element in its
 * request, since no version has been negotiated yet at that point. */
spdm_version_number_t libspdm_local_max_secured_message_version(
    const libspdm_context_t *spdm_context)
{
    uint8_t index;
    spdm_version_number_t max_version;

    max_version = 0;
    for (index = 0;
         index < spdm_context->local_context.secured_message_version.secured_message_version_count;
         index++) {
        spdm_version_number_t version =
            spdm_context->local_context.secured_message_version.secured_message_version[index];
        if (libspdm_get_version_from_version_number(version) >
            libspdm_get_version_from_version_number(max_version)) {
            max_version = version;
        }
    }
    return max_version;
}

/* DSP0277 1.3: derive the AeadLimitExponent that this endpoint advertises from its single source of
 * truth, max_spdm_session_sequence_number. That value is the maximum sequence number that IS allowed
 * (seq > max triggers overflow), i.e. AeadLimit - 1, so the AEAD limit is
 * AeadLimit = max + 1 = 2 ^ exponent (see libspdm_apply_aead_limit_to_session). The advertised
 * exponent is therefore floor(log2(max + 1)): the largest e such that 2 ^ e <= max + 1. The all-ones
 * cap maps to 64 (the spec default, since 2^64 is not representable). A cap that is not of the form
 * 2 ^ e - 1 rounds the exponent down to the nearest representable AEAD limit, which is <= the
 * configured cap (the safe direction). */
static uint8_t libspdm_aead_limit_exponent_from_max_sequence_number(uint64_t max_sequence_number)
{
    uint8_t exponent;
    uint64_t aead_limit;

    /* All-ones is the maximum allowed value for the default AeadLimit of 2^64, which is not
     * representable in a uint64_t; adding 1 would overflow, so handle it directly. */
    if (max_sequence_number >= LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER) {
        return SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_MAX;
    }

    aead_limit = max_sequence_number + 1;
    exponent = 0;
    while (aead_limit > 1) {
        aead_limit >>= 1;
        exponent++;
    }
    return exponent;
}

size_t libspdm_get_opaque_data_aead_limit_element_size(const libspdm_context_t *spdm_context,
                                                       spdm_version_number_t secured_message_version)
{
    size_t size;

    /* The AEADlimitOE element is only defined for secured message version 1.3 and later. It must
     * not be appended to opaque data for an older version. */
    if (libspdm_get_version_from_version_number(secured_message_version) < SECURED_SPDM_VERSION_13) {
        return 0;
    }

    size = sizeof(secured_message_opaque_element_table_header_t) +
           sizeof(secured_message_opaque_element_aead_limit_t);
    /* Add Padding*/
    return (size + 3) & ~3;
}

/* Walk a well-formed opaque data blob (general opaque data table header followed by total_elements
 * elements) and return its current length in bytes. data_out_capacity bounds the walk. Returns
 * false if the blob does not fit within data_out_capacity. */
static bool libspdm_get_opaque_data_current_size(libspdm_context_t *spdm_context,
                                                 const void *data_out, size_t data_out_capacity,
                                                 size_t *current_size)
{
    const secured_message_general_opaque_data_table_header_t *general_opaque_data_table_header;
    const spdm_general_opaque_data_table_header_t *spdm_general_opaque_data_table_header;
    const opaque_element_table_header_t *opaque_element_table_header;
    uint8_t element_num;
    uint8_t index;
    uint16_t opaque_element_data_len;
    size_t total_size;
    size_t current_element_len;

    if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        if (data_out_capacity < sizeof(spdm_general_opaque_data_table_header_t)) {
            return false;
        }
        spdm_general_opaque_data_table_header = data_out;
        element_num = spdm_general_opaque_data_table_header->total_elements;
        opaque_element_table_header = (const void *)(spdm_general_opaque_data_table_header + 1);
        total_size = sizeof(spdm_general_opaque_data_table_header_t);
    } else {
        if (data_out_capacity < sizeof(secured_message_general_opaque_data_table_header_t)) {
            return false;
        }
        general_opaque_data_table_header = data_out;
        element_num = general_opaque_data_table_header->total_elements;
        opaque_element_table_header = (const void *)(general_opaque_data_table_header + 1);
        total_size = sizeof(secured_message_general_opaque_data_table_header_t);
    }

    for (index = 0; index < element_num; index++) {
        if (total_size + sizeof(opaque_element_table_header_t) +
            opaque_element_table_header->vendor_len + sizeof(uint16_t) > data_out_capacity) {
            return false;
        }
        opaque_element_data_len = libspdm_read_uint16(
            (const uint8_t *)opaque_element_table_header + sizeof(opaque_element_table_header_t) +
            opaque_element_table_header->vendor_len);
        current_element_len = sizeof(opaque_element_table_header_t) +
                              opaque_element_table_header->vendor_len + sizeof(uint16_t) +
                              opaque_element_data_len;
        /* Add Padding*/
        current_element_len = (current_element_len + 3) & ~3;
        if (total_size + current_element_len > data_out_capacity) {
            return false;
        }
        total_size += current_element_len;
        opaque_element_table_header = (const opaque_element_table_header_t *)
                                      ((const uint8_t *)opaque_element_table_header +
                                       current_element_len);
    }

    *current_size = total_size;
    return true;
}

void libspdm_build_opaque_data_aead_limit_element(libspdm_context_t *spdm_context,
                                                  spdm_version_number_t secured_message_version,
                                                  size_t *data_out_size, void *data_out)
{
    size_t data_out_capacity;
    size_t existing_size;
    size_t element_size;
    secured_message_opaque_element_table_header_t *opaque_element_table_header;
    secured_message_opaque_element_aead_limit_t *opaque_element_aead_limit;
    uint8_t *element_ptr;
    bool result;

    /* data_out already holds a blob built by the supported-version / version-selection builder.
     * *data_out_size is the capacity of data_out on input. Parse the blob to find where it ends;
     * that is the append offset. */
    data_out_capacity = *data_out_size;
    result = libspdm_get_opaque_data_current_size(spdm_context, data_out, data_out_capacity,
                                                  &existing_size);
    LIBSPDM_ASSERT(result);
    if (!result) {
        return;
    }

    /* The size helper enforces the secured message version 1.3 gate; for an older version it
     * returns 0 and nothing is appended. */
    element_size = libspdm_get_opaque_data_aead_limit_element_size(spdm_context,
                                                                   secured_message_version);
    if (element_size == 0) {
        *data_out_size = existing_size;
        return;
    }

    LIBSPDM_ASSERT(existing_size + element_size <= data_out_capacity);

    if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header_t *spdm_general_opaque_data_table_header;
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements++;
    } else {
        secured_message_general_opaque_data_table_header_t *general_opaque_data_table_header;
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->total_elements++;
    }

    element_ptr = (uint8_t *)data_out + existing_size;
    opaque_element_table_header = (void *)element_ptr;
    opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
    opaque_element_table_header->vendor_len = 0;
    opaque_element_table_header->opaque_element_data_len =
        sizeof(secured_message_opaque_element_aead_limit_t);

    opaque_element_aead_limit = (void *)(opaque_element_table_header + 1);
    opaque_element_aead_limit->sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_element_aead_limit->sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_AEAD_LIMIT;
    opaque_element_aead_limit->aead_limit_exponent =
        libspdm_aead_limit_exponent_from_max_sequence_number(
            spdm_context->max_spdm_session_sequence_number);

    /* Zero the padding bytes between the element and the new end. */
    libspdm_zero_mem(element_ptr + sizeof(secured_message_opaque_element_table_header_t) +
                     sizeof(secured_message_opaque_element_aead_limit_t),
                     element_size - (sizeof(secured_message_opaque_element_table_header_t) +
                                     sizeof(secured_message_opaque_element_aead_limit_t)));

    *data_out_size = existing_size + element_size;
}

libspdm_return_t libspdm_process_opaque_data_aead_limit(libspdm_context_t *spdm_context,
                                                        spdm_version_number_t
                                                        secured_message_version,
                                                        size_t data_in_size, const void *data_in,
                                                        uint8_t *aead_limit_exponent)
{
    bool result;
    const void *get_element_ptr;
    size_t get_element_len;
    const secured_message_opaque_element_table_header_t *opaque_element_table_header;
    const secured_message_opaque_element_aead_limit_t *opaque_element_aead_limit;

    /* Default per DSP0277 1.3: when the AEAD limit element is absent, the exponent is 64. */
    *aead_limit_exponent = SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_DEFAULT;

    /* The AEADlimitOE element is only defined for secured message version 1.3 and later. For an
     * older negotiated version, ignore the element entirely (keep the default exponent) even if a
     * peer erroneously included it. */
    if (libspdm_get_version_from_version_number(secured_message_version) <
        SECURED_SPDM_VERSION_13) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    get_element_ptr = NULL;
    result = libspdm_get_sm_data_element_from_opaque_data(
        spdm_context, data_in_size, data_in,
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_AEAD_LIMIT,
        &get_element_ptr, &get_element_len);
    if ((!result) || (get_element_ptr == NULL)) {
        /* Absent is allowed: keep the default exponent. */
        return LIBSPDM_STATUS_SUCCESS;
    }

    opaque_element_table_header = (const secured_message_opaque_element_table_header_t *)
                                  get_element_ptr;
    if ((opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_aead_limit_t))) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    opaque_element_aead_limit = (const void *)(opaque_element_table_header + 1);
    if ((const uint8_t *)opaque_element_aead_limit +
        sizeof(secured_message_opaque_element_aead_limit_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    /* AeadLimitExponent shall be <= 64. */
    if (opaque_element_aead_limit->aead_limit_exponent >
        SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_MAX) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *aead_limit_exponent = opaque_element_aead_limit->aead_limit_exponent;
    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_apply_aead_limit_to_session(libspdm_context_t *spdm_context,
                                         void *session_info_p,
                                         uint8_t peer_aead_limit_exponent)
{
    libspdm_session_info_t *session_info;
    uint64_t peer_max_sequence_number;
    uint64_t effective_max;

    session_info = session_info_p;

    /* The caller invokes this only when the session negotiated secured message version >= 1.3.
     *
     * The single source of truth for this endpoint's limit is max_spdm_session_sequence_number,
     * which is the maximum sequence number that IS allowed (seq > max triggers
     * LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW). The DSP0277 AeadLimit is the first sequence number
     * that is NOT allowed, so max = AeadLimit - 1 = 2 ^ AeadLimitExponent - 1. That is also what this
     * endpoint advertised, encoded as an exponent. We only need to fold in the peer's advertised
     * AeadLimitExponent: the peer's maximum allowed sequence number is 2 ^ peer_aead_limit_exponent
     * - 1. At exponent 64 the AEAD limit is 2^64, so the maximum allowed value is 2^64 - 1, i.e.
     * LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER (all-ones), which is also the default. */
    if (peer_aead_limit_exponent >= 64) {
        peer_max_sequence_number = LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER;
    } else {
        peer_max_sequence_number = ((uint64_t)1 << peer_aead_limit_exponent) - 1;
    }

    /* The effective cap is the smaller of this endpoint's configured cap and the peer's maximum
     * allowed sequence number, so neither side's limit is ever raised by the other. */
    effective_max = spdm_context->max_spdm_session_sequence_number;
    if (peer_max_sequence_number < effective_max) {
        effective_max = peer_max_sequence_number;
    }

    libspdm_secured_message_set_max_spdm_session_sequence_number(
        session_info->secured_message_context, effective_max);
}
