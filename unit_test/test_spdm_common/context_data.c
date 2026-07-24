/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (void *context, const void *msg_buf_ptr);

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (void *context, const void *msg_buf_ptr);

static uint32_t libspdm_opaque_data = 0xDEADBEEF;

/**
 * This function verifies peer certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  cert_chain_buffer       Certificate chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size  Size in bytes of the certificate chain buffer.
 * @param  trust_anchor            A buffer to hold the trust_anchor which is used to validate the
 *                                 peer certificate, if not NULL.
 * @param  trust_anchor_size       A buffer to hold the trust_anchor_size, if not NULL.
 *
 * @retval true  Peer certificate chain buffer verification passed.
 * @retval false Peer certificate chain buffer verification failed.
 **/
static bool libspdm_verify_peer_cert_chain_buffer(void *spdm_context,
                                                  const void *cert_chain_buffer,
                                                  size_t cert_chain_buffer_size,
                                                  const void **trust_anchor,
                                                  size_t *trust_anchor_size)
{
    bool result;

    /*verify peer cert chain integrity*/
    result = libspdm_verify_peer_cert_chain_buffer_integrity(spdm_context, cert_chain_buffer,
                                                             cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    /*verify peer cert chain authority*/
    result = libspdm_verify_peer_cert_chain_buffer_authority(spdm_context, cert_chain_buffer,
                                                             cert_chain_buffer_size, trust_anchor,
                                                             trust_anchor_size);
    if (!result) {
        return false;
    }

    return true;
}

/**
 * Return the size in bytes of multi element opaque data supported version.
 *
 * @param  version_count                 Secure version count.
 *
 * @return the size in bytes of opaque data supported version.
 **/
size_t libspdm_get_multi_element_opaque_data_supported_version_data_size(
    libspdm_context_t *spdm_context, uint8_t version_count, uint8_t element_num)
{
    size_t size;
    uint8_t element_index;

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_supported_version_t) +
                    sizeof(spdm_version_number_t) * version_count;
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_supported_version_t) +
                    sizeof(spdm_version_number_t) * version_count;
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    }

    return size;
}

/**
 * Build opaque data supported version test.
 *
 * @param  data_out_size[in]                 size in bytes of the data_out.
 *                                           On input, it means the size in bytes of data_out buffer.
 *                                           On output, it means the size in bytes of copied data_out buffer if LIBSPDM_STATUS_SUCCESS is returned,
 *                                           and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out[in]                      A pointer to the destination buffer to store the opaque data supported version.
 * @param  element_num[in]                   in this test function, the element number < 9 is right. because element id is changed with element_index
 **/
libspdm_return_t
libspdm_build_multi_element_opaque_data_supported_version_test(libspdm_context_t *spdm_context,
                                                               size_t *data_out_size,
                                                               void *data_out,
                                                               uint8_t element_num)
{
    size_t final_data_size;
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_supported_version_t
    *opaque_element_support_version;
    spdm_version_number_t *versions_list;
    void *end;
    uint8_t element_index;

    if (spdm_context->local_context.secured_message_version.secured_message_version_count == 0) {
        *data_out_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.secured_message_version_count,
            element_num);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = element_num;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);
        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id =
            SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version =
            SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = element_num;
        general_opaque_data_table_header->reserved = 0;
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }

    for (element_index = 0; element_index < element_num; element_index++) {
        /*id is changed with element_index*/
        opaque_element_table_header->id = element_index;
        opaque_element_table_header->vendor_len = 0;
        opaque_element_table_header->opaque_element_data_len =
            sizeof(secured_message_opaque_element_supported_version_t) +
            sizeof(spdm_version_number_t) *
            spdm_context->local_context.secured_message_version.secured_message_version_count;

        opaque_element_support_version =
            (void *)(opaque_element_table_header + 1);
        opaque_element_support_version->sm_data_version =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
        opaque_element_support_version->sm_data_id =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
        opaque_element_support_version->version_count =
            spdm_context->local_context.secured_message_version.secured_message_version_count;

        versions_list = (void *)(opaque_element_support_version + 1);

        libspdm_copy_mem(versions_list,
                         *data_out_size - ((uint8_t*)versions_list - (uint8_t*)data_out),
                         spdm_context->local_context.secured_message_version.secured_message_version,
                         spdm_context->local_context.secured_message_version.secured_message_version_count *
                         sizeof(spdm_version_number_t));

        /*move to next element*/
        if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
            opaque_element_table_header =
                (secured_message_opaque_element_table_header_t *)(
                    (uint8_t *)opaque_element_table_header +
                    libspdm_get_multi_element_opaque_data_supported_version_data_size(
                        spdm_context,
                        spdm_context->local_context.secured_message_version.secured_message_version_count,
                        1) -
                    sizeof(spdm_general_opaque_data_table_header_t));
        } else {
            opaque_element_table_header =
                (secured_message_opaque_element_table_header_t *)(
                    (uint8_t *)opaque_element_table_header +
                    libspdm_get_multi_element_opaque_data_supported_version_data_size(
                        spdm_context,
                        spdm_context->local_context.secured_message_version.secured_message_version_count,
                        1) -
                    sizeof(secured_message_general_opaque_data_table_header_t));
        }

        /* Zero Padding. *data_out_size does not need to be changed, because data is 0 padded */
        end = versions_list +
              spdm_context->local_context.secured_message_version.secured_message_version_count;
        libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "successful build multi element opaque data supported version! \n"));
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Return the size in bytes of multi element opaque data selection version.
 *
 * @param  version_count                 Secure version count.
 *
 * @return the size in bytes of opaque data selection version.
 **/
size_t libspdm_get_multi_element_opaque_data_version_selection_data_size(
    const libspdm_context_t *spdm_context, uint8_t element_num)
{
    size_t size;
    uint8_t element_index;

    if (spdm_context->local_context.secured_message_version.secured_message_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_version_selection_t);
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_version_selection_t);
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    }

    return size;
}

static libspdm_return_t libspdm_build_opaque_data_version_selection_data_test(
    const libspdm_context_t *spdm_context, spdm_version_number_t secured_message_version,
    size_t *data_out_size, void *data_out, uint8_t element_num)
{
    size_t final_data_size;
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_version_selection_t
    *opaque_element_version_section;
    void *end;
    uint8_t element_index;
    size_t current_element_len;

    if (spdm_context->local_context.secured_message_version.secured_message_version_count == 0) {
        *data_out_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size = libspdm_get_multi_element_opaque_data_version_selection_data_size(
        spdm_context, element_num);

    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = element_num;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);

        opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id = SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version = SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = element_num;
        general_opaque_data_table_header->reserved = 0;

        opaque_element_table_header = (void *)(general_opaque_data_table_header + 1);
    }

    for (element_index = 0; element_index < element_num; element_index++) {
        /*id is changed with element_index*/
        opaque_element_table_header->id = element_index;
        opaque_element_table_header->vendor_len = 0;
        opaque_element_table_header->opaque_element_data_len =
            sizeof(secured_message_opaque_element_version_selection_t);

        opaque_element_version_section = (void *)(opaque_element_table_header + 1);
        opaque_element_version_section->sm_data_version =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
        opaque_element_version_section->sm_data_id =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
        opaque_element_version_section->selected_version = secured_message_version;

        /*move to next element*/
        current_element_len = sizeof(secured_message_opaque_element_table_header_t) +
                              opaque_element_table_header->opaque_element_data_len;
        /* Add Padding*/
        current_element_len = (current_element_len + 3) & ~3;

        opaque_element_table_header =
            (secured_message_opaque_element_table_header_t *)(
                (uint8_t *)opaque_element_table_header + current_element_len);
    }

    /* Zero Padding*/
    end = opaque_element_version_section + 1;
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "successful build multi element opaque data selection version! \n"));

    return LIBSPDM_STATUS_SUCCESS;
}


/**
 * Test 1: Basic test - tests happy path of setting and getting opaque data from
 * context successfully.
 **/
static void libspdm_test_common_context_data_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = (void *)&libspdm_opaque_data;
    void *return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(data));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_memory_equal(data, return_data, sizeof(data));
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);
}

/**
 * Test 2: Test failure paths of setting opaque data in context. libspdm_set_data
 * should fail when an invalid size is passed.
 **/
static void libspdm_test_common_context_data_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = (void *)&libspdm_opaque_data;
    void *return_data = NULL;
    void *current_return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    /**
     * Get current opaque data in context. May have been set in previous
     * tests. This will be used to compare later to ensure the value hasn't
     * changed after a failed set data.
     */
    data_return_size = sizeof(current_return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &current_return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_return_size, sizeof(void*));

    /* Ensure nothing has changed between subsequent calls to get data */
    assert_ptr_equal(current_return_data, &libspdm_opaque_data);

    /*
     * Set data with invalid size, it should fail. Read back to ensure that
     * no data was set.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, 500);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(return_data, current_return_data);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);
}

/**
 * Test 3: Test failure paths of setting opaque data in context. libspdm_set_data
 * should fail when data contains NULL value.
 **/
static void libspdm_test_common_context_data_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = NULL;
    void *return_data = NULL;
    void *current_return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    /**
     * Get current opaque data in context. May have been set in previous
     * tests. This will be used to compare later to ensure the value hasn't
     * changed after a failed set data.
     */
    data_return_size = sizeof(current_return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &current_return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_return_size, sizeof(void*));

    /* Ensure nothing has changed between subsequent calls to get data */
    assert_ptr_equal(current_return_data, &libspdm_opaque_data);


    /*
     * Set data with NULL data, it should fail. Read back to ensure that
     * no data was set.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(void *));
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(return_data, current_return_data);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);

}

/**
 * Test 4: Test failure paths of getting opaque data in context. libspdm_get_data
 * should fail when the size of buffer to get is too small.
 **/
static void libspdm_test_common_context_data_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = (void *)&libspdm_opaque_data;
    void *return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    /*
     * Set data successfully.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(void *));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /*
     * Fail get data due to insufficient buffer for return value. returned
     * data size must return required buffer size.
     */
    data_return_size = sizeof(void*) - 1;
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);
}

/**
 * Test 5: There is no root cert.
 * Expected Behavior: Return true result.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }
    if (!libspdm_x509_get_cert_from_cert_chain(
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
            data_size - sizeof(spdm_cert_chain_t) - hash_size, 0, &root_cert, &root_cert_size)) {
        assert(false);
    }

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;
    spdm_context->local_context.is_requester = true;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);

    free(data);
}

/**
 * Test 6: There is one root cert. And the root cert has two case: match root cert, mismatch root cert.
 *
 * case                                              Expected Behavior
 * there is one match root cert;                     return false
 * there is one mismatch root cert;                  return true, and the return trust_anchor is root cert.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case6(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    void *data_test;
    size_t data_size_test;
    void *hash_test;
    size_t hash_size_test;
    const uint8_t *root_cert_test;
    size_t root_cert_size_test;
    uint32_t m_libspdm_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;

    /* Loading Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }
    if (!libspdm_x509_get_cert_from_cert_chain(
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
            data_size - sizeof(spdm_cert_chain_t) - hash_size, 0, &root_cert, &root_cert_size)) {
        assert(false);
    }
    /* Loading Other test Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo_test, &data_test,
                                                         &data_size_test, &hash_test, &hash_size_test)) {
        return;
    }
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
        data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
        &root_cert_test, &root_cert_size_test);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }

    /*case: match root cert case*/
    spdm_context->local_context.peer_root_cert_provision_size[0] =root_cert_size_test;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert_test;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, false);

    /*case: mismatch root cert case*/
    spdm_context->local_context.peer_root_cert_provision_size[0] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}

/**
 * Test 7: There are LIBSPDM_MAX_ROOT_CERT_SUPPORT/2 root cert.
 *
 * case                                              Expected Behavior
 * there is no match root cert;                      return false
 * there is one match root cert in the end;          return true, and the return trust_anchor is root cert.
 * there is one match root cert in the middle;       return true, and the return trust_anchor is root cert.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case7(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    void *data_test;
    size_t data_size_test;
    void *hash_test;
    size_t hash_size_test;
    const uint8_t *root_cert_test;
    size_t root_cert_size_test;
    uint32_t m_libspdm_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    /* Loading Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }
    if (!libspdm_x509_get_cert_from_cert_chain(
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
            data_size - sizeof(spdm_cert_chain_t) - hash_size, 0, &root_cert, &root_cert_size)) {
        assert(false);
    }
    /* Loading Other test Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo_test, &data_test,
                                                         &data_size_test, &hash_test, &hash_size_test)) {
        return;
    }
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
        data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
        &root_cert_test, &root_cert_size_test);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }

    /*case: there is no match root cert*/
    for (root_cert_index = 0; root_cert_index < (LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2);
         root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, false);

    /*case: there is no match root cert in the end*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2 -
                                                              1] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2 -
                                                         1] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    /*case: there is no match root cert in the middle*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                              4] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                         4] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}


/**
 * Test 8: There are full(LIBSPDM_MAX_ROOT_CERT_SUPPORT - 1) root cert.
 *
 * case                                              Expected Behavior
 * there is no match root cert;                      return false
 * there is one match root cert in the end;          return true, and the return trust_anchor is root cert.
 * there is one match root cert in the middle;       return true, and the return trust_anchor is root cert.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    void *data_test;
    size_t data_size_test;
    void *hash_test;
    size_t hash_size_test;
    const uint8_t *root_cert_test;
    size_t root_cert_size_test;
    uint32_t m_libspdm_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    /* Loading Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }
    if (!libspdm_x509_get_cert_from_cert_chain(
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
            data_size - sizeof(spdm_cert_chain_t) - hash_size, 0, &root_cert, &root_cert_size)) {
        assert(false);
    }
    /* Loading Other test Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo_test, &data_test,
                                                         &data_size_test, &hash_test, &hash_size_test)) {
        return;
    }
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
        data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
        &root_cert_test, &root_cert_size_test);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;

    /*case: there is no match root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, false);

    /*case: there is no match root cert in the end*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT -
                                                              1] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT -
                                                         1] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    /*case: there is no match root cert in the middle*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                              2] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                         2] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}

/**
 * Test 9: test set data for root cert.
 *
 * case                                              Expected Behavior
 * there is null root cert;                          return LIBSPDM_STATUS_SUCCESS, and the root cert is set successfully.
 * there is full root cert;                          return RETURN_OUT_OF_RESOURCES.
 **/
static void libspdm_test_set_data_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;

    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    uint8_t root_cert_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t root_cert_size;

    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    /* Loading Root certificate and saving its hash*/
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }
    if (!libspdm_x509_get_cert_from_cert_chain(
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
            data_size - sizeof(spdm_cert_chain_t) - hash_size, 0, &root_cert, &root_cert_size)) {
        assert(false);
    }
    memcpy(root_cert_buffer, root_cert, root_cert_size);

    /*case: there is null root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                              &parameter, root_cert_buffer, root_cert_size);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (spdm_context->local_context.peer_root_cert_provision_size[0], root_cert_size);
    assert_ptr_equal (spdm_context->local_context.peer_root_cert_provision[0], root_cert_buffer);

    /*case: there is full root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = root_cert_size;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_buffer;
    }
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                              &parameter, root_cert_buffer, root_cert_size);
    assert_int_equal (status, LIBSPDM_STATUS_BUFFER_FULL);

    free(data);
}


/**
 * Test 10: There is no root cert.
 * Expected Behavior: Return true result.
 **/
void libspdm_test_process_opaque_data_supported_version_data_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.secured_message_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_supported_version_data_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.secured_message_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_supported_version_data_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.secured_message_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_supported_version_data_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.secured_message_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}


void libspdm_test_process_opaque_data_selection_version_data_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, &opaque_data_size,
            opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (secured_message_version,
                      SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT);

    free(opaque_data_ptr);
}


void libspdm_test_process_opaque_data_selection_version_data_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, &opaque_data_size,
            opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}


void libspdm_test_process_opaque_data_selection_version_data_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    element_num = 2;
    opaque_data_size = libspdm_get_multi_element_opaque_data_version_selection_data_size(
        spdm_context, element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, &opaque_data_size,
            opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_selection_version_data_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;
    spdm_version_number_t secured_message_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, &opaque_data_size,
            opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr,
                                                                &secured_message_version);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}

void libspdm_test_secured_message_context_location_selection_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *secured_message_contexts[LIBSPDM_MAX_SESSION_COUNT];
    size_t index;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x12;

    spdm_context = (libspdm_context_t *)malloc(libspdm_get_context_size_without_secured_context());

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        secured_message_contexts[index] =
            (void *)malloc(libspdm_secured_message_get_context_size());
    }

    status = libspdm_init_context_with_secured_context(spdm_context, secured_message_contexts,
                                                       LIBSPDM_MAX_SESSION_COUNT);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        /* Ensure the SPDM context points to the specified memory. */
        assert_ptr_equal(spdm_context->session_info[index].secured_message_context,
                         secured_message_contexts[index]);
    }

    free(spdm_context);
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        free(secured_message_contexts[index]);
    }
}

static void libspdm_test_export_master_secret_case19(void **state)
{
    uint8_t target_buffer[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    libspdm_secured_message_context_t secured_message_context;
    size_t export_master_secret_size;

    /* Get the entire EMS when the reported size of the target buffer is larger than the size of the
     * EMS. */
    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        secured_message_context.export_master_secret[index] = (uint8_t)index;
        target_buffer[index] = 0x00;
    }

    secured_message_context.hash_size = LIBSPDM_MAX_HASH_SIZE;
    export_master_secret_size = LIBSPDM_MAX_HASH_SIZE + 0x100;

    result = libspdm_secured_message_export_master_secret(&secured_message_context,
                                                          &target_buffer,
                                                          &export_master_secret_size);
    assert_int_equal(result, true);

    libspdm_secured_message_clear_export_master_secret(&secured_message_context);

    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        assert_int_equal(target_buffer[index], index);
        assert_int_equal(secured_message_context.export_master_secret[index], 0x00);
    }
    assert_int_equal(export_master_secret_size, LIBSPDM_MAX_HASH_SIZE);

    /* Get the entire EMS when the size of the target buffer is the same size as the EMS. */
    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        secured_message_context.export_master_secret[index] = (uint8_t)index;
        target_buffer[index] = 0x00;
    }

    secured_message_context.hash_size = LIBSPDM_MAX_HASH_SIZE;
    export_master_secret_size = LIBSPDM_MAX_HASH_SIZE;

    result = libspdm_secured_message_export_master_secret(&secured_message_context,
                                                          &target_buffer,
                                                          &export_master_secret_size);
    assert_int_equal(result, true);

    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        assert_int_equal(target_buffer[index], index);
    }
    assert_int_equal(export_master_secret_size, LIBSPDM_MAX_HASH_SIZE);

    /* Get the truncated EMS when the size of the target buffer is less than the size of the EMS. */
    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        secured_message_context.export_master_secret[index] = (uint8_t)index;
        target_buffer[index] = 0x00;
    }

    secured_message_context.hash_size = LIBSPDM_MAX_HASH_SIZE;
    export_master_secret_size = LIBSPDM_MAX_HASH_SIZE - 4;

    result = libspdm_secured_message_export_master_secret(&secured_message_context,
                                                          &target_buffer,
                                                          &export_master_secret_size);
    assert_int_equal(result, true);

    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        if (index < LIBSPDM_MAX_HASH_SIZE - 4) {
            assert_int_equal(target_buffer[index], index);
        } else {
            assert_int_equal(target_buffer[index], 0x00);
        }
    }
    assert_int_equal(export_master_secret_size, LIBSPDM_MAX_HASH_SIZE - 4);
}

static void libspdm_test_check_context_case20(void **state)
{
    void *context;
    bool result;

    context = (void *)malloc (libspdm_get_context_size());

    libspdm_init_context (context);

    result = libspdm_check_context (context);
    assert_int_equal(false, result);

    libspdm_register_transport_layer_func(context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message);

    libspdm_register_device_buffer_func(context,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    result = libspdm_check_context (context);
    assert_int_equal(true, result);

    libspdm_register_transport_layer_func(context,
                                          SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12,
                                          LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message);

    result = libspdm_check_context (context);
    assert_int_equal(false, result);
}

static void libspdm_test_max_session_count_case21(void **state)
{
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    size_t index;
    size_t round;
    uint16_t req_id;
    uint16_t rsp_id;
    uint32_t session_id;
    void *session_info;
    uint32_t dhe_session_count;
    uint32_t psk_session_count;

    for (round = 0; round <= 5; round++) {
        /* prepare parameter */
        switch (round) {
        case 0:
            dhe_session_count = 1;
            psk_session_count = 1;
            break;
        case 1:
            dhe_session_count = LIBSPDM_MAX_SESSION_COUNT / 2;
            psk_session_count = LIBSPDM_MAX_SESSION_COUNT - dhe_session_count;
            break;
        case 2:
            dhe_session_count = 1;
            psk_session_count = LIBSPDM_MAX_SESSION_COUNT - 1;
            break;
        case 3:
            dhe_session_count = LIBSPDM_MAX_SESSION_COUNT - 1;
            psk_session_count = 1;
            break;
        case 4:
            dhe_session_count = 0;
            psk_session_count = LIBSPDM_MAX_SESSION_COUNT;
            break;
        case 5:
            dhe_session_count = LIBSPDM_MAX_SESSION_COUNT;
            psk_session_count = 0;
            break;
        default:
            dhe_session_count = 0;
            psk_session_count = 0;
            break;
        }

        /* test */
        spdm_context = (libspdm_context_t *)malloc(libspdm_get_context_size());
        libspdm_init_context (spdm_context);
        spdm_context->connection_info.capability.flags =
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
        spdm_context->local_context.capability.flags =
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
        spdm_context->connection_info.algorithm.base_hash_algo =
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
        spdm_context->connection_info.algorithm.dhe_named_group =
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
        spdm_context->connection_info.algorithm.aead_cipher_suite =
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
        spdm_context->connection_info.algorithm.key_schedule =
            SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        if (dhe_session_count != 0) {
            libspdm_set_data (spdm_context, LIBSPDM_DATA_MAX_DHE_SESSION_COUNT, &parameter,
                              &dhe_session_count, sizeof(dhe_session_count));
        }
        if (psk_session_count != 0) {
            libspdm_set_data (spdm_context, LIBSPDM_DATA_MAX_PSK_SESSION_COUNT, &parameter,
                              &psk_session_count, sizeof(psk_session_count));
        }

        if (dhe_session_count != 0) {
            for (index = 0; index < dhe_session_count; index++)
            {
                req_id = libspdm_allocate_req_session_id (spdm_context, false);
                assert_int_not_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

                rsp_id = libspdm_allocate_rsp_session_id (spdm_context, false);
                assert_int_not_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);

                session_id = libspdm_generate_session_id (req_id, rsp_id);
                session_info = libspdm_assign_session_id (spdm_context, session_id,
                                                          SECURED_SPDM_VERSION_11 <<
                                                          SPDM_VERSION_NUMBER_SHIFT_BIT,
                                                          false);
                assert_ptr_not_equal (session_info, NULL);
            }
            req_id = libspdm_allocate_req_session_id (spdm_context, false);
            assert_int_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

            rsp_id = libspdm_allocate_rsp_session_id (spdm_context, false);
            assert_int_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);
        }

        if (psk_session_count != 0) {
            for (index = 0; index < psk_session_count; index++)
            {
                req_id = libspdm_allocate_req_session_id (spdm_context, true);
                assert_int_not_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

                rsp_id = libspdm_allocate_rsp_session_id (spdm_context, true);
                assert_int_not_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);

                session_id = libspdm_generate_session_id (req_id, rsp_id);
                session_info = libspdm_assign_session_id (spdm_context, session_id,
                                                          SECURED_SPDM_VERSION_11 <<
                                                          SPDM_VERSION_NUMBER_SHIFT_BIT,
                                                          true);
                assert_ptr_not_equal (session_info, NULL);
            }
            req_id = libspdm_allocate_req_session_id (spdm_context, true);
            assert_int_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

            rsp_id = libspdm_allocate_rsp_session_id (spdm_context, true);
            assert_int_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);
        }

        free(spdm_context);
    }
}

#pragma pack(1)

typedef struct {
    spdm_general_opaque_data_table_header_t opaque_header;
    spdm_svh_iana_cbor_header_t cbor_header;
    uint8_t cbor_vendor_id[10];
    uint16_t cbor_opaque_len;
    uint8_t cbor_opaque[10];
    /* uint8_t cbor_align[]; */
    spdm_svh_vesa_header_t vesa_header;
    uint16_t vesa_opaque_len;
    uint8_t vesa_opaque[9];
    uint8_t vesa_align[3];
    spdm_svh_jedec_header_t jedec_header;
    uint16_t jedec_opaque_len;
    uint8_t jedec_opaque[8];
    uint8_t jedec_align[2];
    spdm_svh_cxl_header_t cxl_header;
    uint16_t cxl_opaque_len;
    uint8_t cxl_opaque[7];
    uint8_t cxl_align[3];
    spdm_svh_mipi_header_t mipi_header;
    uint16_t mipi_opaque_len;
    uint8_t mipi_opaque[6];
    /* uint8_t mipi_align[0]; */
    spdm_svh_hdbaset_header_t hdbaset_header;
    uint16_t hdbaset_opaque_len;
    uint8_t hdbaset_opaque[5];
    uint8_t hdbaset_align[3];
    spdm_svh_iana_header_t iana_header;
    uint16_t iana_opaque_len;
    uint8_t iana_opaque[4];
    /* uint8_t iana_align[0]; */
    spdm_svh_pcisig_header_t pcisig_header;
    uint16_t pcisig_opaque_len;
    uint8_t pcisig_opaque[3];
    uint8_t pcisig_align[3];
    spdm_svh_usb_header_t usb_header;
    uint16_t usb_opaque_len;
    uint8_t usb_opaque[2];
    /* uint8_t usb_align[0]; */
    spdm_svh_tcg_header_t tcg_header;
    uint16_t tcg_opaque_len;
    uint8_t tcg_opaque[1];
    uint8_t tcg_align[1];
    spdm_svh_dmtf_dsp_header_t dmtf_dsp_header;
    uint16_t dmtf_dsp_opaque_len;
    uint8_t dmtf_dsp_opaque[11];
    uint8_t dmtf_dsp_align[3];
    spdm_svh_dmtf_header_t dmtf_sm_ver_sel_header;
    uint16_t dmtf_sm_ver_sel_opaque_len;
    secured_message_opaque_element_version_selection_t dmtf_sm_ver_sel_opaque;
    /* uint8_t dmtf_sm_ver_sel_align[0]; */
    spdm_svh_dmtf_header_t dmtf_sm_sup_ver_header;
    uint16_t dmtf_sm_sup_ver_opaque_len;
    secured_message_opaque_element_supported_version_t dmtf_sm_sup_ver_opaque;
    spdm_version_number_t dmtf_sm_sup_ver_versions_list[3];
    uint8_t dmtf_sm_sup_ver_align[3];
} test_spdm12_opaque_data_table_t;

#pragma pack()

static void libspdm_test_process_opaque_data_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const void *get_element_ptr;
    size_t get_element_len;
    size_t opaque_data_size;
    uint8_t *opaque_data_ptr;
    test_spdm12_opaque_data_table_t opaque_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_set_mem ((uint8_t *)&opaque_data, sizeof(opaque_data), 0xFF);
    opaque_data.opaque_header.total_elements = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data.cbor_header.header.id = SPDM_REGISTRY_ID_IANA_CBOR;
    opaque_data.cbor_header.header.vendor_id_len = sizeof(opaque_data.cbor_vendor_id);
    opaque_data.cbor_opaque_len = sizeof(opaque_data.cbor_opaque);
    opaque_data.vesa_header.header.id = SPDM_REGISTRY_ID_VESA;
    opaque_data.vesa_header.header.vendor_id_len = 0;
    opaque_data.vesa_opaque_len = sizeof(opaque_data.vesa_opaque);
    opaque_data.jedec_header.header.id = SPDM_REGISTRY_ID_JEDEC;
    opaque_data.jedec_header.header.vendor_id_len = sizeof(opaque_data.jedec_header.vendor_id);
    opaque_data.jedec_opaque_len = sizeof(opaque_data.jedec_opaque);
    opaque_data.cxl_header.header.id = SPDM_REGISTRY_ID_CXL;
    opaque_data.cxl_header.header.vendor_id_len = sizeof(opaque_data.cxl_header.vendor_id);
    opaque_data.cxl_opaque_len = sizeof(opaque_data.cxl_opaque);
    opaque_data.mipi_header.header.id = SPDM_REGISTRY_ID_MIPI;
    opaque_data.mipi_header.header.vendor_id_len = sizeof(opaque_data.mipi_header.vendor_id);
    opaque_data.mipi_opaque_len = sizeof(opaque_data.mipi_opaque);
    opaque_data.hdbaset_header.header.id = SPDM_REGISTRY_ID_HDBASET;
    opaque_data.hdbaset_header.header.vendor_id_len = sizeof(opaque_data.hdbaset_header.vendor_id);
    opaque_data.hdbaset_opaque_len = sizeof(opaque_data.hdbaset_opaque);
    opaque_data.iana_header.header.id = SPDM_REGISTRY_ID_IANA;
    opaque_data.iana_header.header.vendor_id_len = sizeof(opaque_data.iana_header.vendor_id);
    opaque_data.iana_opaque_len = sizeof(opaque_data.iana_opaque);
    opaque_data.pcisig_header.header.id = SPDM_REGISTRY_ID_PCISIG;
    opaque_data.pcisig_header.header.vendor_id_len = sizeof(opaque_data.pcisig_header.vendor_id);
    opaque_data.pcisig_opaque_len = sizeof(opaque_data.pcisig_opaque);
    opaque_data.usb_header.header.id = SPDM_REGISTRY_ID_USB;
    opaque_data.usb_header.header.vendor_id_len = sizeof(opaque_data.usb_header.vendor_id);
    opaque_data.usb_opaque_len = sizeof(opaque_data.usb_opaque);
    opaque_data.tcg_header.header.id = SPDM_REGISTRY_ID_TCG;
    opaque_data.tcg_header.header.vendor_id_len = sizeof(opaque_data.tcg_header.vendor_id);
    opaque_data.tcg_opaque_len = sizeof(opaque_data.tcg_opaque);
    opaque_data.dmtf_dsp_header.header.id = SPDM_REGISTRY_ID_DMTF_DSP;
    opaque_data.dmtf_dsp_header.header.vendor_id_len = sizeof(opaque_data.dmtf_dsp_header.vendor_id);
    opaque_data.dmtf_dsp_opaque_len = sizeof(opaque_data.dmtf_dsp_opaque);
    opaque_data.dmtf_sm_ver_sel_header.header.id = SPDM_REGISTRY_ID_DMTF;
    opaque_data.dmtf_sm_ver_sel_header.header.vendor_id_len = 0;
    opaque_data.dmtf_sm_ver_sel_opaque_len = sizeof(opaque_data.dmtf_sm_ver_sel_opaque);
    opaque_data.dmtf_sm_ver_sel_opaque.sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_data.dmtf_sm_ver_sel_opaque.sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
    opaque_data.dmtf_sm_ver_sel_opaque.selected_version = SECURED_SPDM_VERSION_12 << 8;
    opaque_data.dmtf_sm_sup_ver_header.header.id = SPDM_REGISTRY_ID_DMTF;
    opaque_data.dmtf_sm_sup_ver_header.header.vendor_id_len = 0;
    opaque_data.dmtf_sm_sup_ver_opaque_len = sizeof(opaque_data.dmtf_sm_sup_ver_opaque) +
                                             sizeof(opaque_data.dmtf_sm_sup_ver_versions_list);
    opaque_data.dmtf_sm_sup_ver_opaque.sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_data.dmtf_sm_sup_ver_opaque.sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
    opaque_data.dmtf_sm_sup_ver_opaque.version_count =
        LIBSPDM_ARRAY_SIZE(opaque_data.dmtf_sm_sup_ver_versions_list);
    opaque_data.dmtf_sm_sup_ver_versions_list[0] = SECURED_SPDM_VERSION_10 << 8;
    opaque_data.dmtf_sm_sup_ver_versions_list[1] = SECURED_SPDM_VERSION_11 << 8;
    opaque_data.dmtf_sm_sup_ver_versions_list[2] = SECURED_SPDM_VERSION_12 << 8;

    opaque_data_ptr = (uint8_t *)&opaque_data;
    opaque_data_size = sizeof(opaque_data);
    status = libspdm_get_sm_data_element_from_opaque_data(spdm_context,
                                                          opaque_data_size, opaque_data_ptr,
                                                          SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION,
                                                          &get_element_ptr, &get_element_len
                                                          );
    assert_int_equal (status, true);
    status = libspdm_get_sm_data_element_from_opaque_data(spdm_context,
                                                          opaque_data_size, opaque_data_ptr,
                                                          SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION,
                                                          &get_element_ptr, &get_element_len
                                                          );
    assert_int_equal (status, true);
}

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
/**
 * Test 23: libspdm_reset_context releases the peer leaf certificate public key.
 * Expected Behavior: after a parsed leaf public key is stored for a slot,
 * reset_context frees it and clears the slot, so it is not orphaned when the
 * connection is re-established (reset_context runs on every GET_VERSION).
 **/
static void libspdm_test_reset_context_leaf_key_case23(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    bool result;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    spdm_context->local_context.is_requester = true;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }

    result = libspdm_get_leaf_cert_public_key_from_cert_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    assert_true(result);
    assert_non_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);

    libspdm_reset_context(spdm_context);

    assert_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);

    free(data);
}
#endif /* !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) */

/* DSP0277 1.3 AEAD limit: build the supported-version opaque data then append AEADlimitOE, and
 * verify the round-trip parse recovers the advertised exponent. */
static void libspdm_test_aead_limit_build_parse_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    size_t element_size;
    uint8_t *opaque_data_ptr;
    uint8_t aead_limit_exponent;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* Local secured message version list includes 1.3, so AEADlimitOE is emitted. */
    spdm_context->local_context.secured_message_version.secured_message_version_count = 4;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[1] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[2] =
        SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[3] =
        SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* Advertise a non-default exponent by setting the single-source-of-truth cap to 2^32 - 1, which
     * the builder encodes as exponent 32. The cap is the maximum allowed sequence number =
     * AeadLimit - 1 = 2^exponent - 1. */
    spdm_context->max_spdm_session_sequence_number = (((uint64_t)1 << 32) - 1);

    element_size = libspdm_get_opaque_data_aead_limit_element_size(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT);
    assert_int_not_equal(element_size, 0);

    /* The element size is 0 for a sub-1.3 version. */
    assert_int_equal(libspdm_get_opaque_data_aead_limit_element_size(
                         spdm_context, SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT),
                     0);

    opaque_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    opaque_data_ptr = malloc(opaque_data_size + element_size);
    assert_ptr_not_equal(opaque_data_ptr, NULL);

    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_data_size,
                                                     opaque_data_ptr);
    /* opaque_data_size now becomes the total buffer capacity for the append. */
    opaque_data_size += element_size;
    libspdm_build_opaque_data_aead_limit_element(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            &opaque_data_size, opaque_data_ptr);

    aead_limit_exponent = 0;
    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            opaque_data_size, opaque_data_ptr, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(aead_limit_exponent, 32);

    free(opaque_data_ptr);
}

/* DSP0277 1.3 AEAD limit: an exponent > 64 must be rejected, and an absent element must default to
 * 64. */
static void libspdm_test_aead_limit_invalid_and_default_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    size_t element_size;
    uint8_t *opaque_data_ptr;
    uint8_t aead_limit_exponent;
    secured_message_opaque_element_aead_limit_t *aead_element;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 4;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[1] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[2] =
        SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[3] =
        SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Default cap (all-ones) encodes the default exponent of 64. */
    spdm_context->max_spdm_session_sequence_number = LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER;

    element_size = libspdm_get_opaque_data_aead_limit_element_size(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT);
    assert_int_not_equal(element_size, 0);

    /* Build a valid blob with the AEADlimitOE present. */
    opaque_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    opaque_data_ptr = malloc(opaque_data_size + element_size);
    assert_ptr_not_equal(opaque_data_ptr, NULL);

    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_data_size,
                                                     opaque_data_ptr);
    /* opaque_data_size now becomes the total buffer capacity for the append. */
    opaque_data_size += element_size;
    libspdm_build_opaque_data_aead_limit_element(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            &opaque_data_size, opaque_data_ptr);

    /* Corrupt the exponent so it exceeds the max (64). The AEADlimitOE element follows the
     * element table header which is the last element in the blob. */
    aead_element = (secured_message_opaque_element_aead_limit_t *)
                   (opaque_data_ptr + opaque_data_size -
                    sizeof(secured_message_opaque_element_aead_limit_t));
    /* Account for the padding bytes (element_size rounds up to a multiple of 4). */
    aead_element = (secured_message_opaque_element_aead_limit_t *)
                   ((uint8_t *)aead_element -
                    (element_size - (sizeof(secured_message_opaque_element_table_header_t) +
                                     sizeof(secured_message_opaque_element_aead_limit_t))));
    assert_int_equal(aead_element->sm_data_id,
                     SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_AEAD_LIMIT);
    aead_element->aead_limit_exponent = SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_MAX + 1;

    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            opaque_data_size, opaque_data_ptr, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);

    /* A blob without the AEADlimitOE element must default the exponent to 64. */
    opaque_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    opaque_data_ptr = malloc(opaque_data_size);
    assert_ptr_not_equal(opaque_data_ptr, NULL);

    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_data_size,
                                                     opaque_data_ptr);

    aead_limit_exponent = 0;
    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            opaque_data_size, opaque_data_ptr, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(aead_limit_exponent, SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_DEFAULT);

    free(opaque_data_ptr);
}

/* DSP0277 1.3 AEAD limit: applying the limit to a session sets the session's max sequence number to
 * min(local cap, peer AEAD limit), and the integrator's smaller pre-set cap is never raised. The
 * local limit's single source of truth is max_spdm_session_sequence_number. */
static void libspdm_test_aead_limit_apply_to_session_case26(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint16_t req_id;
    uint16_t rsp_id;
    uint32_t session_id;
    void *session_info;
    uint64_t max_seq;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    /* Local cap = 2^40 - 1 (encodes local exponent 40), peer exponent 30. The peer's maximum allowed
     * sequence number is 2^30 - 1, so the effective session cap is min(2^40 - 1, 2^30 - 1) =
     * 2^30 - 1. The cap is the maximum allowed sequence number = AeadLimit - 1 = 2^exponent - 1. */
    spdm_context->max_spdm_session_sequence_number = (((uint64_t)1 << 40) - 1);

    req_id = libspdm_allocate_req_session_id(spdm_context, false);
    rsp_id = libspdm_allocate_rsp_session_id(spdm_context, false);
    session_id = libspdm_generate_session_id(req_id, rsp_id);
    session_info = libspdm_assign_session_id(spdm_context, session_id,
                                             SECURED_SPDM_VERSION_13 <<
                                             SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    assert_ptr_not_equal(session_info, NULL);

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    libspdm_copy_mem(parameter.additional_data, sizeof(parameter.additional_data),
                     &session_id, sizeof(session_id));

    libspdm_apply_aead_limit_to_session(spdm_context, session_info, 30);

    /* Read back the negotiated effective max sequence number per session via get_data. */
    max_seq = 0;
    data_size = sizeof(max_seq);
    assert_int_equal(libspdm_get_data(spdm_context,
                                      LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &max_seq, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(max_seq, (((uint64_t)1 << 30) - 1));

    /* A smaller local cap must never be raised by the peer's AEAD limit. With local cap 0xFFFF and
     * peer exponent 30 (2^30), the effective cap stays 0xFFFF. */
    spdm_context->max_spdm_session_sequence_number = 0xFFFF;
    libspdm_apply_aead_limit_to_session(spdm_context, session_info, 30);
    max_seq = 0;
    data_size = sizeof(max_seq);
    assert_int_equal(libspdm_get_data(spdm_context,
                                      LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &max_seq, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(max_seq, 0xFFFF);

    /* A per-session set of the max sequence number is not allowed: the session cap is owned by the
     * negotiated AEAD limit and must not be overridden. */
    max_seq = 0x1000;
    assert_int_not_equal(libspdm_set_data(spdm_context,
                                          LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                          &parameter, &max_seq, sizeof(max_seq)),
                         LIBSPDM_STATUS_SUCCESS);

    libspdm_free_session_id(spdm_context, session_id);
}

/* DSP0277 1.3 AEAD limit: the advertised AeadLimitExponent is derived from the single source of
 * truth, max_spdm_session_sequence_number (= floor(log2(max + 1)), with the all-ones cap mapping
 * to the default exponent 64 since max + 1 = 2^64 is not representable). */
static void libspdm_test_aead_limit_set_data_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    size_t element_size;
    uint8_t *opaque_data_ptr;
    uint8_t aead_limit_exponent;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 4;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[1] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[2] =
        SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[3] =
        SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    element_size = libspdm_get_opaque_data_aead_limit_element_size(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT);
    assert_int_not_equal(element_size, 0);

    /* A cap that is not of the form 2^e - 1 (here 0xFFFFFE, i.e. 2^24 - 2) rounds down to the nearest
     * representable AEAD limit 2^23, advertising exponent 23 (<= the configured cap, the safe
     * direction). floor(log2(0xFFFFFE + 1)) = floor(log2(0xFFFFFF)) = 23. */
    spdm_context->max_spdm_session_sequence_number = 0xFFFFFE;
    opaque_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    opaque_data_ptr = malloc(opaque_data_size + element_size);
    assert_ptr_not_equal(opaque_data_ptr, NULL);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_data_size,
                                                     opaque_data_ptr);
    /* opaque_data_size now becomes the total buffer capacity for the append. */
    opaque_data_size += element_size;
    libspdm_build_opaque_data_aead_limit_element(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            &opaque_data_size, opaque_data_ptr);
    aead_limit_exponent = 0;
    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            opaque_data_size, opaque_data_ptr, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(aead_limit_exponent, 23);
    free(opaque_data_ptr);

    /* The all-ones default cap advertises the default exponent of 64. */
    spdm_context->max_spdm_session_sequence_number = LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER;
    opaque_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    opaque_data_ptr = malloc(opaque_data_size + element_size);
    assert_ptr_not_equal(opaque_data_ptr, NULL);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_data_size,
                                                     opaque_data_ptr);
    /* opaque_data_size now becomes the total buffer capacity for the append. */
    opaque_data_size += element_size;
    libspdm_build_opaque_data_aead_limit_element(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            &opaque_data_size, opaque_data_ptr);
    aead_limit_exponent = 0;
    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            opaque_data_size, opaque_data_ptr, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(aead_limit_exponent, SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_DEFAULT);
    free(opaque_data_ptr);
}

#pragma pack(1)
/* A general opaque data table (SPDM 1.2 format) with the AEADlimitOE element placed BEFORE the
 * version-selection element, to exercise order-independent parsing. */
typedef struct {
    spdm_general_opaque_data_table_header_t opaque_header;
    secured_message_opaque_element_table_header_t aead_limit_header;
    secured_message_opaque_element_aead_limit_t aead_limit_opaque;
    uint8_t aead_limit_align[1];
    secured_message_opaque_element_table_header_t ver_sel_header;
    secured_message_opaque_element_version_selection_t ver_sel_opaque;
} test_aead_first_opaque_data_table_t;
#pragma pack()

/* DSP0277 1.3 AEAD limit: opaque data elements may appear in any order. Verify that AEADlimitOE is
 * still parsed correctly when it precedes the version-selection element, and that version-selection
 * parsing is likewise unaffected by the ordering. */
static void libspdm_test_aead_limit_element_order_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    test_aead_first_opaque_data_table_t opaque_data;
    spdm_version_number_t secured_message_version;
    uint8_t aead_limit_exponent;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 4;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[1] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[2] =
        SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[3] =
        SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_zero_mem(&opaque_data, sizeof(opaque_data));
    opaque_data.opaque_header.total_elements = 2;

    /* Element 1: AEADlimitOE (placed first). */
    opaque_data.aead_limit_header.id = SPDM_REGISTRY_ID_DMTF;
    opaque_data.aead_limit_header.vendor_len = 0;
    opaque_data.aead_limit_header.opaque_element_data_len =
        sizeof(secured_message_opaque_element_aead_limit_t);
    opaque_data.aead_limit_opaque.sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_data.aead_limit_opaque.sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_AEAD_LIMIT;
    opaque_data.aead_limit_opaque.aead_limit_exponent = 50;

    /* Element 2: version-selection (placed second). */
    opaque_data.ver_sel_header.id = SPDM_REGISTRY_ID_DMTF;
    opaque_data.ver_sel_header.vendor_len = 0;
    opaque_data.ver_sel_header.opaque_element_data_len =
        sizeof(secured_message_opaque_element_version_selection_t);
    opaque_data.ver_sel_opaque.sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_data.ver_sel_opaque.sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
    opaque_data.ver_sel_opaque.selected_version =
        SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* AEADlimitOE is found even though it precedes version-selection (negotiated version 1.3). */
    aead_limit_exponent = 0;
    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            sizeof(opaque_data), &opaque_data, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(aead_limit_exponent, 50);

    /* The AEADlimitOE element is only defined for secured message version 1.3. With an older
     * negotiated version (1.2) the element must be ignored and the default exponent (64) returned,
     * even though the element is physically present. */
    aead_limit_exponent = 0;
    status = libspdm_process_opaque_data_aead_limit(
        spdm_context, SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            sizeof(opaque_data), &opaque_data, &aead_limit_exponent);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(aead_limit_exponent, SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_DEFAULT);

    /* version-selection is also found regardless of the AEADlimitOE ordering. */
    secured_message_version = 0;
    status = libspdm_process_opaque_data_version_selection_data(spdm_context, sizeof(opaque_data),
                                                                &opaque_data,
                                                                &secured_message_version);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(libspdm_get_version_from_version_number(secured_message_version),
                     SECURED_SPDM_VERSION_13);
}

/* DSP0277 1.3 AEAD limit: peer-supports vs. peer-does-not-support, using a non-power-of-two local
 * cap. With local cap 0xFF00FF:
 *   - peer does not support (absent element -> exponent 64): the session cap stays 0xFF00FF.
 *   - peer supports and advertises a tighter limit: the session cap is reduced to the peer's
 *     (rounded-down) AEAD limit, never raised. */
static void libspdm_test_aead_limit_peer_support_case29(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint16_t req_id;
    uint16_t rsp_id;
    uint32_t session_id;
    void *session_info;
    uint64_t max_seq;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    /* Non-power-of-two local cap. */
    spdm_context->max_spdm_session_sequence_number = 0xFF00FF;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;

    /* Case 1: peer does NOT support AEAD limit. The message paths gate the apply on negotiated
     * secured message version >= 1.3, so for an older session the apply is never called and the
     * session cap is simply inherited from the context cap (0xFF00FF). */
    req_id = libspdm_allocate_req_session_id(spdm_context, false);
    rsp_id = libspdm_allocate_rsp_session_id(spdm_context, false);
    session_id = libspdm_generate_session_id(req_id, rsp_id);
    session_info = libspdm_assign_session_id(spdm_context, session_id,
                                             SECURED_SPDM_VERSION_12 <<
                                             SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    assert_ptr_not_equal(session_info, NULL);
    libspdm_copy_mem(parameter.additional_data, sizeof(parameter.additional_data),
                     &session_id, sizeof(session_id));
    max_seq = 0;
    data_size = sizeof(max_seq);
    assert_int_equal(libspdm_get_data(spdm_context,
                                      LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &max_seq, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(max_seq, 0xFF00FF);
    libspdm_free_session_id(spdm_context, session_id);

    /* Case 2: peer supports but advertises the default (absent element -> exponent 64). Even on a
     * 1.3 session, the negotiated cap is unchanged (min(0xFF00FF, 2^64 - 1) = 0xFF00FF). */
    req_id = libspdm_allocate_req_session_id(spdm_context, false);
    rsp_id = libspdm_allocate_rsp_session_id(spdm_context, false);
    session_id = libspdm_generate_session_id(req_id, rsp_id);
    session_info = libspdm_assign_session_id(spdm_context, session_id,
                                             SECURED_SPDM_VERSION_13 <<
                                             SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    assert_ptr_not_equal(session_info, NULL);
    libspdm_copy_mem(parameter.additional_data, sizeof(parameter.additional_data),
                     &session_id, sizeof(session_id));
    libspdm_apply_aead_limit_to_session(spdm_context, session_info,
                                        SECURED_MESSAGE_AEAD_LIMIT_EXPONENT_DEFAULT);
    max_seq = 0;
    data_size = sizeof(max_seq);
    assert_int_equal(libspdm_get_data(spdm_context,
                                      LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &max_seq, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(max_seq, 0xFF00FF);

    /* Case 3: peer supports and advertises a tighter limit (exponent 23 -> AeadLimit 2^23, max
     * allowed sequence number 2^23 - 1 = 0x7FFFFF). The session cap is reduced to
     * min(0xFF00FF, 0x7FFFFF) = 0x7FFFFF. */
    libspdm_apply_aead_limit_to_session(spdm_context, session_info, 23);
    max_seq = 0;
    data_size = sizeof(max_seq);
    assert_int_equal(libspdm_get_data(spdm_context,
                                      LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &max_seq, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(max_seq, 0x7FFFFF);
    libspdm_free_session_id(spdm_context, session_id);
}

/* DSP0277 1.3 AEAD limit: boundary semantics across exponents. AeadLimit = 2^AeadLimitExponent is
 * the first sequence number that is NOT allowed, so the maximum allowed sequence number (which is
 * what max_spdm_session_sequence_number stores) is AeadLimit - 1 = 2^exponent - 1:
 *   - exponent 0  -> AeadLimit 1     -> max 0            (only sequence number 0 is usable: one msg).
 *   - exponent 1  -> AeadLimit 2     -> max 1            (sequence numbers 0 and 1 are usable).
 *   - exponent 63 -> AeadLimit 2^63  -> max 2^63 - 1     (the largest exponent below the 2^64 clamp).
 *   - exponent 64 -> AeadLimit 2^64  -> max 2^64 - 1     (not representable as AeadLimit; the maximum
 *                                                         allowed value is the all-ones cap, which is
 *                                                         also the spec default).
 * The exponent is also round-tripped through the builder. */
static void libspdm_test_aead_limit_small_exponent_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint16_t req_id;
    uint16_t rsp_id;
    uint32_t session_id;
    void *session_info;
    uint64_t max_seq;
    size_t data_size;
    size_t opaque_data_size;
    size_t element_size;
    uint8_t *opaque_data_ptr;
    uint8_t aead_limit_exponent;
    size_t index;
    uint8_t exponent;
    uint64_t expected_max;
    const uint8_t test_exponents[] = {0, 1, 63, 64};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    /* The local cap is the default (all-ones), so the effective session cap is driven entirely by
     * the peer's advertised exponent: min(all-ones, 2^exponent) = 2^exponent. */
    spdm_context->max_spdm_session_sequence_number = LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;

    /* Each exponent negotiates a session cap of exactly 2^exponent - 1 (the maximum allowed sequence
     * number, one below the AEAD limit). */
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(test_exponents); index++) {
        exponent = test_exponents[index];
        req_id = libspdm_allocate_req_session_id(spdm_context, false);
        rsp_id = libspdm_allocate_rsp_session_id(spdm_context, false);
        session_id = libspdm_generate_session_id(req_id, rsp_id);
        session_info = libspdm_assign_session_id(spdm_context, session_id,
                                                 SECURED_SPDM_VERSION_13 <<
                                                 SPDM_VERSION_NUMBER_SHIFT_BIT, false);
        assert_ptr_not_equal(session_info, NULL);
        libspdm_copy_mem(parameter.additional_data, sizeof(parameter.additional_data),
                         &session_id, sizeof(session_id));

        libspdm_apply_aead_limit_to_session(spdm_context, session_info, exponent);

        /* AeadLimit 2^64 is not representable; exponent 64's maximum allowed value is the all-ones
         * cap. */
        expected_max = (exponent >= 64) ? LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER :
                       (((uint64_t)1 << exponent) - 1);

        max_seq = 0;
        data_size = sizeof(max_seq);
        assert_int_equal(libspdm_get_data(spdm_context,
                                          LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                          &parameter, &max_seq, &data_size),
                         LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(max_seq, expected_max);

        libspdm_free_session_id(spdm_context, session_id);
    }

    /* Builder round-trip for small exponents: a local cap of 2^exponent must advertise exponent. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 4;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[1] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[2] =
        SECURED_SPDM_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.secured_message_version[3] =
        SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    element_size = libspdm_get_opaque_data_aead_limit_element_size(
        spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT);
    assert_int_not_equal(element_size, 0);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(test_exponents); index++) {
        exponent = test_exponents[index];
        /* A local cap of 2^exponent - 1 advertises exponent; exponent 64's limit (2^64) is
         * represented by the all-ones cap. */
        spdm_context->max_spdm_session_sequence_number =
            (exponent >= 64) ? LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER :
            (((uint64_t)1 << exponent) - 1);

        opaque_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
        opaque_data_ptr = malloc(opaque_data_size + element_size);
        assert_ptr_not_equal(opaque_data_ptr, NULL);
        libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_data_size,
                                                         opaque_data_ptr);
        /* opaque_data_size now becomes the total buffer capacity for the append. */
        opaque_data_size += element_size;
        libspdm_build_opaque_data_aead_limit_element(
            spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
                &opaque_data_size, opaque_data_ptr);

        aead_limit_exponent = 0xFF;
        status = libspdm_process_opaque_data_aead_limit(
            spdm_context, SECURED_SPDM_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
                opaque_data_size, opaque_data_ptr, &aead_limit_exponent);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(aead_limit_exponent, exponent);

        free(opaque_data_ptr);
    }
}

static libspdm_test_context_t m_libspdm_common_context_data_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    NULL,
    NULL,
};

int libspdm_common_context_data_test_main(void)
{
    const struct CMUnitTest spdm_common_context_data_tests[] = {
        cmocka_unit_test(libspdm_test_common_context_data_case1),
        cmocka_unit_test(libspdm_test_common_context_data_case2),
        cmocka_unit_test(libspdm_test_common_context_data_case3),
        cmocka_unit_test(libspdm_test_common_context_data_case4),

        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case5),
        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case6),
        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case7),
        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case8),

        cmocka_unit_test(libspdm_test_set_data_case9),

        /* Successful response V1.1 for multi element opaque data supported version, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case10),
        /* Failed response V1.1 for multi element opaque data supported version, element id is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case11),
        /* Successful response V1.2 for multi element opaque data supported version, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case12),
        /* Failed response V1.2 for multi element opaque data supported version, element id is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case13),
        /* Successful response V1.1 for multi element opaque data selection version, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case14),
        /* Failed response V1.1 for multi element opaque data selection version, element number is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case15),
        /* Successful response V1.2 for multi element opaque data selection version, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case16),
        /* Failed response V1.2 for multi element opaque data selection version, element number is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case17),

        /* Successful initialization and setting of secured message context location. */
        cmocka_unit_test(libspdm_test_secured_message_context_location_selection_case18),

        /* Test that the Export Master Secret can be exported and cleared. */
        cmocka_unit_test(libspdm_test_export_master_secret_case19),
        cmocka_unit_test(libspdm_test_check_context_case20),

        /* Test the max DHE/PSK session count */
        cmocka_unit_test(libspdm_test_max_session_count_case21),

        /* Successful response V1.2 for multi element */
        cmocka_unit_test(libspdm_test_process_opaque_data_case22),

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
        /* reset_context frees the stored peer leaf certificate public key */
        cmocka_unit_test(libspdm_test_reset_context_leaf_key_case23),
#endif

        /* DSP0277 1.3 AEAD limit: build + append AEADlimitOE then parse it back. */
        cmocka_unit_test(libspdm_test_aead_limit_build_parse_case24),
        /* DSP0277 1.3 AEAD limit: reject exponent > 64, absent element defaults to 64. */
        cmocka_unit_test(libspdm_test_aead_limit_invalid_and_default_case25),
        /* DSP0277 1.3 AEAD limit: apply min(local, peer) limit to a session. */
        cmocka_unit_test(libspdm_test_aead_limit_apply_to_session_case26),
        /* DSP0277 1.3 AEAD limit: set_data validates the exponent. */
        cmocka_unit_test(libspdm_test_aead_limit_set_data_case27),
        /* DSP0277 1.3 AEAD limit: parse is order-independent (AEADlimitOE before version-sel). */
        cmocka_unit_test(libspdm_test_aead_limit_element_order_case28),
        /* DSP0277 1.3 AEAD limit: peer-supports vs peer-does-not-support with a non-pow2 cap. */
        cmocka_unit_test(libspdm_test_aead_limit_peer_support_case29),
        /* DSP0277 1.3 AEAD limit: exponent boundary semantics (exp 0, 1, 63, 64). */
        cmocka_unit_test(libspdm_test_aead_limit_small_exponent_case30),
    };

    libspdm_setup_test_context(&m_libspdm_common_context_data_test_context);

    return cmocka_run_group_tests(spdm_common_context_data_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
