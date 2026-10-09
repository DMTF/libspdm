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

    assert_ptr_equal(data, return_data);
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
    size_t root_cert_index;

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
    size_t root_cert_index;

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
        assert_true(false);
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
 *
 * Skipped if LIBSPDM_MAX_ROOT_CERT_SUPPORT is less than 2, as the first case then provisions no
 * root certificate.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case7(void **state)
{
#if (LIBSPDM_MAX_ROOT_CERT_SUPPORT) >= 2
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
    size_t root_cert_index;

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
        assert_true(false);
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
#else
    skip();
#endif
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
    size_t root_cert_index;

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
        assert_true(false);
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

    size_t root_cert_index;

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

#if LIBSPDM_CHECK_SPDM_CONTEXT
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

    libspdm_deinit_context(context);
    free(context);
}
#endif /* LIBSPDM_CHECK_SPDM_CONTEXT */

/**
 * Test 21: Allocate DHE and PSK session IDs up to the local maximums, for six splits of
 * LIBSPDM_MAX_SESSION_COUNT between the two.
 * Expected Behavior: each allocation within a maximum succeeds, and the next one fails.
 * Skipped if LIBSPDM_MAX_SESSION_COUNT is less than 2, as the first split needs two sessions.
 **/
static void libspdm_test_max_session_count_case21(void **state)
{
#if (LIBSPDM_MAX_SESSION_COUNT) >= 2
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
#else
    skip();
#endif
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
    spdm_svh_dmtf_dsp_header_t dmtf_dsp_aods_invoke_seap_header;
    uint16_t dmtf_dsp_aods_invoke_seap_opaque_len;
    aods_general_opaque_element_invoke_seap_t dmtf_dsp_aods_invoke_seap_opaque;
    uint8_t dmtf_dsp_aods_invoke_seap_opaque_align[2];
    spdm_svh_dmtf_dsp_header_t dmtf_dsp_aods_seap_success_header;
    uint16_t dmtf_dsp_aods_seap_success_opaque_len;
    aods_general_opaque_element_seap_success_t dmtf_dsp_aods_seap_success_opaque;
    spdm_svh_dmtf_dsp_header_t dmtf_dsp_aods_auth_hello_header;
    uint16_t dmtf_dsp_aods_auth_hello_opaque_len;
    aods_general_opaque_element_auth_hello_t dmtf_dsp_aods_auth_hello_opaque;
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

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_set_mem ((uint8_t *)&opaque_data, sizeof(opaque_data), 0xFF);
    opaque_data.opaque_header.total_elements = SPDM_REGISTRY_ID_MAX + 5;
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
    opaque_data.dmtf_dsp_aods_invoke_seap_header.header.id = SPDM_REGISTRY_ID_DMTF_DSP;
    opaque_data.dmtf_dsp_aods_invoke_seap_header.header.vendor_id_len =
        sizeof(opaque_data.dmtf_dsp_aods_invoke_seap_header.vendor_id);
    opaque_data.dmtf_dsp_aods_invoke_seap_header.vendor_id = SPDM_SPEC_ID_0289;
    opaque_data.dmtf_dsp_aods_invoke_seap_opaque_len =
        sizeof(opaque_data.dmtf_dsp_aods_invoke_seap_opaque);
    opaque_data.dmtf_dsp_aods_invoke_seap_opaque.aods_id =
        SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_INVOKE_SEAP;
    opaque_data.dmtf_dsp_aods_invoke_seap_opaque.presence_extension = 0;
    opaque_data.dmtf_dsp_aods_invoke_seap_opaque.credetial_id = 1;
    opaque_data.dmtf_dsp_aods_seap_success_header.header.id = SPDM_REGISTRY_ID_DMTF_DSP;
    opaque_data.dmtf_dsp_aods_seap_success_header.header.vendor_id_len =
        sizeof(opaque_data.dmtf_dsp_aods_seap_success_header.vendor_id);
    opaque_data.dmtf_dsp_aods_seap_success_header.vendor_id = SPDM_SPEC_ID_0289;
    opaque_data.dmtf_dsp_aods_seap_success_opaque_len =
        sizeof(opaque_data.dmtf_dsp_aods_seap_success_opaque);
    opaque_data.dmtf_dsp_aods_seap_success_opaque.aods_id =
        SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_SEAP_SUCCESS;
    opaque_data.dmtf_dsp_aods_seap_success_opaque.presence_extension = 0;
    opaque_data.dmtf_dsp_aods_auth_hello_header.header.id = SPDM_REGISTRY_ID_DMTF_DSP;
    opaque_data.dmtf_dsp_aods_auth_hello_header.header.vendor_id_len =
        sizeof(opaque_data.dmtf_dsp_aods_auth_hello_header.vendor_id);
    opaque_data.dmtf_dsp_aods_auth_hello_header.vendor_id = SPDM_SPEC_ID_0289;
    opaque_data.dmtf_dsp_aods_auth_hello_opaque_len =
        sizeof(opaque_data.dmtf_dsp_aods_auth_hello_opaque);
    opaque_data.dmtf_dsp_aods_auth_hello_opaque.aods_id =
        SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_AUTH_HELLO;
    opaque_data.dmtf_dsp_aods_auth_hello_opaque.presence_extension = 0;

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
    status = libspdm_get_aods_element_from_opaque_data(spdm_context,
                                                       opaque_data_size, opaque_data_ptr,
                                                       SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_INVOKE_SEAP,
                                                       &get_element_ptr, &get_element_len
                                                       );
    assert_int_equal (status, true);
    status = libspdm_get_aods_element_from_opaque_data(spdm_context,
                                                       opaque_data_size, opaque_data_ptr,
                                                       SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_SEAP_SUCCESS,
                                                       &get_element_ptr, &get_element_len
                                                       );
    assert_int_equal (status, true);
    status = libspdm_get_aods_element_from_opaque_data(spdm_context,
                                                       opaque_data_size, opaque_data_ptr,
                                                       SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_AUTH_HELLO,
                                                       &get_element_ptr, &get_element_len
                                                       );
    assert_int_equal (status, true);
}

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
/**
 * Test 23: libspdm_reset_context empties the peer certificate chain slots.
 * Expected Behavior: a slot that holds a chain as GET_CERTIFICATE leaves it, with the hash of the
 * chain and its parsed leaf public key, is emptied by reset_context. The key is freed rather than
 * orphaned, and the hash is cleared so that the slot does not look populated without a key when the
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

    result = libspdm_hash_all(m_libspdm_use_hash_algo, data, data_size,
                              spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    assert_true(result);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(m_libspdm_use_hash_algo);

    libspdm_reset_context(spdm_context);

    assert_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    assert_int_equal(spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size, 0);

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

    /* Case 2: peer supports but advertises the default (absent element -> exponent 64). On a 1.3
    * session this endpoint still enforces its own rounded-down advertised limit: the non-power-of-
    * two cap 0xFF00FF advertises exponent floor(log2(0xFF00FF + 1)) = 23, so the local advertised
    * max is 2^23 - 1 = 0x7FFFFF and the negotiated cap is min(0x7FFFFF, 2^64 - 1) = 0x7FFFFF. */
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
    assert_int_equal(max_seq, 0x7FFFFF);

    /* Case 3: peer supports and advertises a tighter limit (exponent 23 -> AeadLimit 2^23, max
     * allowed sequence number 2^23 - 1 = 0x7FFFFF). The session cap is
     * min(local 0x7FFFFF, peer 0x7FFFFF) = 0x7FFFFF. */
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

/**
 * Test 31: libspdm_reset_context restores the SPDM 1.0 and 1.1 signature endianness setting.
 * Expected Behavior: the Integrator selects BIG_OR_LITTLE and a successful verification narrows it
 * to the endianness of the peer's signatures. A connection reset returns it to BIG_OR_LITTLE, so the
 * peer of the next connection may use either endianness.
 **/
static void libspdm_test_reset_context_verify_signature_endian_case31(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint8_t endian;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN,
                              &parameter, &endian, sizeof(endian));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* The narrowing that a successful verification of a little-endian signature performs. */
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;

    libspdm_reset_context(spdm_context);

    assert_int_equal(spdm_context->spdm_10_11_verify_signature_endian,
                     LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE);
}

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
/**
 * Test 32: libspdm_reset_context ends a chunk transfer in either direction.
 * Expected Behavior: a CHUNK_GET or CHUNK_SEND transfer that is in progress is ended and the large
 * message it was carrying is erased, so a connection reset on the Requester clears the chunk state
 * as a GET_VERSION does on the Responder.
 **/
static void libspdm_test_reset_context_chunk_case32(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t *large_message;
    size_t large_message_capacity;
    libspdm_chunk_info_t *chunk_info[2];
    size_t index;
    size_t byte_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    large_message = (uint8_t *)scratch_buffer +
                    libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    large_message_capacity = libspdm_get_scratch_buffer_large_message_capacity(spdm_context);

    chunk_info[0] = &spdm_context->chunk_context.get;
    chunk_info[1] = &spdm_context->chunk_context.send;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(chunk_info); index++) {
        libspdm_set_mem(large_message, large_message_capacity, 0xa5);
        chunk_info[index]->chunk_in_use = true;
        chunk_info[index]->chunk_seq_no = 2;
        chunk_info[index]->chunk_bytes_transferred = large_message_capacity / 2;
        chunk_info[index]->large_message = large_message;
        chunk_info[index]->large_message_size = large_message_capacity;
        chunk_info[index]->large_message_capacity = large_message_capacity;

        libspdm_reset_context(spdm_context);

        assert_false(chunk_info[index]->chunk_in_use);
        assert_int_equal(chunk_info[index]->chunk_seq_no, 0);
        assert_int_equal(chunk_info[index]->chunk_bytes_transferred, 0);
        assert_null(chunk_info[index]->large_message);
        assert_int_equal(chunk_info[index]->large_message_size, 0);
        assert_int_equal(chunk_info[index]->large_message_capacity, 0);
        for (byte_index = 0; byte_index < large_message_capacity; byte_index++) {
            assert_int_equal(large_message[byte_index], 0);
        }
    }
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) && LIBSPDM_CERT_PARSE_SUPPORT
/**
 * Test 33: A Responder sets LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER to the Requester's
 * certificate chain. The default Requester algorithm (RSASSA-2048) and Responder algorithm
 * (ECDSA P-256) use different key types.
 * Expected Behavior: the peer is the Requester, so the leaf public key is parsed with
 * ReqBaseAsymAlg and libspdm_set_data succeeds. libspdm_reset_context then releases the key with
 * the same algorithm.
 **/
static void libspdm_test_set_data_peer_cert_chain_responder_case33(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    libspdm_return_t status;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;

    spdm_context->local_context.is_requester = false;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.pqc_asym_algo = 0;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.req_pqc_asym_alg = 0;

    if (!libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_req_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    parameter.additional_data[0] = 0;
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, &parameter,
                              data, data_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);

    libspdm_reset_context(spdm_context);
    assert_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);

    free(data);
}

/**
 * Test 34: A Requester sets LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER to the Responder's
 * certificate chain, with the same algorithms as Test 33.
 * Expected Behavior: the peer is the Responder, so the leaf public key is parsed with
 * BaseAsymAlgo and libspdm_set_data succeeds.
 **/
static void libspdm_test_set_data_peer_cert_chain_requester_case34(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    libspdm_return_t status;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;

    spdm_context->local_context.is_requester = true;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.pqc_asym_algo = 0;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.req_pqc_asym_alg = 0;

    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, &hash, &hash_size)) {
        assert(false);
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    parameter.additional_data[0] = 0;
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, &parameter,
                              data, data_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);

    libspdm_reset_context(spdm_context);
    assert_null(spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);

    free(data);
}
#endif /* !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) && LIBSPDM_CERT_PARSE_SUPPORT */

/* An item that libspdm_set_data or libspdm_get_data is called with, and the value or size to use. */
typedef struct {
    libspdm_data_type_t data_type;
    libspdm_data_location_t location;
    size_t data_size;
    uint64_t value;
} libspdm_test_data_item_t;

typedef union {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    uint8_t bytes[LIBSPDM_MAX_HASH_SIZE];
} libspdm_test_data_value_t;

#define LIBSPDM_TEST_SESSION_ID 0xFFFEFFFE

static void libspdm_test_encode_value(libspdm_test_data_value_t *data, size_t data_size,
                                      uint64_t value)
{
    libspdm_zero_mem(data, sizeof(*data));
    switch (data_size) {
    case sizeof(uint8_t):
        data->u8 = (uint8_t)value;
        break;
    case sizeof(uint16_t):
        data->u16 = (uint16_t)value;
        break;
    case sizeof(uint32_t):
        data->u32 = (uint32_t)value;
        break;
    case sizeof(uint64_t):
        data->u64 = value;
        break;
    default:
        fail();
        break;
    }
}

static void libspdm_test_init_parameter(libspdm_data_parameter_t *parameter,
                                        libspdm_data_location_t location, uint32_t additional_data)
{
    libspdm_zero_mem(parameter, sizeof(*parameter));
    parameter->location = location;
    libspdm_write_uint32(parameter->additional_data, additional_data);
}

static libspdm_session_info_t *libspdm_test_start_session(libspdm_context_t *spdm_context,
                                                          bool use_psk)
{
    libspdm_session_info_t *session_info;

    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, LIBSPDM_TEST_SESSION_ID,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, use_psk);
    return session_info;
}

/* Calls libspdm_set_data for each item, with additional_data holding any slot ID or session ID,
 * and checks that it returns the expected status. */
static void libspdm_test_set_data_items(libspdm_context_t *spdm_context,
                                        const libspdm_test_data_item_t *items, size_t item_count,
                                        uint32_t additional_data, libspdm_return_t expected_status)
{
    libspdm_data_parameter_t parameter;
    libspdm_test_data_value_t data;
    size_t index;

    libspdm_zero_mem(&data, sizeof(data));
    for (index = 0; index < item_count; index++) {
        libspdm_test_init_parameter(&parameter, items[index].location, additional_data);
        assert_int_equal(libspdm_set_data(spdm_context, items[index].data_type, &parameter,
                                          &data, items[index].data_size),
                         expected_status);
    }
}

/* Calls libspdm_get_data for each item, with additional_data holding any slot ID or session ID,
 * and checks that it returns the expected status. */
static void libspdm_test_get_data_items(libspdm_context_t *spdm_context,
                                        const libspdm_test_data_item_t *items, size_t item_count,
                                        uint32_t additional_data, libspdm_return_t expected_status)
{
    libspdm_data_parameter_t parameter;
    libspdm_test_data_value_t data;
    size_t data_size;
    size_t index;

    for (index = 0; index < item_count; index++) {
        libspdm_test_init_parameter(&parameter, items[index].location, additional_data);
        data_size = sizeof(data);
        assert_int_equal(libspdm_get_data(spdm_context, items[index].data_type, &parameter,
                                          &data, &data_size),
                         expected_status);
    }
}

/* Sets a LIBSPDM_DATA_LOCATION_LOCAL item and checks that its value is stored in field. */
static void libspdm_test_set_local_item(libspdm_context_t *spdm_context,
                                        libspdm_data_type_t data_type, uint8_t slot_id,
                                        size_t data_size, uint64_t value, const void *field)
{
    libspdm_data_parameter_t parameter;
    libspdm_test_data_value_t data;

    libspdm_test_encode_value(&data, data_size, value);
    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, slot_id);
    assert_int_equal(libspdm_set_data(spdm_context, data_type, &parameter, &data, data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(field, &data, data_size);
}

/* Gets an item and checks that libspdm_get_data returns the value of field. */
static void libspdm_test_get_item(libspdm_context_t *spdm_context, libspdm_data_type_t data_type,
                                  libspdm_data_location_t location, uint32_t additional_data,
                                  const void *field, size_t field_size)
{
    libspdm_data_parameter_t parameter;
    libspdm_test_data_value_t data;
    size_t data_size;

    libspdm_test_init_parameter(&parameter, location, additional_data);
    data_size = sizeof(data);
    assert_int_equal(libspdm_get_data(spdm_context, data_type, &parameter, &data, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_size, field_size);
    assert_memory_equal(&data, field, field_size);
}

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
/* Checks that hash_context holds the digest of data, without finalizing hash_context. */
static void libspdm_test_assert_digest(uint32_t base_hash_algo, const void *hash_context,
                                       const uint8_t *data, size_t data_size)
{
    uint8_t expected[LIBSPDM_MAX_HASH_SIZE];
    uint8_t actual[LIBSPDM_MAX_HASH_SIZE];
    void *copy;

    assert_non_null(hash_context);
    copy = libspdm_hash_new(base_hash_algo);
    assert_non_null(copy);
    assert_true(libspdm_hash_duplicate(base_hash_algo, hash_context, copy));
    assert_true(libspdm_hash_final(base_hash_algo, copy, actual));
    libspdm_hash_free(base_hash_algo, copy);
    assert_true(libspdm_hash_all(base_hash_algo, data, data_size, expected));
    assert_memory_equal(actual, expected, libspdm_get_hash_size(base_hash_algo));
}
#endif /* !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) */

/* Items that libspdm_get_data returns at the location libspdm_set_data stores them. */
static const libspdm_test_data_item_t m_libspdm_test_round_trip_items[] = {
    { LIBSPDM_DATA_SPDM_VERSION, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(spdm_version_number_t),
      SPDM_MESSAGE_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT },
    { LIBSPDM_DATA_CAPABILITY_FLAGS, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t),
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP },
    { LIBSPDM_DATA_CAPABILITY_FLAGS, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP },
    { LIBSPDM_DATA_CAPABILITY_EXT_FLAGS, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0x0001 },
    { LIBSPDM_DATA_CAPABILITY_EXT_FLAGS, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t),
      0x0002 },
    { LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t), 12 },
    { LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t), 13 },
    { LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(uint32_t), 0x2000 },
    { LIBSPDM_DATA_MEASUREMENT_SPEC, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t),
      SPDM_MEASUREMENT_SPECIFICATION_DMTF },
    { LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 },
    { LIBSPDM_DATA_BASE_ASYM_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 },
    { LIBSPDM_DATA_BASE_HASH_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 },
    { LIBSPDM_DATA_DHE_NAME_GROUP, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t),
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 },
    { LIBSPDM_DATA_AEAD_CIPHER_SUITE, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t),
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM },
    { LIBSPDM_DATA_REQ_BASE_ASYM_ALG, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t),
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 },
    { LIBSPDM_DATA_KEY_SCHEDULE, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t),
      SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM },
    { LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t),
      SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 },
    { LIBSPDM_DATA_MEL_SPEC, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t),
      SPDM_MEL_SPECIFICATION_DMTF },
    { LIBSPDM_DATA_PQC_ASYM_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65 },
    { LIBSPDM_DATA_REQ_PQC_ASYM_ALG, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65 },
    { LIBSPDM_DATA_KEM_ALG, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t),
      SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768 },
    { LIBSPDM_DATA_CONNECTION_STATE, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(libspdm_connection_state_t), LIBSPDM_CONNECTION_STATE_NEGOTIATED },
    { LIBSPDM_DATA_RESPONSE_STATE, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(libspdm_response_state_t),
      LIBSPDM_RESPONSE_STATE_BUSY },
    { LIBSPDM_DATA_APP_CONTEXT_DATA, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(void *), 0x1000 },
    { LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t),
      LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR },
    /* The two maximums cannot sum to more than LIBSPDM_MAX_SESSION_COUNT, which can be 1. */
    { LIBSPDM_DATA_MAX_DHE_SESSION_COUNT, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t), 1 },
    { LIBSPDM_DATA_MAX_PSK_SESSION_COUNT, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t),
      LIBSPDM_MAX_SESSION_COUNT - 1 },
    { LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(uint64_t), 0xFFFF },
    { LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(uint8_t), LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY },
    { LIBSPDM_DATA_SEQUENCE_NUMBER_ENDIAN, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t),
      LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BIG },
    { LIBSPDM_DATA_MULTI_KEY_CONN_REQ, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(bool), true },
    { LIBSPDM_DATA_MULTI_KEY_CONN_RSP, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(bool), true },
};

/* Items whose size libspdm_set_data checks, each with a size that it does not accept. */
static const libspdm_test_data_item_t m_libspdm_test_wrong_size_items[] = {
    { LIBSPDM_DATA_CAPABILITY_FLAGS, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_EXT_FLAGS, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_RTT_US, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_MEASUREMENT_SPEC, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_BASE_ASYM_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_BASE_HASH_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_DHE_NAME_GROUP, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_AEAD_CIPHER_SUITE, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_REQ_BASE_ASYM_ALG, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_KEY_SCHEDULE, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_MEL_SPEC, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_PQC_ASYM_ALGO, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_REQ_PQC_ASYM_ALG, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_KEM_ALG, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_CONNECTION_STATE, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_RESPONSE_STATE, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_LOCAL_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_LOCAL_CERT_INFO, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_HEARTBEAT_PERIOD, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_APP_CONTEXT_DATA, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_VCA_CACHE, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(((libspdm_context_t *)0)->transcript.message_a.buffer) + 1, 0 },
    { LIBSPDM_DATA_IS_REQUESTER, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_REQUEST_RETRY_TIMES, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_REQUEST_RETRY_DELAY_TIME, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_MAX_DHE_SESSION_COUNT, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_MAX_PSK_SESSION_COUNT, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_SEQUENCE_NUMBER_ENDIAN, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_MULTI_KEY_CONN_REQ, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_MULTI_KEY_CONN_RSP, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint16_t), 0 },
};

/* Items that libspdm_set_data accepts at some locations, each with a location that it rejects. */
static const libspdm_test_data_item_t m_libspdm_test_set_wrong_location_items[] = {
    { LIBSPDM_DATA_SPDM_VERSION, LIBSPDM_DATA_LOCATION_SESSION, sizeof(spdm_version_number_t), 0 },
    { LIBSPDM_DATA_SECURED_MESSAGE_VERSION, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_version_number_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_FLAGS, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_EXT_FLAGS, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_RTT_US, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t),
      0 },
    { LIBSPDM_DATA_MEASUREMENT_SPEC, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_BASE_ASYM_ALGO, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_BASE_HASH_ALGO, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_DHE_NAME_GROUP, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_AEAD_CIPHER_SUITE, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_REQ_BASE_ASYM_ALG, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_KEY_SCHEDULE, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint16_t), 0 },
    { LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_MEL_SPEC, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_PQC_ASYM_ALGO, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_REQ_PQC_ASYM_ALG, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_KEM_ALG, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(bool), 0 },
    { LIBSPDM_DATA_CONNECTION_STATE, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(libspdm_connection_state_t), 0 },
    { LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint64_t),
      0 },
    { LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t),
      0 },
    { LIBSPDM_DATA_LOCAL_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_key_pair_id_t), 0 },
    { LIBSPDM_DATA_LOCAL_CERT_INFO, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_certificate_info_t), 0 },
    { LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_key_usage_bit_mask_t), 0 },
    { LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint64_t),
      0 },
    { LIBSPDM_DATA_PEER_PUBLIC_KEY, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_LOCAL_PUBLIC_KEY, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_HEARTBEAT_PERIOD, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_IS_REQUESTER, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(bool), 0 },
    { LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER, LIBSPDM_DATA_LOCATION_SESSION,
      sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_MULTI_KEY_CONN_REQ, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(bool), 0 },
    { LIBSPDM_DATA_MULTI_KEY_CONN_RSP, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(bool), 0 },
    { LIBSPDM_DATA_SESSION_POLICY, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t), 0 },
};

/* Items that libspdm_set_data stores per slot, with the slot ID in additional_data[0]. */
static const libspdm_test_data_item_t m_libspdm_test_set_slot_items[] = {
    { LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_LOCAL_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(spdm_key_pair_id_t), 0 },
    { LIBSPDM_DATA_LOCAL_CERT_INFO, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(spdm_certificate_info_t),
      0 },
    { LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(spdm_key_usage_bit_mask_t), 0 },
    { LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(uint64_t), 0 },
};

/* Items that libspdm_get_data returns but libspdm_set_data does not store. */
static const libspdm_test_data_item_t m_libspdm_test_read_only_items[] = {
    { LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint32_t),
      0 },
    { LIBSPDM_DATA_CAPABILITY_SENDER_DATA_TRANSFER_SIZE, LIBSPDM_DATA_LOCATION_LOCAL,
      sizeof(uint32_t), 0 },
    { LIBSPDM_DATA_PEER_PROVISIONED_SLOT_MASK, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t),
      0 },
    { LIBSPDM_DATA_PEER_SUPPORTED_SLOT_MASK, LIBSPDM_DATA_LOCATION_CONNECTION, sizeof(uint8_t),
      0 },
    { LIBSPDM_DATA_PEER_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_key_pair_id_t), 0 },
    { LIBSPDM_DATA_PEER_CERT_INFO, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_certificate_info_t), 0 },
    { LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_CONNECTION,
      sizeof(spdm_key_usage_bit_mask_t), 0 },
    { LIBSPDM_DATA_REQUEST_AND_SIZE, LIBSPDM_DATA_LOCATION_LOCAL, sizeof(uint8_t), 0 },
};

/* Session items that libspdm_get_data returns but libspdm_set_data does not store. */
static const libspdm_test_data_item_t m_libspdm_test_read_only_session_items[] = {
    { LIBSPDM_DATA_SESSION_SECURED_MESSAGE_VERSION, LIBSPDM_DATA_LOCATION_SESSION,
      sizeof(spdm_version_number_t), 0 },
    { LIBSPDM_DATA_SESSION_USE_PSK, LIBSPDM_DATA_LOCATION_SESSION, sizeof(bool), 0 },
    { LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES, LIBSPDM_DATA_LOCATION_SESSION,
      sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_SESSION_POLICY, LIBSPDM_DATA_LOCATION_SESSION, sizeof(uint8_t), 0 },
    { LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_RSP_DIR, LIBSPDM_DATA_LOCATION_SESSION,
      sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_REQ_DIR, LIBSPDM_DATA_LOCATION_SESSION,
      sizeof(uint64_t), 0 },
    { LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_ENDIAN, LIBSPDM_DATA_LOCATION_SESSION,
      sizeof(uint8_t), 0 },
};

/* Items that libspdm_get_data returns at some locations, each with a location that it rejects. */
static const libspdm_test_data_item_t m_libspdm_test_get_wrong_location_items[] = {
    { LIBSPDM_DATA_SPDM_VERSION, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_FLAGS, LIBSPDM_DATA_LOCATION_SESSION, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_EXT_FLAGS, LIBSPDM_DATA_LOCATION_SESSION, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, LIBSPDM_DATA_LOCATION_SESSION, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE, LIBSPDM_DATA_LOCATION_SESSION, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE, LIBSPDM_DATA_LOCATION_SESSION, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_SENDER_DATA_TRANSFER_SIZE, LIBSPDM_DATA_LOCATION_CONNECTION, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_SENDER_DATA_TRANSFER_SIZE, LIBSPDM_DATA_LOCATION_SESSION, 0, 0 },
    { LIBSPDM_DATA_MEASUREMENT_SPEC, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_BASE_ASYM_ALGO, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_BASE_HASH_ALGO, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_DHE_NAME_GROUP, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_AEAD_CIPHER_SUITE, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_REQ_BASE_ASYM_ALG, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_KEY_SCHEDULE, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_MEL_SPEC, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PQC_ASYM_ALGO, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_REQ_PQC_ASYM_ALG, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_KEM_ALG, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_CONNECTION_STATE, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_PROVISIONED_SLOT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_SUPPORTED_SLOT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_CERT_INFO, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_MULTI_KEY_CONN_REQ, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_MULTI_KEY_CONN_RSP, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_SESSION_POLICY, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
};

/* Items that libspdm_get_data returns per slot, with the slot ID in additional_data[0]. */
static const libspdm_test_data_item_t m_libspdm_test_get_slot_items[] = {
    { LIBSPDM_DATA_PEER_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_CONNECTION, 0, 0 },
    { LIBSPDM_DATA_PEER_CERT_INFO, LIBSPDM_DATA_LOCATION_CONNECTION, 0, 0 },
    { LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_CONNECTION, 0, 0 },
};

/* Items that libspdm_set_data stores but libspdm_get_data does not return. */
static const libspdm_test_data_item_t m_libspdm_test_write_only_items[] = {
    { LIBSPDM_DATA_SECURED_MESSAGE_VERSION, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_CAPABILITY_RTT_US, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_LOCAL_KEY_PAIR_ID, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_LOCAL_CERT_INFO, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, LIBSPDM_DATA_LOCATION_CONNECTION, 0, 0 },
    { LIBSPDM_DATA_PEER_PUBLIC_KEY, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_LOCAL_PUBLIC_KEY, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_HEARTBEAT_PERIOD, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_IS_REQUESTER, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_REQUEST_RETRY_TIMES, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
    { LIBSPDM_DATA_REQUEST_RETRY_DELAY_TIME, LIBSPDM_DATA_LOCATION_LOCAL, 0, 0 },
};

/**
 * Test 35: libspdm_set_data stores each item that libspdm_get_data also returns.
 * Expected Behavior: libspdm_get_data returns the value and size that libspdm_set_data was given.
 **/
static void libspdm_test_set_get_data_round_trip_case35(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    const libspdm_test_data_item_t *item;
    libspdm_test_data_value_t data;
    libspdm_test_data_value_t returned_data;
    uint8_t vca[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    uint8_t returned_vca[sizeof(vca)];
    size_t data_size;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_test_round_trip_items); index++) {
        item = &m_libspdm_test_round_trip_items[index];
        libspdm_test_encode_value(&data, item->data_size, item->value);
        libspdm_test_init_parameter(&parameter, item->location, 0);
        assert_int_equal(libspdm_set_data(spdm_context, item->data_type, &parameter, &data,
                                          item->data_size),
                         LIBSPDM_STATUS_SUCCESS);

        libspdm_zero_mem(&returned_data, sizeof(returned_data));
        data_size = sizeof(returned_data);
        assert_int_equal(libspdm_get_data(spdm_context, item->data_type, &parameter,
                                          &returned_data, &data_size),
                         LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(data_size, item->data_size);
        assert_memory_equal(&returned_data, &data, data_size);
    }

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_VCA_CACHE, &parameter,
                                      vca, sizeof(vca)),
                     LIBSPDM_STATUS_SUCCESS);
    data_size = sizeof(returned_vca);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_VCA_CACHE, &parameter,
                                      returned_vca, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_size, sizeof(vca));
    assert_memory_equal(returned_vca, vca, sizeof(vca));
}

/**
 * Test 36: libspdm_set_data is given each LIBSPDM_DATA_LOCATION_LOCAL item that libspdm_get_data
 * does not return at that location.
 * Expected Behavior: each value is stored in the local context.
 **/
static void libspdm_test_set_data_local_items_case36(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_local_context_t *local_context;
    libspdm_data_parameter_t parameter;
    spdm_version_number_t versions[2];
    uint8_t buffer[16];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x24;
    local_context = &spdm_context->local_context;

    versions[0] = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    versions[1] = SPDM_MESSAGE_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                                      versions, sizeof(versions)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(local_context->version.spdm_version_count, 2);
    assert_memory_equal(local_context->version.spdm_version, versions, sizeof(versions));

    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                                      &parameter, versions, sizeof(versions[0])),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(local_context->secured_message_version.secured_message_version_count, 1);
    assert_int_equal(local_context->secured_message_version.secured_message_version[0],
                     versions[0]);

    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_CAPABILITY_RTT_US, 0,
                                sizeof(uint64_t), 1000, &local_context->capability.rtt);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, 0, sizeof(uint8_t),
                                SPDM_MEASUREMENT_SPECIFICATION_DMTF,
                                &local_context->algorithm.measurement_spec);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, 0,
                                sizeof(uint32_t),
                                SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
                                &local_context->algorithm.measurement_hash_algo);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, 0, sizeof(uint32_t),
                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
                                &local_context->algorithm.base_asym_algo);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, 0, sizeof(uint32_t),
                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                                &local_context->algorithm.base_hash_algo);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, 0, sizeof(uint16_t),
                                SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
                                &local_context->algorithm.dhe_named_group);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, 0,
                                sizeof(uint16_t), SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
                                &local_context->algorithm.aead_cipher_suite);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, 0,
                                sizeof(uint16_t),
                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                &local_context->algorithm.req_base_asym_alg);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, 0, sizeof(uint16_t),
                                SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM,
                                &local_context->algorithm.key_schedule);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, 0,
                                sizeof(uint8_t), SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
                                &local_context->algorithm.other_params_support);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_MEL_SPEC, 0, sizeof(uint8_t),
                                SPDM_MEL_SPECIFICATION_DMTF, &local_context->algorithm.mel_spec);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_PQC_ASYM_ALGO, 0, sizeof(uint32_t),
                                SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65,
                                &local_context->algorithm.pqc_asym_algo);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_REQ_PQC_ASYM_ALG, 0, sizeof(uint32_t),
                                SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65,
                                &local_context->algorithm.req_pqc_asym_alg);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_KEM_ALG, 0, sizeof(uint32_t),
                                SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768,
                                &local_context->algorithm.kem_alg);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST, 0,
                                sizeof(bool), true, &local_context->algorithm.pqc_first);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, 0,
                                sizeof(uint8_t), 0x03, &local_context->local_supported_slot_mask);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_LOCAL_KEY_PAIR_ID, 1,
                                sizeof(spdm_key_pair_id_t), 2,
                                &local_context->local_key_pair_id[1]);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_LOCAL_CERT_INFO, 1,
                                sizeof(spdm_certificate_info_t), 1,
                                &local_context->local_cert_info[1]);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK, 1,
                                sizeof(spdm_key_usage_bit_mask_t), 0x0003,
                                &local_context->local_key_usage_bit_mask[1]);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, 0, sizeof(uint8_t),
                                5, &local_context->heartbeat_period);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_IS_REQUESTER, 0, sizeof(bool), false,
                                &local_context->is_requester);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_REQUEST_RETRY_TIMES, 0,
                                sizeof(uint8_t), 3, &spdm_context->retry_times);
    libspdm_test_set_local_item(spdm_context, LIBSPDM_DATA_REQUEST_RETRY_DELAY_TIME, 0,
                                sizeof(uint64_t), 100, &spdm_context->retry_delay_time);

    libspdm_set_mem(buffer, sizeof(buffer), 0x5a);
    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 1);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                      &parameter, buffer, sizeof(buffer)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(local_context->local_cert_chain_provision[1], buffer);
    assert_int_equal(local_context->local_cert_chain_provision_size[1], sizeof(buffer));

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_KEY, &parameter,
                                      buffer, sizeof(buffer)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(local_context->peer_public_key_provision, buffer);
    assert_int_equal(local_context->peer_public_key_provision_size, sizeof(buffer));

    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_KEY, &parameter,
                                      buffer, sizeof(buffer) - 1),
                     LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(local_context->local_public_key_provision, buffer);
    assert_int_equal(local_context->local_public_key_provision_size, sizeof(buffer) - 1);
}

/**
 * Test 37: libspdm_set_data sets LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER to 0.
 * Expected Behavior: 0 selects the default, LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER.
 **/
static void libspdm_test_set_data_default_max_sequence_number_case37(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint64_t max_sequence_number;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x25;

    spdm_context->max_spdm_session_sequence_number = 0xFF;
    max_sequence_number = 0;
    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &max_sequence_number,
                                      sizeof(max_sequence_number)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_true(spdm_context->max_spdm_session_sequence_number ==
                LIBSPDM_MAX_SPDM_SESSION_SEQUENCE_NUMBER);
}

/**
 * Test 38: libspdm_set_data is given a data_size that the item does not accept.
 * Expected Behavior: libspdm_set_data returns LIBSPDM_STATUS_INVALID_PARAMETER for each item.
 **/
static void libspdm_test_set_data_wrong_size_case38(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x26;

    libspdm_test_set_data_items(spdm_test_context->spdm_context, m_libspdm_test_wrong_size_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_wrong_size_items), 0,
                                LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 39: libspdm_set_data is given a location that the item does not support.
 * Expected Behavior: libspdm_set_data returns LIBSPDM_STATUS_INVALID_PARAMETER for each item.
 **/
static void libspdm_test_set_data_wrong_location_case39(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x27;

    libspdm_test_set_data_items(spdm_test_context->spdm_context,
                                m_libspdm_test_set_wrong_location_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_set_wrong_location_items), 0,
                                LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 40: libspdm_set_data is given a slot ID of SPDM_MAX_SLOT_COUNT for an item that is stored
 * per slot.
 * Expected Behavior: libspdm_set_data returns LIBSPDM_STATUS_INVALID_PARAMETER for each item.
 **/
static void libspdm_test_set_data_invalid_slot_case40(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x28;

    libspdm_test_set_data_items(spdm_test_context->spdm_context, m_libspdm_test_set_slot_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_set_slot_items),
                                SPDM_MAX_SLOT_COUNT, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 41: libspdm_set_data is given a NULL context, an out-of-range data type, a session that
 * does not exist, or a value that the item does not accept.
 * Expected Behavior: libspdm_set_data returns LIBSPDM_STATUS_INVALID_PARAMETER for each.
 **/
static void libspdm_test_set_data_invalid_value_case41(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint32_t response_state;
    void *app_context_data;
    uint32_t session_count;
    uint8_t data8;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x29;

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    data8 = 0;
    assert_int_equal(libspdm_set_data(NULL, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter, &data8,
                                      sizeof(data8)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_MAX, &parameter, &data8,
                                      sizeof(data8)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    response_state = LIBSPDM_RESPONSE_STATE_MAX;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_RESPONSE_STATE, &parameter,
                                      &response_state, sizeof(libspdm_response_state_t)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    app_context_data = NULL;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
                                      &app_context_data, sizeof(app_context_data)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    session_count = LIBSPDM_MAX_SESSION_COUNT + 1;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_MAX_DHE_SESSION_COUNT,
                                      &parameter, &session_count, sizeof(session_count)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    spdm_context->max_dhe_session_count = LIBSPDM_MAX_SESSION_COUNT;
    session_count = 1;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_MAX_PSK_SESSION_COUNT,
                                      &parameter, &session_count, sizeof(session_count)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    data8 = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE + 1;
    assert_int_equal(libspdm_set_data(spdm_context,
                                      LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN,
                                      &parameter, &data8, sizeof(data8)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_SESSION,
                                LIBSPDM_TEST_SESSION_ID);
    data8 = 0;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_POLICY, &parameter,
                                      &data8, sizeof(data8)),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 42: libspdm_set_data is given an item that libspdm_get_data returns but that the
 * Integrator cannot set.
 * Expected Behavior: libspdm_set_data returns LIBSPDM_STATUS_UNSUPPORTED_CAP for each item,
 * including the session items of a session that exists.
 **/
static void libspdm_test_set_data_read_only_case42(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2A;

    libspdm_test_set_data_items(spdm_context, m_libspdm_test_read_only_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_read_only_items), 0,
                                LIBSPDM_STATUS_UNSUPPORTED_CAP);

    libspdm_test_start_session(spdm_context, false);
    libspdm_test_set_data_items(spdm_context, m_libspdm_test_read_only_session_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_read_only_session_items),
                                LIBSPDM_TEST_SESSION_ID, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 43: libspdm_get_data is given a location that the item does not support.
 * Expected Behavior: libspdm_get_data returns LIBSPDM_STATUS_INVALID_PARAMETER for each item.
 **/
static void libspdm_test_get_data_wrong_location_case43(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2B;

    libspdm_test_get_data_items(spdm_test_context->spdm_context,
                                m_libspdm_test_get_wrong_location_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_get_wrong_location_items), 0,
                                LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 44: libspdm_get_data is given a NULL argument, an out-of-range data type, a slot ID of
 * SPDM_MAX_SLOT_COUNT, or a session that does not exist.
 * Expected Behavior: libspdm_get_data returns LIBSPDM_STATUS_INVALID_PARAMETER for each.
 **/
static void libspdm_test_get_data_invalid_parameter_case44(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint64_t data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2C;

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    data_size = sizeof(data);
    assert_int_equal(libspdm_get_data(NULL, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &data,
                                      &data_size),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                                      NULL, &data_size),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                                      &data, NULL),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_MAX, &parameter, &data,
                                      &data_size),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    libspdm_test_get_data_items(spdm_context, m_libspdm_test_get_slot_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_get_slot_items),
                                SPDM_MAX_SLOT_COUNT, LIBSPDM_STATUS_INVALID_PARAMETER);

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_SESSION,
                                LIBSPDM_TEST_SESSION_ID);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_POLICY, &parameter,
                                      &data, &data_size),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                                      &parameter, &data, &data_size),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 45: libspdm_get_data is given an item that the Integrator can set but not get.
 * Expected Behavior: libspdm_get_data returns LIBSPDM_STATUS_UNSUPPORTED_CAP for each item.
 **/
static void libspdm_test_get_data_write_only_case45(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2D;

    libspdm_test_get_data_items(spdm_test_context->spdm_context, m_libspdm_test_write_only_items,
                                LIBSPDM_ARRAY_SIZE(m_libspdm_test_write_only_items), 0,
                                LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 46: libspdm_get_data is given each item outside of a session that libspdm sets and the
 * Integrator can only read.
 * Expected Behavior: libspdm_get_data returns the value that libspdm holds for each item.
 **/
static void libspdm_test_get_data_read_only_case46(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_connection_info_t *connection_info;
    libspdm_data_parameter_t parameter;
    uint8_t request[4];
    uint8_t returned_request[sizeof(request)];
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2E;
    connection_info = &spdm_context->connection_info;

    connection_info->capability.data_transfer_size = 0x1234;
    connection_info->peer_provisioned_slot_mask = 0x05;
    connection_info->peer_supported_slot_mask = 0x07;
    connection_info->peer_key_pair_id[1] = 4;
    connection_info->peer_cert_info[1] = 2;
    connection_info->peer_key_usage_bit_mask[1] = 0x0002;
    connection_info->end_session_attributes =
        SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;

    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE,
                          LIBSPDM_DATA_LOCATION_LOCAL, 0,
                          &spdm_context->local_context.capability.data_transfer_size,
                          sizeof(uint32_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 0,
                          &connection_info->capability.data_transfer_size, sizeof(uint32_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE,
                          LIBSPDM_DATA_LOCATION_LOCAL, 0,
                          &spdm_context->local_context.capability.max_spdm_msg_size,
                          sizeof(uint32_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_CAPABILITY_SENDER_DATA_TRANSFER_SIZE,
                          LIBSPDM_DATA_LOCATION_LOCAL, 0,
                          &spdm_context->local_context.capability.sender_data_transfer_size,
                          sizeof(uint32_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_PEER_PROVISIONED_SLOT_MASK,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 0,
                          &connection_info->peer_provisioned_slot_mask, sizeof(uint8_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_PEER_SUPPORTED_SLOT_MASK,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 0,
                          &connection_info->peer_supported_slot_mask, sizeof(uint8_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_PEER_KEY_PAIR_ID,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 1,
                          &connection_info->peer_key_pair_id[1], sizeof(spdm_key_pair_id_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_PEER_CERT_INFO,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 1,
                          &connection_info->peer_cert_info[1], sizeof(spdm_certificate_info_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 1,
                          &connection_info->peer_key_usage_bit_mask[1],
                          sizeof(spdm_key_usage_bit_mask_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES,
                          LIBSPDM_DATA_LOCATION_CONNECTION, 0,
                          &connection_info->end_session_attributes, sizeof(uint8_t));

    request[0] = SPDM_MESSAGE_VERSION_12;
    request[1] = SPDM_GET_VERSION;
    request[2] = 0;
    request[3] = 0;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     request, sizeof(request));
    spdm_context->last_spdm_request_size = sizeof(request);
    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_LOCAL, 0);
    data_size = sizeof(returned_request);
    assert_int_equal(libspdm_get_data(spdm_context, LIBSPDM_DATA_REQUEST_AND_SIZE, &parameter,
                                      returned_request, &data_size),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_size, sizeof(request));
    assert_memory_equal(returned_request, request, sizeof(request));
}

/**
 * Test 47: libspdm_get_data is given each session item for a session that exists.
 * Expected Behavior: libspdm_get_data returns the session's value for each item.
 **/
static void libspdm_test_get_data_session_items_case47(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2F;

    session_info = libspdm_test_start_session(spdm_context, true);
    secured_context = session_info->secured_message_context;
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    session_info->end_session_attributes =
        SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;
    session_info->session_policy = 0x01;
    secured_context->application_secret.request_data_sequence_number = 5;
    secured_context->application_secret.response_data_sequence_number = 6;
    secured_context->max_spdm_session_sequence_number = 0xFFFF;
    secured_context->sequence_number_endian = LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BIG;

    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_SECURED_MESSAGE_VERSION,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &secured_context->secured_message_version,
                          sizeof(spdm_version_number_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_USE_PSK,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &session_info->use_psk, sizeof(bool));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &session_info->mut_auth_requested, sizeof(uint8_t));
    /* LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES is read at LIBSPDM_DATA_LOCATION_CONNECTION. */
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES,
                          LIBSPDM_DATA_LOCATION_CONNECTION, LIBSPDM_TEST_SESSION_ID,
                          &session_info->end_session_attributes, sizeof(uint8_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_POLICY,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &session_info->session_policy, sizeof(uint8_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_REQ_DIR,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &secured_context->application_secret.request_data_sequence_number,
                          sizeof(uint64_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_RSP_DIR,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &secured_context->application_secret.response_data_sequence_number,
                          sizeof(uint64_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &secured_context->max_spdm_session_sequence_number, sizeof(uint64_t));
    libspdm_test_get_item(spdm_context, LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_ENDIAN,
                          LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_TEST_SESSION_ID,
                          &secured_context->sequence_number_endian, sizeof(uint8_t));
}

/**
 * Test 48: libspdm_set_data sets LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER to a buffer that is not
 * a certificate chain, with a traditional and then with a PQC asymmetric algorithm negotiated.
 * Expected Behavior: the leaf certificate's public key cannot be parsed, so libspdm_set_data
 * returns LIBSPDM_STATUS_INVALID_CERT in both cases. Skipped if
 * LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled or LIBSPDM_CERT_PARSE_SUPPORT is disabled, as
 * libspdm then does not parse the chain.
 **/
static void libspdm_test_set_data_peer_cert_chain_invalid_case48(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) && LIBSPDM_CERT_PARSE_SUPPORT
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    uint8_t cert_chain[64];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x30;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    libspdm_set_mem(cert_chain, sizeof(cert_chain), 0xa5);

    libspdm_test_init_parameter(&parameter, LIBSPDM_DATA_LOCATION_CONNECTION, 0);
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                                      &parameter, cert_chain, sizeof(cert_chain)),
                     LIBSPDM_STATUS_INVALID_CERT);

    spdm_context->connection_info.algorithm.pqc_asym_algo =
        SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                                      &parameter, cert_chain, sizeof(cert_chain)),
                     LIBSPDM_STATUS_INVALID_CERT);
#else
    skip();
#endif
}

/**
 * Test 49: libspdm_is_version_supported is asked about the connection version and another version.
 * Expected Behavior: only the connection version is supported.
 **/
static void libspdm_test_is_version_supported_case49(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x31;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    assert_true(libspdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_12));
    assert_false(libspdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11));
}

/**
 * Test 50: libspdm_is_capabilities_ext_flag_supported is asked about extended capability flags
 * from the Requester's and the Responder's point of view.
 * Expected Behavior: the Requester's flags are the local flags of a Requester and the connection's
 * flags of a Responder, and the Responder's flags are the other set.
 **/
static void libspdm_test_is_capabilities_ext_flag_supported_case50(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x32;

    spdm_context->local_context.capability.ext_flags = 0x0001;
    spdm_context->connection_info.capability.ext_flags = 0x0002;

    assert_true(libspdm_is_capabilities_ext_flag_supported(spdm_context, true, 0x0001, 0x0002));
    assert_false(libspdm_is_capabilities_ext_flag_supported(spdm_context, true, 0x0002, 0));
    assert_true(libspdm_is_capabilities_ext_flag_supported(spdm_context, false, 0x0002, 0x0001));
    assert_false(libspdm_is_capabilities_ext_flag_supported(spdm_context, false, 0, 0x0002));
}

/**
 * Test 51: libspdm_is_encap_supported is called for an SPDM 1.0 connection in which both
 * endpoints set ENCAP_CAP.
 * Expected Behavior: SPDM 1.0 has no encapsulated requests, so it returns false.
 **/
static void libspdm_test_is_encap_supported_10_case51(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x33;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    assert_false(libspdm_is_encap_supported(spdm_context));
}

/**
 * Test 52: libspdm_is_encap_supported is called for an SPDM 1.2 connection in which both
 * endpoints set MUT_AUTH_CAP but not ENCAP_CAP.
 * Expected Behavior: ENCAP_CAP was deprecated in SPDM 1.2.0 and 1.2.1 and MUT_AUTH_CAP was used in
 * its place, so it returns true.
 **/
static void libspdm_test_is_encap_supported_12_case52(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x34;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    assert_true(libspdm_is_encap_supported(spdm_context));
}

/**
 * Test 53: The device buffers are registered before the transport layer.
 * Expected Behavior: the data transfer sizes are first the whole buffer sizes, and
 * libspdm_register_transport_layer_func then removes the transport header and tail from them.
 **/
static void libspdm_test_register_transport_after_buffer_case53(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x35;

    spdm_context = (libspdm_context_t *)malloc(libspdm_get_context_size());
    assert_non_null(spdm_context);
    libspdm_init_context(spdm_context);

    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);
    assert_int_equal(spdm_context->local_context.capability.data_transfer_size,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE);
    assert_int_equal(spdm_context->local_context.capability.sender_data_transfer_size,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE);

    libspdm_register_transport_layer_func(spdm_context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message);
    assert_int_equal(spdm_context->local_context.capability.data_transfer_size,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE -
                     (LIBSPDM_TEST_TRANSPORT_HEADER_SIZE + LIBSPDM_TEST_TRANSPORT_TAIL_SIZE));
    assert_int_equal(spdm_context->local_context.capability.sender_data_transfer_size,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE -
                     (LIBSPDM_TEST_TRANSPORT_HEADER_SIZE + LIBSPDM_TEST_TRANSPORT_TAIL_SIZE));

    libspdm_deinit_context(spdm_context);
    free(spdm_context);
}

static bool libspdm_test_verify_spdm_cert_chain(void *spdm_context, uint8_t slot_id,
                                                size_t cert_chain_size, const void *cert_chain,
                                                const void **trust_anchor,
                                                size_t *trust_anchor_size)
{
    return true;
}

/**
 * Test 54: The Integrator registers a certificate chain verification function.
 * Expected Behavior: libspdm stores the function for verifying the peer's certificate chain.
 **/
static void libspdm_test_register_verify_spdm_cert_chain_func_case54(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x36;

    libspdm_register_verify_spdm_cert_chain_func(spdm_context,
                                                 libspdm_test_verify_spdm_cert_chain);
    assert_true(spdm_context->local_context.verify_peer_spdm_cert_chain ==
                libspdm_test_verify_spdm_cert_chain);
}

/**
 * Test 55: libspdm_get_receiver_buffer is called while the receiver buffer is acquired.
 * Expected Behavior: it returns the Integrator's receiver buffer and its registered size.
 **/
static void libspdm_test_get_receiver_buffer_case55(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *message;
    size_t message_size;
    void *receiver_buffer;
    size_t receiver_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x37;

    assert_int_equal(libspdm_acquire_receiver_buffer(spdm_context, &message_size, &message),
                     LIBSPDM_STATUS_SUCCESS);
    libspdm_get_receiver_buffer(spdm_context, &receiver_buffer, &receiver_buffer_size);
    libspdm_release_receiver_buffer(spdm_context);

    assert_non_null(receiver_buffer);
    assert_int_equal(receiver_buffer_size, LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE);
}

/**
 * Test 56: libspdm_get_last_spdm_error_struct is called after libspdm_set_last_spdm_error_struct.
 * Expected Behavior: it returns the error code and session ID that were set.
 **/
static void libspdm_test_last_spdm_error_struct_case56(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_error_struct_t last_spdm_error;
    libspdm_error_struct_t returned_error;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x38;

    libspdm_zero_mem(&last_spdm_error, sizeof(last_spdm_error));
    last_spdm_error.error_code = SPDM_ERROR_CODE_DECRYPT_ERROR;
    last_spdm_error.session_id = LIBSPDM_TEST_SESSION_ID;
    libspdm_set_last_spdm_error_struct(spdm_context, &last_spdm_error);

    libspdm_zero_mem(&returned_error, sizeof(returned_error));
    libspdm_get_last_spdm_error_struct(spdm_context, &returned_error);
    assert_int_equal(returned_error.error_code, SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(returned_error.session_id, LIBSPDM_TEST_SESSION_ID);
}

/**
 * Test 57: The Integrator initializes a FIPS self-test context, imports it into the SPDM context,
 * and exports it again.
 * Expected Behavior: each step succeeds and the exported context matches the imported one.
 * Skipped if LIBSPDM_FIPS_MODE is disabled.
 **/
static void libspdm_test_fips_selftest_context_case57(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t context_size;
    void *fips_selftest_context;
    void *exported_context;
    uint8_t *selftest_buffer;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x39;

    context_size = libspdm_get_fips_selftest_context_size();
    fips_selftest_context = malloc(context_size);
    exported_context = malloc(context_size);
    selftest_buffer = malloc(libspdm_get_fips_selftest_buffer_size() + 1);
    assert_non_null(fips_selftest_context);
    assert_non_null(exported_context);
    assert_non_null(selftest_buffer);

    assert_int_equal(libspdm_init_fips_selftest_context(fips_selftest_context,
                                                        libspdm_get_fips_selftest_buffer_size(),
                                                        selftest_buffer),
                     LIBSPDM_STATUS_SUCCESS);
    assert_true(libspdm_import_fips_selftest_context_to_spdm_context(spdm_context,
                                                                     fips_selftest_context,
                                                                     context_size));
    libspdm_zero_mem(exported_context, context_size);
    assert_true(libspdm_export_fips_selftest_context_from_spdm_context(spdm_context,
                                                                       exported_context,
                                                                       context_size));
    assert_memory_equal(exported_context, fips_selftest_context, context_size);

    free(selftest_buffer);
    free(exported_context);
    free(fips_selftest_context);
#else
    skip();
#endif
}

/**
 * Test 58: A FIPS self-test context is imported or exported with a NULL context or a wrong size.
 * Expected Behavior: libspdm_import_fips_selftest_context_to_spdm_context and
 * libspdm_export_fips_selftest_context_from_spdm_context return false. Skipped if
 * LIBSPDM_FIPS_MODE is disabled.
 **/
static void libspdm_test_fips_selftest_context_invalid_case58(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t context_size;
    void *fips_selftest_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3A;

    context_size = libspdm_get_fips_selftest_context_size();
    fips_selftest_context = malloc(context_size);
    assert_non_null(fips_selftest_context);
    libspdm_zero_mem(fips_selftest_context, context_size);

    assert_false(libspdm_import_fips_selftest_context_to_spdm_context(NULL, fips_selftest_context,
                                                                      context_size));
    assert_false(libspdm_import_fips_selftest_context_to_spdm_context(spdm_context, NULL,
                                                                      context_size));
    assert_false(libspdm_import_fips_selftest_context_to_spdm_context(spdm_context,
                                                                      fips_selftest_context,
                                                                      context_size - 1));
    assert_false(libspdm_export_fips_selftest_context_from_spdm_context(NULL,
                                                                        fips_selftest_context,
                                                                        context_size));
    assert_false(libspdm_export_fips_selftest_context_from_spdm_context(spdm_context, NULL,
                                                                        context_size));
    assert_false(libspdm_export_fips_selftest_context_from_spdm_context(spdm_context,
                                                                        fips_selftest_context,
                                                                        context_size - 1));

    free(fips_selftest_context);
#else
    skip();
#endif
}

/**
 * Test 59: The sender data transfer size is below SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12.
 * Expected Behavior: libspdm_check_context returns false. Skipped if LIBSPDM_CHECK_SPDM_CONTEXT is
 * disabled.
 **/
static void libspdm_test_check_context_sender_size_case59(void **state)
{
#if LIBSPDM_CHECK_SPDM_CONTEXT
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3B;

    spdm_context->local_context.capability.sender_data_transfer_size =
        SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12 - 1;

    assert_false(libspdm_check_context(spdm_context));
#else
    skip();
#endif
}

/**
 * Test 60: The maximum SPDM message size is smaller than the sender data transfer size.
 * Expected Behavior: libspdm_check_context returns false. Skipped if LIBSPDM_CHECK_SPDM_CONTEXT is
 * disabled.
 **/
static void libspdm_test_check_context_sender_max_msg_size_case60(void **state)
{
#if LIBSPDM_CHECK_SPDM_CONTEXT
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3C;

    spdm_context->local_context.capability.sender_data_transfer_size =
        spdm_context->local_context.capability.max_spdm_msg_size + 1;

    assert_false(libspdm_check_context(spdm_context));
#else
    skip();
#endif
}

/**
 * Test 61: CHUNK_CAP is set and a local certificate chain does not fit in a CERTIFICATE response
 * of the maximum SPDM message size.
 * Expected Behavior: libspdm_check_context returns false. Skipped if LIBSPDM_CHECK_SPDM_CONTEXT is
 * disabled.
 **/
static void libspdm_test_check_context_cert_chain_size_case61(void **state)
{
#if LIBSPDM_CHECK_SPDM_CONTEXT
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3D;

    cert_chain = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->local_context.local_cert_chain_provision[1] = &cert_chain;
    spdm_context->local_context.local_cert_chain_provision_size[1] =
        spdm_context->local_context.capability.max_spdm_msg_size;

    assert_false(libspdm_check_context(spdm_context));
#else
    skip();
#endif
}

/**
 * Test 62: libspdm_init_context_with_secured_context is given a NULL secured message context.
 * Expected Behavior: it returns LIBSPDM_STATUS_INVALID_PARAMETER.
 **/
static void libspdm_test_init_context_null_secured_context_case62(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    void *spdm_context;
    void *secured_contexts[LIBSPDM_MAX_SESSION_COUNT];
    uint8_t *secured_context_buffer;
    size_t secured_context_size;
    size_t index;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3E;

    spdm_context = malloc(libspdm_get_context_size_without_secured_context());
    secured_context_size = libspdm_secured_message_get_context_size();
    secured_context_buffer = malloc(secured_context_size * LIBSPDM_MAX_SESSION_COUNT);
    assert_non_null(spdm_context);
    assert_non_null(secured_context_buffer);
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        secured_contexts[index] = secured_context_buffer + index * secured_context_size;
    }
    secured_contexts[LIBSPDM_MAX_SESSION_COUNT - 1] = NULL;

    assert_int_equal(libspdm_init_context_with_secured_context(spdm_context, secured_contexts,
                                                               LIBSPDM_MAX_SESSION_COUNT),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    free(secured_context_buffer);
    free(spdm_context);
}

/**
 * Test 63: libspdm_reset_message_c is called while the M1/M2 transcript is being hashed.
 * Expected Behavior: the M1/M2 hash context is freed. Skipped if
 * LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript is then recorded rather
 * than hashed.
 **/
static void libspdm_test_reset_message_c_case63(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_GET_DIGESTS, 0, 0 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3F;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    assert_int_equal(libspdm_append_message_b(spdm_context, message, sizeof(message)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_non_null(spdm_context->transcript.digest_context_m1m2);

    libspdm_reset_message_c(spdm_context);

    assert_null(spdm_context->transcript.digest_context_m1m2);
#else
    skip();
#endif
}

/**
 * Test 64: A GET_MEASUREMENTS request is added to the L1/L2 transcript of a session of an SPDM 1.2
 * connection.
 * Expected Behavior: as of SPDM 1.2 the transcript starts with the VCA messages, so the session's
 * L1/L2 hash covers the VCA followed by the request. Skipped if
 * LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript is then recorded rather
 * than hashed.
 **/
static void libspdm_test_append_message_m_session_case64(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t vca[] = { 0x10, 0x11, 0x12 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_GET_MEASUREMENTS, 0, 0 };
    uint8_t expected[sizeof(vca) + sizeof(message)];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x40;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    assert_int_equal(libspdm_append_message_a(spdm_context, vca, sizeof(vca)),
                     LIBSPDM_STATUS_SUCCESS);
    session_info = libspdm_test_start_session(spdm_context, false);

    assert_int_equal(libspdm_append_message_m(spdm_context, session_info, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_SUCCESS);

    libspdm_copy_mem(expected, sizeof(expected), vca, sizeof(vca));
    libspdm_copy_mem(expected + sizeof(vca), sizeof(expected) - sizeof(vca),
                     message, sizeof(message));
    libspdm_test_assert_digest(m_libspdm_use_hash_algo,
                               session_info->session_transcript.digest_context_l1l2,
                               expected, sizeof(expected));
#else
    skip();
#endif
}

/**
 * Test 65: A Requester adds KEY_EXCHANGE to the transcript of a session with a Responder that
 * negotiated multiple asymmetric keys.
 * Expected Behavior: the transcript hash covers the VCA, the connection's DIGESTS, the hash of the
 * Responder's certificate chain, and the request. Skipped if
 * LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript is then recorded rather
 * than hashed.
 **/
static void libspdm_test_append_message_k_multi_key_case65(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t vca[] = { 0x10, 0x11, 0x12 };
    uint8_t digests[] = { 0x20, 0x21 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_KEY_EXCHANGE, 0, 0 };
    uint8_t expected[sizeof(vca) + sizeof(digests) + LIBSPDM_MAX_HASH_SIZE + sizeof(message)];
    uint32_t hash_size;
    size_t expected_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x41;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = hash_size;
    libspdm_set_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                    hash_size, 0x30);
    assert_int_equal(libspdm_append_message_a(spdm_context, vca, sizeof(vca)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(libspdm_append_message_d(spdm_context, digests, sizeof(digests)),
                     LIBSPDM_STATUS_SUCCESS);
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->peer_used_cert_chain_slot_id = 0;

    assert_int_equal(libspdm_append_message_k(spdm_context, session_info, true, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_SUCCESS);

    expected_size = 0;
    libspdm_copy_mem(expected, sizeof(expected), vca, sizeof(vca));
    expected_size += sizeof(vca);
    libspdm_copy_mem(expected + expected_size, sizeof(expected) - expected_size,
                     digests, sizeof(digests));
    expected_size += sizeof(digests);
    libspdm_copy_mem(expected + expected_size, sizeof(expected) - expected_size,
                     spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash, hash_size);
    expected_size += hash_size;
    libspdm_copy_mem(expected + expected_size, sizeof(expected) - expected_size,
                     message, sizeof(message));
    expected_size += sizeof(message);
    libspdm_test_assert_digest(m_libspdm_use_hash_algo,
                               session_info->session_transcript.digest_context_th,
                               expected, expected_size);
#else
    skip();
#endif
}

/**
 * Test 66: A Requester that negotiated multiple asymmetric keys adds FINISH to the transcript of a
 * session with mutual authentication.
 * Expected Behavior: the transcript hash covers the VCA, the hash of the Responder's certificate
 * chain, the encapsulated DIGESTS, the hash of the Requester's certificate chain, and the request.
 * Skipped if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript is then
 * recorded rather than hashed.
 **/
static void libspdm_test_append_message_f_multi_key_case66(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t vca[] = { 0x10, 0x11, 0x12 };
    uint8_t encap_digests[] = { 0x40, 0x41 };
    uint8_t local_cert_chain[] = { 0x50, 0x51, 0x52, 0x53 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_FINISH, 0, 0 };
    uint8_t expected[sizeof(vca) + LIBSPDM_MAX_HASH_SIZE + sizeof(encap_digests) +
                     LIBSPDM_MAX_HASH_SIZE + sizeof(message)];
    uint32_t hash_size;
    size_t expected_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x42;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = hash_size;
    libspdm_set_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                    hash_size, 0x30);
    spdm_context->local_context.local_cert_chain_provision[0] = local_cert_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] = sizeof(local_cert_chain);
    assert_int_equal(libspdm_append_message_a(spdm_context, vca, sizeof(vca)),
                     LIBSPDM_STATUS_SUCCESS);
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->peer_used_cert_chain_slot_id = 0;
    session_info->local_used_cert_chain_slot_id = 0;
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    assert_int_equal(libspdm_append_message_encap_d(session_info, encap_digests,
                                                    sizeof(encap_digests)),
                     LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(libspdm_append_message_f(spdm_context, session_info, true, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_SUCCESS);

    expected_size = 0;
    libspdm_copy_mem(expected, sizeof(expected), vca, sizeof(vca));
    expected_size += sizeof(vca);
    libspdm_copy_mem(expected + expected_size, sizeof(expected) - expected_size,
                     spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash, hash_size);
    expected_size += hash_size;
    libspdm_copy_mem(expected + expected_size, sizeof(expected) - expected_size,
                     encap_digests, sizeof(encap_digests));
    expected_size += sizeof(encap_digests);
    assert_true(libspdm_hash_all(m_libspdm_use_hash_algo, local_cert_chain,
                                 sizeof(local_cert_chain), expected + expected_size));
    expected_size += hash_size;
    libspdm_copy_mem(expected + expected_size, sizeof(expected) - expected_size,
                     message, sizeof(message));
    expected_size += sizeof(message);
    libspdm_test_assert_digest(m_libspdm_use_hash_algo,
                               session_info->session_transcript.digest_context_th,
                               expected, expected_size);
#else
    skip();
#endif
}

/**
 * Test 67: A Requester adds KEY_EXCHANGE to the transcript of a session that uses the Responder's
 * public key (slot 0xFF), but no public key has been provisioned for the Responder.
 * Expected Behavior: libspdm_append_message_k returns LIBSPDM_STATUS_INVALID_STATE_PEER. Skipped
 * if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript then does not contain
 * the public key.
 **/
static void libspdm_test_append_message_k_no_peer_public_key_case67(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_KEY_EXCHANGE, 0, 0 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x43;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->peer_used_cert_chain_slot_id = 0xFF;

    assert_int_equal(libspdm_append_message_k(spdm_context, session_info, true, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_INVALID_STATE_PEER);
#else
    skip();
#endif
}

/**
 * Test 68: A Responder adds KEY_EXCHANGE to the transcript of a session that uses its public key
 * (slot 0xFF), but no public key has been provisioned for the Responder.
 * Expected Behavior: libspdm_append_message_k returns LIBSPDM_STATUS_INVALID_STATE_LOCAL. Skipped
 * if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript then does not contain
 * the public key.
 **/
static void libspdm_test_append_message_k_no_local_public_key_case68(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_KEY_EXCHANGE, 0, 0 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x44;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->local_used_cert_chain_slot_id = 0xFF;

    assert_int_equal(libspdm_append_message_k(spdm_context, session_info, false, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_INVALID_STATE_LOCAL);
#else
    skip();
#endif
}

/**
 * Test 69: A Requester adds FINISH to a session transcript that has no KEY_EXCHANGE yet, in a
 * session that uses the Responder's public key (slot 0xFF), but no public key has been
 * provisioned for the Responder.
 * Expected Behavior: libspdm_append_message_f returns the LIBSPDM_STATUS_INVALID_STATE_PEER of the
 * KEY_EXCHANGE part of the transcript. Skipped if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is
 * enabled, as the transcript then does not contain the public key.
 **/
static void libspdm_test_append_message_f_no_peer_public_key_case69(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_FINISH, 0, 0 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x45;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->peer_used_cert_chain_slot_id = 0xFF;

    assert_int_equal(libspdm_append_message_f(spdm_context, session_info, true, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_INVALID_STATE_PEER);
#else
    skip();
#endif
}

/**
 * Test 70: A Requester adds FINISH to the transcript of a session with mutual authentication that
 * uses the Requester's public key (slot 0xFF), but no public key has been provisioned for the
 * Requester.
 * Expected Behavior: libspdm_append_message_f returns LIBSPDM_STATUS_INVALID_STATE_LOCAL. Skipped
 * if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript then does not contain
 * the public key.
 **/
static void libspdm_test_append_message_f_no_local_public_key_case70(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_FINISH, 0, 0 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x46;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(m_libspdm_use_hash_algo);
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->peer_used_cert_chain_slot_id = 0;
    session_info->local_used_cert_chain_slot_id = 0xFF;
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    assert_int_equal(libspdm_append_message_f(spdm_context, session_info, true, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_INVALID_STATE_LOCAL);
#else
    skip();
#endif
}

/**
 * Test 71: A Responder adds FINISH to the transcript of a session with mutual authentication that
 * uses the Requester's public key (slot 0xFF), but no public key has been provisioned for the
 * Requester.
 * Expected Behavior: libspdm_append_message_f returns LIBSPDM_STATUS_INVALID_STATE_PEER. Skipped
 * if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled, as the transcript then does not contain
 * the public key.
 **/
static void libspdm_test_append_message_f_mut_auth_no_peer_public_key_case71(void **state)
{
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t local_public_key[] = { 0x60, 0x61, 0x62, 0x63 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_FINISH, 0, 0 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x47;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_public_key_provision = local_public_key;
    spdm_context->local_context.local_public_key_provision_size = sizeof(local_public_key);
    session_info = libspdm_test_start_session(spdm_context, false);
    session_info->local_used_cert_chain_slot_id = 0xFF;
    session_info->peer_used_cert_chain_slot_id = 0xFF;
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    assert_int_equal(libspdm_append_message_f(spdm_context, session_info, false, message,
                                              sizeof(message)),
                     LIBSPDM_STATUS_INVALID_STATE_PEER);
#else
    skip();
#endif
}

/**
 * Test 72: Two encapsulated DIGESTS responses are added to a session transcript.
 * Expected Behavior: only the first DIGESTS is part of the transcript, so the second call succeeds
 * without adding to it.
 **/
static void libspdm_test_append_message_encap_d_second_case72(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t first_digests[] = { 0x70, 0x71 };
    uint8_t second_digests[] = { 0x72, 0x73, 0x74 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x48;

    session_info = libspdm_test_start_session(spdm_context, false);
    assert_int_equal(libspdm_append_message_encap_d(session_info, first_digests,
                                                    sizeof(first_digests)),
                     LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(libspdm_append_message_encap_d(session_info, second_digests,
                                                    sizeof(second_digests)),
                     LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(libspdm_get_managed_buffer_size(
                         &session_info->session_transcript.message_encap_d),
                     sizeof(first_digests));
    assert_memory_equal(libspdm_get_managed_buffer(
                            &session_info->session_transcript.message_encap_d),
                        first_digests, sizeof(first_digests));
}

/**
 * Test 73: libspdm_negotiate_connection_version is given a version list that is longer than
 * LIBSPDM_MAX_VERSION_COUNT, or an empty version list.
 * Expected Behavior: no common version is negotiated and it returns false.
 **/
static void libspdm_test_negotiate_connection_version_invalid_case73(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_version_number_t common_version;
    spdm_version_number_t req_versions[LIBSPDM_MAX_VERSION_COUNT + 1];
    spdm_version_number_t rsp_versions[1];
    size_t index;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x49;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(req_versions); index++) {
        req_versions[index] = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    }
    rsp_versions[0] = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    assert_false(libspdm_negotiate_connection_version(&common_version, req_versions,
                                                      LIBSPDM_ARRAY_SIZE(req_versions),
                                                      rsp_versions,
                                                      LIBSPDM_ARRAY_SIZE(rsp_versions)));
    assert_false(libspdm_negotiate_connection_version(&common_version, req_versions, 1,
                                                      NULL, 0));
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
#if LIBSPDM_CHECK_SPDM_CONTEXT
        cmocka_unit_test(libspdm_test_check_context_case20),
#endif /* LIBSPDM_CHECK_SPDM_CONTEXT */

        /* Test the max DHE/PSK session count */
        cmocka_unit_test(libspdm_test_max_session_count_case21),

        /* Successful response V1.2 for multi element */
        cmocka_unit_test(libspdm_test_process_opaque_data_case22),

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
        /* reset_context empties the peer certificate chain slots */
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

        /* reset_context restores the SPDM 1.0 and 1.1 signature endianness setting */
        cmocka_unit_test(libspdm_test_reset_context_verify_signature_endian_case31),

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
        /* reset_context ends a chunk transfer in either direction */
        cmocka_unit_test(libspdm_test_reset_context_chunk_case32),
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) && LIBSPDM_CERT_PARSE_SUPPORT
        /* The peer leaf key is parsed with the peer's asymmetric algorithm. */
        cmocka_unit_test(libspdm_test_set_data_peer_cert_chain_responder_case33),
        cmocka_unit_test(libspdm_test_set_data_peer_cert_chain_requester_case34),
#endif
        /* set_data and get_data agree on every item that supports both */
        cmocka_unit_test_setup(libspdm_test_set_get_data_round_trip_case35,
                               libspdm_unit_test_reset_context),
        /* set_data stores each local item that get_data does not return */
        cmocka_unit_test_setup(libspdm_test_set_data_local_items_case36,
                               libspdm_unit_test_reset_context),
        /* a maximum sequence number of 0 selects the default */
        cmocka_unit_test_setup(libspdm_test_set_data_default_max_sequence_number_case37,
                               libspdm_unit_test_reset_context),
        /* set_data rejects a wrong data_size */
        cmocka_unit_test_setup(libspdm_test_set_data_wrong_size_case38,
                               libspdm_unit_test_reset_context),
        /* set_data rejects an unsupported location */
        cmocka_unit_test_setup(libspdm_test_set_data_wrong_location_case39,
                               libspdm_unit_test_reset_context),
        /* set_data rejects an out-of-range slot ID */
        cmocka_unit_test_setup(libspdm_test_set_data_invalid_slot_case40,
                               libspdm_unit_test_reset_context),
        /* set_data rejects invalid arguments and values */
        cmocka_unit_test_setup(libspdm_test_set_data_invalid_value_case41,
                               libspdm_unit_test_reset_context),
        /* set_data does not set read-only items */
        cmocka_unit_test_setup(libspdm_test_set_data_read_only_case42,
                               libspdm_unit_test_reset_context),
        /* get_data rejects an unsupported location */
        cmocka_unit_test_setup(libspdm_test_get_data_wrong_location_case43,
                               libspdm_unit_test_reset_context),
        /* get_data rejects invalid arguments, slot IDs and sessions */
        cmocka_unit_test_setup(libspdm_test_get_data_invalid_parameter_case44,
                               libspdm_unit_test_reset_context),
        /* get_data does not get write-only items */
        cmocka_unit_test_setup(libspdm_test_get_data_write_only_case45,
                               libspdm_unit_test_reset_context),
        /* get_data returns the read-only items outside of a session */
        cmocka_unit_test_setup(libspdm_test_get_data_read_only_case46,
                               libspdm_unit_test_reset_context),
        /* get_data returns the session items */
        cmocka_unit_test_setup(libspdm_test_get_data_session_items_case47,
                               libspdm_unit_test_reset_context),
        /* set_data rejects a peer certificate chain that cannot be parsed */
        cmocka_unit_test_setup(libspdm_test_set_data_peer_cert_chain_invalid_case48,
                               libspdm_unit_test_reset_context),
        /* only the connection version is supported */
        cmocka_unit_test_setup(libspdm_test_is_version_supported_case49,
                               libspdm_unit_test_reset_context),
        /* extended capability flags from either endpoint's point of view */
        cmocka_unit_test_setup(libspdm_test_is_capabilities_ext_flag_supported_case50,
                               libspdm_unit_test_reset_context),
        /* SPDM 1.0 has no encapsulated requests */
        cmocka_unit_test_setup(libspdm_test_is_encap_supported_10_case51,
                               libspdm_unit_test_reset_context),
        /* SPDM 1.2 accepts MUT_AUTH_CAP in place of ENCAP_CAP */
        cmocka_unit_test_setup(libspdm_test_is_encap_supported_12_case52,
                               libspdm_unit_test_reset_context),
        /* registering the transport layer after the buffers adjusts the transfer sizes */
        cmocka_unit_test_setup(libspdm_test_register_transport_after_buffer_case53,
                               libspdm_unit_test_reset_context),
        /* the certificate chain verification function is registered */
        cmocka_unit_test_setup(libspdm_test_register_verify_spdm_cert_chain_func_case54,
                               libspdm_unit_test_reset_context),
        /* the receiver buffer is the Integrator's */
        cmocka_unit_test_setup(libspdm_test_get_receiver_buffer_case55,
                               libspdm_unit_test_reset_context),
        /* the last SPDM error is returned as set */
        cmocka_unit_test_setup(libspdm_test_last_spdm_error_struct_case56,
                               libspdm_unit_test_reset_context),
        /* a FIPS self-test context is imported and exported */
        cmocka_unit_test_setup(libspdm_test_fips_selftest_context_case57,
                               libspdm_unit_test_reset_context),
        /* a FIPS self-test context with a NULL pointer or wrong size is rejected */
        cmocka_unit_test_setup(libspdm_test_fips_selftest_context_invalid_case58,
                               libspdm_unit_test_reset_context),
        /* check_context rejects a small sender data transfer size */
        cmocka_unit_test_setup(libspdm_test_check_context_sender_size_case59,
                               libspdm_unit_test_reset_context),
        /* check_context rejects a max message size below the sender data transfer size */
        cmocka_unit_test_setup(libspdm_test_check_context_sender_max_msg_size_case60,
                               libspdm_unit_test_reset_context),
        /* check_context rejects a certificate chain that exceeds the max message size */
        cmocka_unit_test_setup(libspdm_test_check_context_cert_chain_size_case61,
                               libspdm_unit_test_reset_context),
        /* init_context_with_secured_context rejects a NULL secured context */
        cmocka_unit_test_setup(libspdm_test_init_context_null_secured_context_case62,
                               libspdm_unit_test_reset_context),
        /* reset_message_c frees the M1/M2 hash */
        cmocka_unit_test_setup(libspdm_test_reset_message_c_case63,
                               libspdm_unit_test_reset_context),
        /* a session's L1/L2 includes the VCA as of SPDM 1.2 */
        cmocka_unit_test_setup(libspdm_test_append_message_m_session_case64,
                               libspdm_unit_test_reset_context),
        /* TH includes the DIGESTS when the Responder negotiated multiple keys */
        cmocka_unit_test_setup(libspdm_test_append_message_k_multi_key_case65,
                               libspdm_unit_test_reset_context),
        /* TH includes the encapsulated DIGESTS when the Requester negotiated multiple keys */
        cmocka_unit_test_setup(libspdm_test_append_message_f_multi_key_case66,
                               libspdm_unit_test_reset_context),
        /* message K needs the Responder's public key for slot 0xFF */
        cmocka_unit_test_setup(libspdm_test_append_message_k_no_peer_public_key_case67,
                               libspdm_unit_test_reset_context),
        /* message K needs the local public key for slot 0xFF */
        cmocka_unit_test_setup(libspdm_test_append_message_k_no_local_public_key_case68,
                               libspdm_unit_test_reset_context),
        /* message F returns the error of message K */
        cmocka_unit_test_setup(libspdm_test_append_message_f_no_peer_public_key_case69,
                               libspdm_unit_test_reset_context),
        /* message F needs the Requester's own public key for slot 0xFF */
        cmocka_unit_test_setup(libspdm_test_append_message_f_no_local_public_key_case70,
                               libspdm_unit_test_reset_context),
        /* message F needs the Requester's public key for slot 0xFF on the Responder */
        cmocka_unit_test_setup(libspdm_test_append_message_f_mut_auth_no_peer_public_key_case71,
                               libspdm_unit_test_reset_context),
        /* only the first encapsulated DIGESTS is in the transcript */
        cmocka_unit_test_setup(libspdm_test_append_message_encap_d_second_case72,
                               libspdm_unit_test_reset_context),
        /* version negotiation rejects invalid version lists */
        cmocka_unit_test_setup(libspdm_test_negotiate_connection_version_invalid_case73,
                               libspdm_unit_test_reset_context),
    };

    libspdm_setup_test_context(&m_libspdm_common_context_data_test_context);

    return cmocka_run_group_tests(spdm_common_context_data_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
