/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

static const uint32_t opaque_data = 0xDEADBEEF;

/**
 * Test 1: Basic test - tests happy path of setting and getting opaque data from
 * context successfully.
 **/
static void test_spdm_common_context_data_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data = (void *)&opaque_data;
    void *return_data = NULL;
    uintn data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(data));
    assert_int_equal(status, RETURN_SUCCESS);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, RETURN_SUCCESS);

    assert_memory_equal(data, return_data, sizeof(data));
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(opaque_data, 0xDEADBEEF);
}

/**
 * Test 2: Test failure paths of setting opaque data in context. libspdm_set_data
 * should fail when an invalid size is passed.
 **/
static void test_spdm_common_context_data_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data = (void *)&opaque_data;
    void *return_data = NULL;
    void *current_return_data = NULL;
    uintn data_return_size = 0;

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
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(data_return_size, sizeof(void*));

    /* Ensure nothing has changed between subsequent calls to get data */
    assert_ptr_equal(current_return_data, &opaque_data);

    /*
     * Set data with invalid size, it should fail. Read back to ensure that
     * no data was set.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, 500);
    assert_int_equal(status, RETURN_INVALID_PARAMETER);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_ptr_equal(return_data, current_return_data);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(opaque_data, 0xDEADBEEF);
}

/**
 * Test 3: Test failure paths of setting opaque data in context. libspdm_set_data
 * should fail when data contains NULL value.
 **/
static void test_spdm_common_context_data_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data = NULL;
    void *return_data = NULL;
    void *current_return_data = NULL;
    uintn data_return_size = 0;

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
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(data_return_size, sizeof(void*));

    /* Ensure nothing has changed between subsequent calls to get data */
    assert_ptr_equal(current_return_data, &opaque_data);


    /*
     * Set data with NULL data, it should fail. Read back to ensure that
     * no data was set.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(void *));
    assert_int_equal(status, RETURN_INVALID_PARAMETER);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_ptr_equal(return_data, current_return_data);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(opaque_data, 0xDEADBEEF);

}

/**
 * Test 4: Test failure paths of getting opaque data in context. libspdm_get_data
 * should fail when the size of buffer to get is too small.
 **/
static void test_spdm_common_context_data_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data = (void *)&opaque_data;
    void *return_data = NULL;
    uintn data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    /*
     * Set data successfully.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(void *));
    assert_int_equal(status, RETURN_SUCCESS);

    /*
     * Fail get data due to insufficient buffer for return value. returned
     * data size must return required buffer size.
     */
    data_return_size = sizeof(void*) - 1;
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, RETURN_BUFFER_TOO_SMALL);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(opaque_data, 0xDEADBEEF);
}

/**
 * Test 5: There is no root cert.
 * Expected Behavior: Return TRUE result.
 **/
void test_spdm_verify_peer_cert_chain_buffer_case5(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    void *trust_anchor;
    uintn trust_anchor_size;
    boolean result;
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
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                  data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                  &root_cert, &root_cert_size);

    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, TRUE);

    free(data);
}

/**
 * Test 6: There is one root cert. And the root cert has two case: match root cert, mismatch root cert.
 *
 * case                                              Expected Behavior
 * there is one match root cert;                     return FALSE
 * there is one mismatch root cert;                  return TRUE, and the return trust_anchor is root cert.
 **/
void test_spdm_verify_peer_cert_chain_buffer_case6(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    void *data_test;
    uintn data_size_test;
    void *hash_test;
    uintn hash_size_test;
    uint8_t *root_cert_test;
    uintn root_cert_size_test;
    uint32_t m_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    void *trust_anchor;
    uintn trust_anchor_size;
    boolean result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                  data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                  &root_cert, &root_cert_size);
    /* Loading Other test Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo_test, &data_test,
                                            &data_size_test, &hash_test, &hash_size_test);
    x509_get_cert_from_cert_chain((uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
                                  data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
                                  &root_cert_test, &root_cert_size_test);

    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }

    /*case: match root cert case*/
    spdm_context->local_context.peer_root_cert_provision_size[0] =root_cert_size_test;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert_test;
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, FALSE);

    /*case: mismatch root cert case*/
    spdm_context->local_context.peer_root_cert_provision_size[0] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, TRUE);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}

/**
 * Test 7: There are LIBSPDM_MAX_ROOT_CERT_SUPPORT/2 root cert.
 *
 * case                                              Expected Behavior
 * there is no match root cert;                      return FALSE
 * there is one match root cert in the end;          return TRUE, and the return trust_anchor is root cert.
 * there is one match root cert in the middle;       return TRUE, and the return trust_anchor is root cert.
 **/
void test_spdm_verify_peer_cert_chain_buffer_case7(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    void *data_test;
    uintn data_size_test;
    void *hash_test;
    uintn hash_size_test;
    uint8_t *root_cert_test;
    uintn root_cert_size_test;
    uint32_t m_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    void *trust_anchor;
    uintn trust_anchor_size;
    boolean result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                  data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                  &root_cert, &root_cert_size);
    /* Loading Other test Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo_test, &data_test,
                                            &data_size_test, &hash_test, &hash_size_test);
    x509_get_cert_from_cert_chain((uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
                                  data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
                                  &root_cert_test, &root_cert_size_test);

    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

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
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, FALSE);

    /*case: there is no match root cert in the end*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2 -
                                                              1] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2 -
                                                         1] = root_cert;
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, TRUE);
    assert_ptr_equal (trust_anchor, root_cert);

    /*case: there is no match root cert in the middle*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                              4] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                         4] = root_cert;
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, TRUE);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}


/**
 * Test 8: There are full(LIBSPDM_MAX_ROOT_CERT_SUPPORT - 1) root cert.
 *
 * case                                              Expected Behavior
 * there is no match root cert;                      return FALSE
 * there is one match root cert in the end;          return TRUE, and the return trust_anchor is root cert.
 * there is one match root cert in the middle;       return TRUE, and the return trust_anchor is root cert.
 **/
void test_spdm_verify_peer_cert_chain_buffer_case8(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    void *data_test;
    uintn data_size_test;
    void *hash_test;
    uintn hash_size_test;
    uint8_t *root_cert_test;
    uintn root_cert_size_test;
    uint32_t m_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    void *trust_anchor;
    uintn trust_anchor_size;
    boolean result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                  data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                  &root_cert, &root_cert_size);
    /* Loading Other test Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo_test, &data_test,
                                            &data_size_test, &hash_test, &hash_size_test);
    x509_get_cert_from_cert_chain((uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
                                  data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
                                  &root_cert_test, &root_cert_size_test);

    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

    /*case: there is no match root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, FALSE);

    /*case: there is no match root cert in the end*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT -
                                                              1] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT -
                                                         1] = root_cert;
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, TRUE);
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
    result = spdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                &trust_anchor_size);
    assert_int_equal (result, TRUE);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}

/**
 * Test 9: test set data for root cert.
 *
 * case                                              Expected Behavior
 * there is null root cert;                          return RETURN_SUCCESS, and the root cert is set successfully.
 * there is full root cert;                          return RETURN_OUT_OF_RESOURCES.
 **/
static void test_libspdm_set_data_case9(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    /* Loading Root certificate and saving its hash*/
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                  data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                  &root_cert, &root_cert_size);

    /*case: there is null root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                              NULL, root_cert, root_cert_size);
    assert_int_equal (status, RETURN_SUCCESS);
    assert_int_equal (spdm_context->local_context.peer_root_cert_provision_size[0], root_cert_size);
    assert_ptr_equal (spdm_context->local_context.peer_root_cert_provision[0], root_cert);

    /*case: there is full root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = root_cert_size;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert;
    }
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                              NULL, root_cert, root_cert_size);
    assert_int_equal (status, RETURN_OUT_OF_RESOURCES);

    free(data);
}

static spdm_test_context_t m_spdm_common_context_data_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    NULL,
    NULL,
};

int spdm_common_context_data_test_main(void)
{
    const struct CMUnitTest spdm_common_context_data_tests[] = {
        cmocka_unit_test(test_spdm_common_context_data_case1),
        cmocka_unit_test(test_spdm_common_context_data_case2),
        cmocka_unit_test(test_spdm_common_context_data_case3),
        cmocka_unit_test(test_spdm_common_context_data_case4),

        cmocka_unit_test(test_spdm_verify_peer_cert_chain_buffer_case5),
        cmocka_unit_test(test_spdm_verify_peer_cert_chain_buffer_case6),
        cmocka_unit_test(test_spdm_verify_peer_cert_chain_buffer_case7),
        cmocka_unit_test(test_spdm_verify_peer_cert_chain_buffer_case8),

        cmocka_unit_test(test_libspdm_set_data_case9),
    };

    setup_spdm_test_context(&m_spdm_common_context_data_test_context);

    return cmocka_run_group_tests(spdm_common_context_data_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}
