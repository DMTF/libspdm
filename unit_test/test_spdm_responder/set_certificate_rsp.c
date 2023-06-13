/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP

extern bool g_in_trusted_environment;

/**
 * Test 1: receives a valid SET_CERTIFICATE request message from Requester to set cert in slot_id:0 with device_cert model
 * Expected Behavior: produces a valid SET_CERTIFICATE_RSP response message
 **/
void libspdm_test_responder_set_cetificate_rsp_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_certificate_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_CERTIFICATE_RSP);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}

/**
 * Test 2: Wrong SET_CERTIFICATE message size (larger than expected)
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_set_cetificate_rsp_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;
    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    /* Bad request size: only have header size*/
    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t);

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}


/**
 * Test 3: Force response_state = LIBSPDM_RESPONSE_STATE_BUSY when asked SET_CERTIFICATE
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_BUSY
 **/
void libspdm_test_responder_set_cetificate_rsp_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;
    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    /* Bad request size: right request size + 1*/
    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size + 1;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}


/**
 * Test 4: Force response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC when asked SET_CERTIFICATE
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_REQUEST_RESYNCH
 **/
void libspdm_test_responder_set_cetificate_rsp_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NEED_RESYNC);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}

/**
 * Test 5: receives a valid SET_CERTIFICATE request message from Requester to set cert in slot_id:1 with session
 * Expected Behavior: produces a valid SET_CERTIFICATE_RSP response message
 **/
void libspdm_test_responder_set_cetificate_rsp_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /*responset_state need to set normal*/
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 1;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_certificate_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_CERTIFICATE_RSP);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}

/**
 * Test 6: receives a valid SET_CERTIFICATE request message from Requester with need_reset
 * Expected Behavior: The Responder return need reset
 **/
void libspdm_test_responder_set_cetificate_rsp_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}

/**
 * Test 7: receives a valid SET_CERTIFICATE request message from Requester to set cert in slot_id:0 with alias_cert model
 * Expected Behavior: produces a valid SET_CERTIFICATE_RSP response message
 **/
void libspdm_test_responder_set_cetificate_rsp_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->local_context.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set alias cert mode*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    /*read alias cert*/
    libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &cert_chain, &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_certificate_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_CERTIFICATE_RSP);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}

/**
 * Test 8: receives a SET_CERTIFICATE request message to set cert in slot_id:1 without session and with trusted environment
 * Expected Behavior: produces a valid SET_CERTIFICATE_RSP response message
 **/
void libspdm_test_responder_set_cetificate_rsp_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /*responset_state need to set normal*/
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->last_spdm_request_session_id_valid = false;
    g_in_trusted_environment = true;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 1;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_certificate_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_CERTIFICATE_RSP);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}

/**
 * Test 9: receives a SET_CERTIFICATE request message to set cert in slot_id:1 without session and without trusted environment
 * Expected Behavior: produces a valid ERROR response message
 **/
void libspdm_test_responder_set_cetificate_rsp_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_certificate_response_t *spdm_response;
    void *cert_chain;
    size_t cert_chain_size;
    spdm_set_certificate_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /*responset_state need to set normal*/
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->last_spdm_request_session_id_valid = false;
    g_in_trusted_environment = false;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &cert_chain,
                                                    &cert_chain_size, NULL, NULL);

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_set_certificate_request_t) +
                                               cert_chain_size);

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    m_libspdm_set_certificate_request->header.param1 = 1;
    m_libspdm_set_certificate_request->header.param2 = 0;

    libspdm_copy_mem(m_libspdm_set_certificate_request + 1,
                     LIBSPDM_MAX_CERT_CHAIN_SIZE,
                     (uint8_t *)cert_chain, cert_chain_size);

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_set_certificate_request_t) +
                                                    cert_chain_size;

    response_size = sizeof(response);
    status = libspdm_get_response_set_certificate(spdm_context,
                                                  m_libspdm_set_certificate_request_size,
                                                  m_libspdm_set_certificate_request,
                                                  &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(cert_chain);
    free(m_libspdm_set_certificate_request);
}
libspdm_test_context_t m_libspdm_responder_set_certificate_rsp_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_set_certificate_rsp_test_main(void)
{
    const struct CMUnitTest spdm_responder_set_cetificate_tests[] = {
        /* Success Case for set_certificate to slot_id:0 with device_cert mode*/
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case2),
        /* response_state: LIBSPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case4),
        /* Success Case for set_certificate to slot_id:1 with session*/
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case5),
        /* Responder requires a reset to complete the SET_CERTIFICATE request */
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case6),
        /* Success Case for set_certificate to slot_id:0 with alias_cert mode*/
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case7),
        /* Success Case for set_certificate to slot_id:1 without session and with trusted environment */
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case8),
        /* Error Case for set_certificate to slot_id:1 without session and without trusted environment */
        cmocka_unit_test(libspdm_test_responder_set_cetificate_rsp_case9),
    };

    libspdm_setup_test_context(&m_libspdm_responder_set_certificate_rsp_test_context);

    return cmocka_run_group_tests(spdm_responder_set_cetificate_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP*/
