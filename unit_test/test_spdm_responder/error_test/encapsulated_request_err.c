/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

/* Every test here delivers an encapsulated response that libspdm must reject, or that it must
 * not act on because the flow or session it belongs to has ended, so the Integrator's handler is
 * never consulted. */
static libspdm_return_t encap_flow_handler(
    void *spdm_context, const uint32_t *session_id, libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code, uint8_t error_code, bool *terminate_flow, size_t *request_size,
    void *request)
{
    assert_true(false);

    return LIBSPDM_STATUS_SUCCESS;
}

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.request_id = 0;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->last_spdm_request_session_id_valid = false;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);
}

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/* The Integrator's buffer for the Requester's certificate chain. */
static uint8_t m_cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];

/* Deliver one CERTIFICATE under the given Request ID, in the regular or the large certificate
 * chain form, carrying portion_length bytes of chain and announcing remainder_length more, and
 * return the Responder's response to it. */
static libspdm_return_t deliver_certificate(
    libspdm_context_t *spdm_context, uint8_t spdm_version, uint8_t request_id, bool large_form,
    const uint8_t *chain, uint32_t portion_length, uint32_t remainder_length,
    size_t *response_size, void *response)
{
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_deliver_encapsulated_response_request_t *deliver;
    size_t header_size;
    size_t deliver_size;

    deliver = (void *)temp_buf;
    deliver->header.spdm_version = spdm_version;
    deliver->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    deliver->header.param1 = request_id;
    deliver->header.param2 = 0;

    if (large_form) {
        spdm_certificate_large_response_t *certificate = (void *)(deliver + 1);

        certificate->header.spdm_version = spdm_version;
        certificate->header.request_response_code = SPDM_CERTIFICATE;
        certificate->header.param1 = SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN;
        certificate->header.param2 = 0;
        certificate->portion_length = 0;
        certificate->remainder_length = 0;
        certificate->large_portion_length = portion_length;
        certificate->large_remainder_length = remainder_length;
        header_size = sizeof(spdm_certificate_large_response_t);
    } else {
        spdm_certificate_response_t *certificate = (void *)(deliver + 1);

        certificate->header.spdm_version = spdm_version;
        certificate->header.request_response_code = SPDM_CERTIFICATE;
        certificate->header.param1 = 0;
        certificate->header.param2 = 0;
        certificate->portion_length = (uint16_t)portion_length;
        certificate->remainder_length = (uint16_t)remainder_length;
        header_size = sizeof(spdm_certificate_response_t);
    }

    deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) + header_size;
    libspdm_copy_mem(temp_buf + deliver_size, sizeof(temp_buf) - deliver_size,
                     chain, portion_length);
    deliver_size += portion_length;

    return libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size, deliver,
                                                          response_size, response);
}

/**
 * Test 1: the Requester's certificate chain arrives in portions, and the second portion announces
 * a remainder that is inconsistent with the total length that the first portion announced.
 * Expected behavior: the first portion is accepted and the next GET_CERTIFICATE is issued; the
 * second portion is rejected with ERROR(InvalidResponseCode) and the flow ends.
 **/
static void rsp_encapsulated_request_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *error_response;
    const spdm_message_header_t *ack;
    const spdm_get_certificate_request_t *get_certificate;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;
    uint32_t portion_length;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* GET_CERTIFICATE for slot 0 is outstanding under Request ID 0 in a Requester-initiated flow,
     * in the regular form, and none of the chain has been received yet. */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_CERTIFICATE;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.use_large_cert_chain = false;
    spdm_context->encap_context.payload_buffer = m_cert_chain_buffer;
    spdm_context->encap_context.payload_buffer_size = 0;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_cert_chain_buffer);
    libspdm_reset_message_mut_b(spdm_context);

    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        assert_true(false);
    }
    assert_true(data_size > LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    /* The first portion announces the total length of the chain. */
    response_size = sizeof(response);
    status = deliver_certificate(spdm_context, SPDM_MESSAGE_VERSION_11, 0, false, data,
                                 portion_length, (uint32_t)data_size - portion_length,
                                 &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    ack = (const void *)response;
    assert_int_equal(ack->request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(ack->param1, 1);
    assert_int_equal(ack->param2, SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT);
    get_certificate = (const void *)(ack + 1);
    assert_int_equal(get_certificate->header.request_response_code, SPDM_GET_CERTIFICATE);
    assert_int_equal(get_certificate->offset, portion_length);

    /* The second portion claims that one byte more remains than the total allows. */
    response_size = sizeof(response);
    status = deliver_certificate(spdm_context, SPDM_MESSAGE_VERSION_11, 1, false,
                                 (const uint8_t *)data + portion_length,
                                 (uint32_t)data_size - portion_length, 1,
                                 &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    error_response = (const void *)response;
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(error_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    free(data);
}

/**
 * Test 2: over SPDM 1.4 the Responder requested the large certificate chain form, but the Requester
 * returns a CERTIFICATE without the LargeCertChain bit set.
 * Expected behavior: ERROR(InvalidResponseCode), and the flow ends.
 **/
static void rsp_encapsulated_request_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *error_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint8_t chain[LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* The Requester supports large responses, so the GET_CERTIFICATE for slot 0 that is
     * outstanding under Request ID 0 is in the large certificate chain form. */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_CERTIFICATE;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.use_large_cert_chain = true;
    spdm_context->encap_context.payload_buffer = m_cert_chain_buffer;
    spdm_context->encap_context.payload_buffer_size = 0;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_cert_chain_buffer);
    libspdm_reset_message_mut_b(spdm_context);

    libspdm_set_mem(chain, sizeof(chain), (uint8_t)0x5A);

    response_size = sizeof(response);
    status = deliver_certificate(spdm_context, SPDM_MESSAGE_VERSION_14, 0, false, chain,
                                 sizeof(chain), sizeof(chain), &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    error_response = (const void *)response;
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(error_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

/**
 * Test 3: over SPDM 1.4 the Responder requested the regular form, as the Requester does not
 * support large responses, but the Requester returns a CERTIFICATE with the LargeCertChain bit set.
 * Expected behavior: ERROR(InvalidResponseCode), and the flow ends.
 **/
static void rsp_encapsulated_request_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *error_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint8_t chain[LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* The Requester does not support large responses, so the GET_CERTIFICATE for slot 0 that is
     * outstanding under Request ID 0 is in the regular form despite the SPDM version. */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_CERTIFICATE;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.use_large_cert_chain = false;
    spdm_context->encap_context.payload_buffer = m_cert_chain_buffer;
    spdm_context->encap_context.payload_buffer_size = 0;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_cert_chain_buffer);
    libspdm_reset_message_mut_b(spdm_context);

    libspdm_set_mem(chain, sizeof(chain), (uint8_t)0x5A);

    response_size = sizeof(response);
    status = deliver_certificate(spdm_context, SPDM_MESSAGE_VERSION_14, 0, true, chain,
                                 sizeof(chain), sizeof(chain), &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    error_response = (const void *)response;
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(error_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

/**
 * Test 4: the Requester returns a CERTIFICATE that carries none of the chain while announcing that
 * some of it remains.
 * Expected behavior: ERROR(InvalidResponseCode), and the flow ends.
 **/
static void rsp_encapsulated_request_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *error_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint8_t chain[LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);

    /* GET_CERTIFICATE for slot 0 is outstanding under Request ID 0 in a Requester-initiated flow,
     * in the regular form, and none of the chain has been received yet. */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_CERTIFICATE;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.use_large_cert_chain = false;
    spdm_context->encap_context.payload_buffer = m_cert_chain_buffer;
    spdm_context->encap_context.payload_buffer_size = 0;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_cert_chain_buffer);
    libspdm_reset_message_mut_b(spdm_context);

    libspdm_set_mem(chain, sizeof(chain), (uint8_t)0x5A);

    response_size = sizeof(response);
    status = deliver_certificate(spdm_context, SPDM_MESSAGE_VERSION_11, 0, false, chain,
                                 0, sizeof(chain), &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    error_response = (const void *)response;
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(error_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

/**
 * Test 5: the buffer that the Integrator supplied for the Requester's certificate chain is too
 * small for the portion that arrives.
 * Expected behavior: the shortfall is the Responder's own, so ERROR(Unspecified) rather than an
 * ErrorCode that blames the Requester's response, and the flow ends.
 **/
static void rsp_encapsulated_request_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *error_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint8_t chain[LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    /* GET_CERTIFICATE for slot 0 is outstanding under Request ID 0 in a Requester-initiated flow,
     * in the regular form, and the Integrator's buffer holds less than one portion. */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_CERTIFICATE;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.use_large_cert_chain = false;
    spdm_context->encap_context.payload_buffer = m_cert_chain_buffer;
    spdm_context->encap_context.payload_buffer_size = 0;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(chain) / 2;
    libspdm_reset_message_mut_b(spdm_context);

    libspdm_set_mem(chain, sizeof(chain), (uint8_t)0x5A);

    response_size = sizeof(response);
    status = deliver_certificate(spdm_context, SPDM_MESSAGE_VERSION_11, 0, false, chain,
                                 sizeof(chain), sizeof(chain), &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    error_response = (const void *)response;
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(error_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

static spdm_deliver_encapsulated_response_request_t m_deliver_encapsulated_response_11 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_DELIVER_ENCAPSULATED_RESPONSE, 0, 0}
};
static size_t m_deliver_encapsulated_response_11_size = sizeof(m_deliver_encapsulated_response_11);

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
static spdm_deliver_encapsulated_response_request_t m_deliver_encapsulated_response_12 = {
    {SPDM_MESSAGE_VERSION_12, SPDM_DELIVER_ENCAPSULATED_RESPONSE, 0xFF, 0}
};
static size_t m_deliver_encapsulated_response_12_size = sizeof(m_deliver_encapsulated_response_12);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
/* The buffer that libspdm writes the Requester's endpoint information into. */
static uint8_t m_endpoint_info[0x20];
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */

/* Deliver an encapsulated ERROR for an outstanding request of the given code, so that the
 * response-processing dispatch arm for that code is exercised. */
static void deliver_encap_error(libspdm_context_t *spdm_context, uint8_t last_request_code,
                                uint8_t error_code, size_t encap_size,
                                uint8_t *response, size_t *response_size)
{
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_t *encap_error;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_return_t status;

    /* This flow occurs outside of a session, and an earlier test in this group leaves a session
     * behind. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.last_encap_request_header.request_response_code = last_request_code;
    spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_request = (void *)temp_buf;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    spdm_request->header.param1 = 0xFF;
    spdm_request->header.param2 = 0;
    encap_error = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_error->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    encap_error->header.request_response_code = SPDM_ERROR;
    encap_error->header.param1 = error_code;
    encap_error->header.param2 = 0;

    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context, sizeof(spdm_deliver_encapsulated_response_request_t) + encap_size,
        spdm_request, response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 6: in the optimized encapsulated flow, where KEY_EXCHANGE_RSP set MutAuthRequested bit 2
 * and embedded GET_DIGESTS, the Responder never sent an ENCAPSULATED_REQUEST and so never provided
 * a Request ID, but the Requester's DELIVER_ENCAPSULATED_RESPONSE carries a Request ID of 1.
 * Expected behavior: only a Request ID of 0 is legal, so the Responder returns
 * ERROR(InvalidRequest) without processing the DIGESTS.
 **/
static void rsp_encapsulated_request_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    spdm_deliver_encapsulated_response_request_t *deliver;
    spdm_digest_response_t *digests;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t deliver_size;
    size_t response_size;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);
    /* This is the state init_encap_state leaves behind for bit 2. */
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;

    deliver = (void *)temp_buf;
    libspdm_copy_mem(deliver, sizeof(temp_buf),
                     &m_deliver_encapsulated_response_11,
                     m_deliver_encapsulated_response_11_size);
    /* A Request ID the Responder never handed out. */
    deliver->header.param1 = 1;

    digests = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    digests->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    digests->header.request_response_code = SPDM_DIGESTS;
    digests->header.param1 = 0;
    digests->header.param2 = (0x01 << 0);
    libspdm_set_mem(digests + 1, libspdm_get_hash_size(m_libspdm_use_hash_algo), (uint8_t)0xA5);

    deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                   sizeof(spdm_digest_response_t) +
                   libspdm_get_hash_size(m_libspdm_use_hash_algo);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size,
                                                            temp_buf, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    /* The flow is still waiting for the DIGESTS. */
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);

    spdm_context->last_spdm_request_session_id_valid = false;
}
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 7: the encapsulated response is neither the expected
 * response nor an ERROR, so there is no ErrorCode to report to the Integrator.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode) and tears the flow down.
 **/
static void rsp_encapsulated_request_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_message_header_t *encap_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    /* This flow occurs outside of a session, and an earlier test in this group leaves a session
     * behind. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_deliver_encapsulated_response_12,
                     m_deliver_encapsulated_response_12_size);
    /* A CERTIFICATE response where DIGESTS was requested. */
    encap_response = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_response->spdm_version = SPDM_MESSAGE_VERSION_12;
    encap_response->request_response_code = SPDM_CERTIFICATE;
    encap_response->param1 = 0;
    encap_response->param2 = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + sizeof(spdm_message_header_t),
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) && (LIBSPDM_RESPOND_IF_READY_SUPPORT)
/**
 * Test 8: the Requester returns ResponseNotReady but the ERROR
 * carries no extended data, so the fields needed to reissue the request are absent.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode) and tears the flow down.
 **/
static void rsp_encapsulated_request_err_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, SPDM_GET_DIGESTS,
                        SPDM_ERROR_CODE_RESPONSE_NOT_READY, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_false(spdm_context->encap_context.response_not_ready);
}
#endif /* (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) && (LIBSPDM_RESPOND_IF_READY_SUPPORT) */

#if (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) && (LIBSPDM_RESPOND_IF_READY_SUPPORT)
/**
 * Test 9: the Requester returns ERROR(ResponseNotReady) whose
 * extended data does not describe the request that was deferred, or names a retry interval that
 * DSP0274 does not permit.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode) and tears the flow down, rather
 * than reissuing RESPOND_IF_READY built from fields it cannot use.
 **/
static void rsp_encapsulated_request_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_data_response_not_ready_t *encap_error;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    size_t index;

    /* RequestCode does not match the outstanding GET_DIGESTS, RDTM is not greater than 1, and
     * RDTExponent is beyond what the Responder will wait. */
    const uint8_t bad_request_code[] = { SPDM_GET_CERTIFICATE, SPDM_GET_DIGESTS, SPDM_GET_DIGESTS };
    const uint8_t bad_rd_tm[] = { 2, 1, 2 };
    const uint8_t bad_rd_exponent[] = { 1, 1, LIBSPDM_MAX_RDT_EXPONENT + 1 };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(bad_request_code); index++) {
        spdm_context->last_spdm_request_session_id_valid = false;
        spdm_context->latest_session_id = INVALID_SESSION_ID;
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.request_id = 0xFF;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
        spdm_context->encap_context.last_encap_request_header.request_response_code =
            SPDM_GET_DIGESTS;
        spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
        spdm_context->encap_context.response_not_ready = false;
        spdm_context->connection_info.capability.flags |=
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
        spdm_context->local_context.capability.flags |=
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                                SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

        spdm_request = (void *)temp_buf;
        libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                         &m_deliver_encapsulated_response_12,
                         m_deliver_encapsulated_response_12_size);

        encap_error = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
        encap_error->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        encap_error->header.request_response_code = SPDM_ERROR;
        encap_error->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        encap_error->header.param2 = 0;
        encap_error->extend_error_data.request_code = bad_request_code[index];
        encap_error->extend_error_data.rd_tm = bad_rd_tm[index];
        encap_error->extend_error_data.rd_exponent = bad_rd_exponent[index];
        encap_error->extend_error_data.token = 0x5A;

        response_size = sizeof(response);
        status = libspdm_get_response_encapsulated_response_ack(
            spdm_context,
            sizeof(spdm_deliver_encapsulated_response_request_t) +
            sizeof(spdm_error_response_data_response_not_ready_t),
            spdm_request, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        assert_int_equal(response_size, sizeof(spdm_error_response_t));
        spdm_response = (void *)response;
        assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
        assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
        assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
        /* Nothing was retained, so no RESPOND_IF_READY can be built from it. */
        assert_false(spdm_context->encap_context.response_not_ready);
    }
}
#endif /* (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) && (LIBSPDM_RESPOND_IF_READY_SUPPORT) */

/**
 * Test 10: the KEY_UPDATE_ACK for the UpdateKey operation is
 * delivered, but the follow-up VerifyNewKey cannot be built because the Requester no longer
 * supports KEY_UPD_CAP.
 * Expected behavior: Responder returns ERROR(Unspecified) and tears the flow down rather than
 * leaving it half-open.
 **/
static void rsp_encapsulated_request_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_key_update_response_t *key_update_ack;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;
    session_info->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    session_info->encap_context.last_encap_request_header.param2 = 0x5A;

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_deliver_encapsulated_response_11,
                     m_deliver_encapsulated_response_11_size);

    key_update_ack = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    key_update_ack->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    key_update_ack->header.request_response_code = SPDM_KEY_UPDATE_ACK;
    key_update_ack->header.param1 = SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    key_update_ack->header.param2 = 0x5A;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + sizeof(spdm_key_update_response_t),
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->last_spdm_request_session_id_valid = false;
}
/**
 * Test 11: the Requester answers an encapsulated KEY_UPDATE with
 * ERROR(DecryptError), which ends the session that the encapsulated flow belongs to.
 * Expected behavior: Responder returns ERROR(Unspecified). The Integrator's handler is not
 * consulted, as neither the flow nor the session it names still exists.
 **/
static void rsp_encapsulated_request_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_t *encap_error;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;
    session_info->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    session_info->encap_context.last_encap_request_header.param2 = 0x5A;

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_deliver_encapsulated_response_11,
                     m_deliver_encapsulated_response_11_size);

    encap_error = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_error->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    encap_error->header.request_response_code = SPDM_ERROR;
    encap_error->header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
    encap_error->header.param2 = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + sizeof(spdm_error_response_t),
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);

    /* DecryptError ends the session, so the flow it belonged to is gone with it. */
    assert_int_equal(session_info->session_id, INVALID_SESSION_ID);
    assert_int_equal(spdm_context->latest_session_id, INVALID_SESSION_ID);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    spdm_context->last_spdm_request_session_id_valid = false;
}
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
/**
 * Test 12: the Requester returns a valid ENDPOINT_INFO response that
 * is larger than the buffer the Integrator supplied.
 * Expected behavior: Responder returns ERROR(Unspecified) rather than ERROR(InvalidResponseCode),
 * as the Requester's response was not at fault, and tears the flow down.
 **/
static void rsp_encapsulated_request_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_endpoint_info_response_t *encap_response;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t *ptr;
    size_t response_size;
    uint32_t ep_info_data_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_ENDPOINT_INFO;
    spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.req_attributes = 0;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    /* One byte short of what the Requester returns. */
    ep_info_data_len = sizeof(m_endpoint_info);
    spdm_context->encap_context.payload_buffer = m_endpoint_info;
    spdm_context->encap_context.payload_buffer_max_size = ep_info_data_len - 1;
    spdm_context->encap_context.payload_buffer_size = 0;

    spdm_request = (void *)temp_buf;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    spdm_request->header.param1 = 0xFF;
    spdm_request->header.param2 = 0;

    encap_response = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    encap_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    encap_response->header.param1 = 0;
    encap_response->header.param2 = 0;
    encap_response->reserved = 0;

    ptr = (void *)(encap_response + 1);
    libspdm_write_uint32(ptr, ep_info_data_len);
    ptr += sizeof(uint32_t);
    libspdm_set_mem(ptr, ep_info_data_len, 0x5A);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) +
        sizeof(spdm_endpoint_info_response_t) + sizeof(uint32_t) + ep_info_data_len,
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    /* Not InvalidResponseCode, which would blame the Requester for the Responder's buffer. */
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

}
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */

/**
 * Test 13: the Requester delivers an encapsulated ERROR whose
 * ErrorCode is the reserved value 0x00.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode) and tears the flow down. The
 * Integrator's handler is not consulted, as an ErrorCode of 0x00 cannot be reported to it.
 **/
static void rsp_encapsulated_request_err_case13(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, SPDM_KEY_UPDATE, 0x00, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
/**
 * Test 14: the Requester declines the encapsulated CHALLENGE of the
 * basic mutual authentication flow with an ERROR whose ErrorCode is the reserved value 0x00.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode). The flow must not be reported
 * as having completed normally, which is what an ErrorCode of 0x00 would otherwise indicate.
 **/
static void rsp_encapsulated_request_err_case14(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, SPDM_CHALLENGE, 0x00, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    /* Not ENCAPSULATED_RESPONSE_ACK, which would report the flow as having ended normally. */
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */


int libspdm_rsp_encapsulated_request_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* A later portion contradicts the total length that the first portion announced */
        cmocka_unit_test(rsp_encapsulated_request_err_case1),
        /* The large certificate chain form was requested but not returned */
        cmocka_unit_test(rsp_encapsulated_request_err_case2),
        /* The large certificate chain form was returned but not requested */
        cmocka_unit_test(rsp_encapsulated_request_err_case3),
        /* An empty portion */
        cmocka_unit_test(rsp_encapsulated_request_err_case4),
        /* The Integrator's buffer is too small for the chain */
        cmocka_unit_test(rsp_encapsulated_request_err_case5),
        /* Optimized flow: the Responder never provided a Request ID, so Param1 must be 0 */
        cmocka_unit_test(rsp_encapsulated_request_err_case6),
        /* An encapsulated response that is neither expected nor an ERROR */
        cmocka_unit_test(rsp_encapsulated_request_err_case7),
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* ResponseNotReady without the extended data needed to reissue the request */
        cmocka_unit_test(rsp_encapsulated_request_err_case8),
        /* ResponseNotReady extended data that the Responder cannot use */
        cmocka_unit_test(rsp_encapsulated_request_err_case9),
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
        /* The follow-up request of a multi-message operation cannot be built */
        cmocka_unit_test(rsp_encapsulated_request_err_case10),
        /* An encapsulated ERROR(DecryptError) ends the session the flow belongs to */
        cmocka_unit_test(rsp_encapsulated_request_err_case11),
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
        /* A payload larger than the Integrator's buffer is not the Requester's fault */
        cmocka_unit_test(rsp_encapsulated_request_err_case12),
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
        /* An encapsulated ERROR whose ErrorCode is the reserved 0x00 */
        cmocka_unit_test(rsp_encapsulated_request_err_case13),
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
        /* The same, declining the CHALLENGE of the basic mutual authentication flow */
        cmocka_unit_test(rsp_encapsulated_request_err_case14),
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
