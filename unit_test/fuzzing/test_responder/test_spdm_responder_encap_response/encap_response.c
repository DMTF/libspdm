/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_response_encapsulated_request_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void libspdm_test_get_response_encapsulated_request_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn data_size;
    void *data;
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = 0;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);
    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context, spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer, &response_size,
                                              response);
    free(data);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    free(spdm_context->transcript.digest_context_mut_m1m2);
    #endif
}

void libspdm_test_get_response_encapsulated_request_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.current_request_op_code = SPDM_CHALLENGE;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context, spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer, &response_size,
                                              response);
}

void libspdm_test_get_response_encapsulated_request_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.current_request_op_code = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context, spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer, &response_size,
                                              response);
}

void libspdm_test_get_response_encapsulated_request_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.current_request_op_code = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context, spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer, &response_size,
                                              response);
}

void libspdm_test_get_response_encapsulated_request_case5(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = 0;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context, spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer, &response_size,
                                              response);
}

void libspdm_test_get_response_encapsulated_response_ack_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn data_size;
    void *data;
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    spdm_context->encap_context.current_request_op_code = 0;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
    free(data);
}

void libspdm_test_get_response_encapsulated_response_ack_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = 0;

    response_size = sizeof(response);

    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
}

void libspdm_test_get_response_encapsulated_response_ack_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn data_size;
    void *data;
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
    free(data);
}

void libspdm_test_get_response_encapsulated_response_ack_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
}

void libspdm_test_get_response_encapsulated_response_ack_case5(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
}

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_response_encapsulated_request_test_context);

    m_spdm_response_encapsulated_request_test_context.test_buffer = test_buffer;
    m_spdm_response_encapsulated_request_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /*current_request_op_code: SPDM_CHALLENGE */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case2(&State);
    spdm_unit_test_group_teardown(&State);

    /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case3(&State);
    spdm_unit_test_group_teardown(&State);

    /*response_state : LIBSPDM_RESPONSE_STATE_NOT_READY */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case4(&State);
    spdm_unit_test_group_teardown(&State);

    /* current_request_op_code: NULL */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case5(&State);
    spdm_unit_test_group_teardown(&State);

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* current_request_op_code: NULL */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case2(&State);
    spdm_unit_test_group_teardown(&State);

    /*current_request_op_code: SPDM_GET_DIGESTS */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case3(&State);
    spdm_unit_test_group_teardown(&State);

    /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case4(&State);
    spdm_unit_test_group_teardown(&State);

    /*response_state : LIBSPDM_RESPONSE_STATE_NOT_READY */
    spdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case5(&State);
    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(const void *test_buffer, uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
