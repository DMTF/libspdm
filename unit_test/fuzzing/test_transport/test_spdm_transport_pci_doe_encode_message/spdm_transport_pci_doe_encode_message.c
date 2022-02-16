/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_transport_pcidoe_lib.h"
#include "industry_standard/pcidoe.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_transport_pci_doe_encode_message(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn transport_message_size;
    uint8_t transport_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    bool is_app_message;
    bool is_requester;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    is_requester = spdm_test_context->is_requester;
    is_app_message = false;

    transport_message_size = sizeof(transport_message);

    libspdm_transport_pci_doe_encode_message(spdm_context, NULL, is_app_message, is_requester,
                                             spdm_test_context->test_buffer_size,
                                             spdm_test_context->test_buffer,
                                             &transport_message_size,
                                             transport_message);
}

spdm_test_context_t m_spdm_transport_pci_doe_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;
    uintn record_header_max_size;
    uintn aead_tag_max_size;
    uintn buffer_size;

    setup_spdm_test_context(&m_spdm_transport_pci_doe_test_context);

    /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
    record_header_max_size = sizeof(pci_doe_data_object_header_t) +
                             sizeof(spdm_secured_message_a_data_header1_t) +
                             0 + /* PCI_DOE_SEQUENCE_NUMBER_COUNT */
                             sizeof(spdm_secured_message_a_data_header2_t) +
                             sizeof(spdm_secured_message_cipher_header_t) +
                             0; /* PCI_DOE_MAX_RANDOM_NUMBER_COUNT */
    aead_tag_max_size = LIBSPDM_MAX_AEAD_TAG_SIZE;
    buffer_size = test_buffer_size;
    if (buffer_size >
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - record_header_max_size - aead_tag_max_size) {
        buffer_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - record_header_max_size -
                      aead_tag_max_size;
    }

    m_spdm_transport_pci_doe_test_context.test_buffer = test_buffer;
    m_spdm_transport_pci_doe_test_context.test_buffer_size = buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_transport_pci_doe_encode_message(&State);

    spdm_unit_test_group_teardown(&State);
}
