/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context,
				       IN uintn request_size, IN void *request,
				       IN uint64_t timeout)
{
	return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context,
					  IN OUT uintn *response_size,
					  IN OUT void *response,
					  IN uint64_t timeout)
{
	spdm_test_context_t *spdm_test_context;
	static uintn calling_index = 0;
	uint16_t portion_length;

	portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_test_context = get_spdm_test_context();
	*response_size = spdm_test_context->test_buffer_size;
	copy_mem(response + 1,
		 (uint8_t *)spdm_test_context->test_buffer +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
		 portion_length);

	calling_index++;
	return RETURN_SUCCESS;
}

void test_spdm_requester_get_certificate(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8_t cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8_t *root_cert;
	uintn root_cert_size;

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain(
		(uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
		data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
		&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	libspdm_reset_message_b(spdm_context);

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	libspdm_get_certificate(spdm_context, 0, &cert_chain_size, cert_chain);
}

spdm_test_context_t m_spdm_requester_get_certificate_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_device_send_message,
	spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_requester_get_certificate_test_context);

	m_spdm_requester_get_certificate_test_context.test_buffer = test_buffer;
	m_spdm_requester_get_certificate_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_requester_get_certificate(&State);

	spdm_unit_test_group_teardown(&State);
}
