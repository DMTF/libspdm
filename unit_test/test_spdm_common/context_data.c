/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

static const uint32_t opaque_data = 0xDEADBEEF;

/**
  Test 1: Basic test - tests happy path of setting and getting opaque data from
  context successfully.
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

	status = spdm_set_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &data, sizeof(data));
	assert_int_equal(status, RETURN_SUCCESS);

	data_return_size = sizeof(return_data);
	status = spdm_get_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &return_data, &data_return_size);
	assert_int_equal(status, RETURN_SUCCESS);

	assert_memory_equal(data, return_data, sizeof(data));
	assert_int_equal(data_return_size, sizeof(void*));

	/* check that nothing changed at the data location */
	assert_int_equal(opaque_data, 0xDEADBEEF);
}

/**
  Test 2: Test failure paths of setting opaque data in context. spdm_set_data
  should fail when an invalid size is passed.
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
	spdm_test_context->case_id = 0x1;

	/**
	 * Get current opaque data in context. May have been set in previous
	 * tests. This will be used to compare later to ensure the value hasn't
	 * changed after a failed set data.
	 */
	data_return_size = sizeof(current_return_data);
	status = spdm_get_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &current_return_data, &data_return_size);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(data_return_size, sizeof(void*));

	/* Ensure nothing has changed between subsequent calls to get data */
	assert_ptr_equal(current_return_data, &opaque_data);

	/*
	 * Set data with invalid size, it should fail. Read back to ensure that
	 * no data was set.
	 */
	status = spdm_set_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &data, 500);
	assert_int_equal(status, RETURN_INVALID_PARAMETER);

	data_return_size = sizeof(return_data);
	status = spdm_get_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &return_data, &data_return_size);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_ptr_equal(return_data, current_return_data);
	assert_int_equal(data_return_size, sizeof(void*));

	/* check that nothing changed at the data location */
	assert_int_equal(opaque_data, 0xDEADBEEF);
}

/**
  Test 3: Test failure paths of setting opaque data in context. spdm_set_data
  should fail when data contains NULL value.
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
	spdm_test_context->case_id = 0x1;

	/**
	 * Get current opaque data in context. May have been set in previous
	 * tests. This will be used to compare later to ensure the value hasn't
	 * changed after a failed set data.
	 */
	data_return_size = sizeof(current_return_data);
	status = spdm_get_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &current_return_data, &data_return_size);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(data_return_size, sizeof(void*));

	/* Ensure nothing has changed between subsequent calls to get data */
	assert_ptr_equal(current_return_data, &opaque_data);


	/*
	 * Set data with NULL data, it should fail. Read back to ensure that
	 * no data was set.
	 */
	status = spdm_set_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &data, sizeof(void *));
	assert_int_equal(status, RETURN_INVALID_PARAMETER);

	data_return_size = sizeof(return_data);
	status = spdm_get_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &return_data, &data_return_size);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_ptr_equal(return_data, current_return_data);
	assert_int_equal(data_return_size, sizeof(void*));

	/* check that nothing changed at the data location */
	assert_int_equal(opaque_data, 0xDEADBEEF);

}

/**
  Test 4: Test failure paths of getting opaque data in context. spdm_get_data
  should fail when the size of buffer to get is too small.
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
	spdm_test_context->case_id = 0x1;

	/*
	 * Set data successfully.
	 */
	status = spdm_set_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &data, sizeof(void *));
	assert_int_equal(status, RETURN_SUCCESS);

	/*
	 * Fail get data due to insufficient buffer for return value. returned
	 * data size must return required buffer size.
	 */
	data_return_size = 4;
	status = spdm_get_data(spdm_context, SPDM_DATA_OPAQUE_CONTEXT_DATA,
			       NULL, &return_data, &data_return_size);
	assert_int_equal(status, RETURN_BUFFER_TOO_SMALL);
	assert_int_equal(data_return_size, sizeof(void*));

	/* check that nothing changed at the data location */
	assert_int_equal(opaque_data, 0xDEADBEEF);
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
	};

	setup_spdm_test_context(&m_spdm_common_context_data_test_context);

	return cmocka_run_group_tests(spdm_common_context_data_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
