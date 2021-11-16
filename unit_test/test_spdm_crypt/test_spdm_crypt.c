/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"

// https://lapo.it/asn1js/#MCQGCisGAQQBgxyCEgEMFkFDTUU6V0lER0VUOjEyMzQ1Njc4OTA
const uint8_t m_subject_alt_name_buffer1[] = {
	0x30, 0x24, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
	0x1C, 0x82, 0x12, 0x01, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45,
	0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32,
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

// https://lapo.it/asn1js/#MCYGCisGAQQBgxyCEgGgGAwWQUNNRTpXSURHRVQ6MTIzNDU2Nzg5MA
const uint8_t m_subject_alt_name_buffer2[] = {
	0x30, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
	0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43,
	0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

// https://lapo.it/asn1js/#MCigJgYKKwYBBAGDHIISAaAYDBZBQ01FOldJREdFVDoxMjM0NTY3ODkw
const uint8_t m_subject_alt_name_buffer3[] = {
	0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01,
	0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43,
	0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31,
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

const uint8_t m_dmtf_oid[] = { 0x2B, 0x06, 0x01, 0x4,  0x01,
			     0x83, 0x1C, 0x82, 0x12, 0x01 };

void test_spdm_crypt_spdm_get_dmtf_subject_alt_name_from_bytes(void **state)
{
	uintn common_name_size;
	char8 common_name[64];
	uintn dmtf_oid_size;
	uint8_t dmtf_oid[64];
	return_status ret;

	common_name_size = 64;
	dmtf_oid_size = 64;
	zero_mem(common_name, common_name_size);
	zero_mem(dmtf_oid, dmtf_oid_size);
	ret = spdm_get_dmtf_subject_alt_name_from_bytes(
		m_subject_alt_name_buffer1, sizeof(m_subject_alt_name_buffer1),
		common_name, &common_name_size, dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");

	common_name_size = 64;
	dmtf_oid_size = 64;
	zero_mem(common_name, common_name_size);
	zero_mem(dmtf_oid, dmtf_oid_size);
	ret = spdm_get_dmtf_subject_alt_name_from_bytes(
		m_subject_alt_name_buffer2, sizeof(m_subject_alt_name_buffer2),
		common_name, &common_name_size, dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");

	common_name_size = 64;
	dmtf_oid_size = 64;
	zero_mem(common_name, common_name_size);
	zero_mem(dmtf_oid, dmtf_oid_size);
	ret = spdm_get_dmtf_subject_alt_name_from_bytes(
		m_subject_alt_name_buffer3, sizeof(m_subject_alt_name_buffer3),
		common_name, &common_name_size, dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
}

void test_spdm_crypt_spdm_get_dmtf_subject_alt_name(void **state)
{
	uintn common_name_size;
	char8 common_name[64];
	uintn dmtf_oid_size;
	uint8_t dmtf_oid[64];
	uint8_t *file_buffer;
	uintn file_buffer_size;
	return_status ret;
	boolean status;

	status = read_input_file("rsa2048/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	dmtf_oid_size = 64;
	common_name_size = 64;
	ret = spdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
					     common_name, &common_name_size,
					     dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
	free(file_buffer);

	status = read_input_file("rsa3072/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	dmtf_oid_size = 64;
	common_name_size = 64;
	ret = spdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
					     common_name, &common_name_size,
					     dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
	free(file_buffer);

	status = read_input_file("rsa4096/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	dmtf_oid_size = 64;
	common_name_size = 64;
	ret = spdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
					     common_name, &common_name_size,
					     dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
	free(file_buffer);

	status = read_input_file("ecp256/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	dmtf_oid_size = 64;
	common_name_size = 64;
	ret = spdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
					     common_name, &common_name_size,
					     dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
	free(file_buffer);

	status = read_input_file("ecp384/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	dmtf_oid_size = 64;
	common_name_size = 64;
	ret = spdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
					     common_name, &common_name_size,
					     dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
	free(file_buffer);

	status = read_input_file("ecp512/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	dmtf_oid_size = 64;
	common_name_size = 64;
	ret = spdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
					     common_name, &common_name_size,
					     dmtf_oid, &dmtf_oid_size);
	assert_int_equal((int)ret, RETURN_SUCCESS);
	assert_memory_equal(m_dmtf_oid, dmtf_oid, sizeof(m_dmtf_oid));
	assert_string_equal(common_name, "ACME:WIDGET:1234567890");
	free(file_buffer);
}

void test_spdm_crypt_spdm_x509_certificate_check(void **state)
{
	boolean status;
	uint8_t *file_buffer;
	uintn file_buffer_size;

	status = read_input_file("rsa2048/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	status = spdm_x509_certificate_check(file_buffer, file_buffer_size);
	assert_true(status);
	free(file_buffer);

	status = read_input_file("rsa3072/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	status = spdm_x509_certificate_check(file_buffer, file_buffer_size);
	assert_true(status);
	free(file_buffer);

	status = read_input_file("rsa4096/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	status = spdm_x509_certificate_check(file_buffer, file_buffer_size);
	assert_true(status);
	free(file_buffer);

	status = read_input_file("ecp256/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	status = spdm_x509_certificate_check(file_buffer, file_buffer_size);
	assert_true(status);
	free(file_buffer);

	status = read_input_file("ecp384/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	status = spdm_x509_certificate_check(file_buffer, file_buffer_size);
	assert_true(status);
	free(file_buffer);

	status = read_input_file("ecp512/end_requester.cert.der",
				 (void **)&file_buffer, &file_buffer_size);
	assert_true(status);
	status = spdm_x509_certificate_check(file_buffer, file_buffer_size);
	assert_true(status);
	free(file_buffer);
}

int spdm_crypt_lib_setup(void **state)
{
	return 0;
}

int spdm_crypt_lib_teardown(void **state)
{
	return 0;
}

int spdm_crypt_lib_test_main(void)
{
	const struct CMUnitTest spdm_crypt_lib_tests[] = {
		cmocka_unit_test(
			test_spdm_crypt_spdm_get_dmtf_subject_alt_name_from_bytes),
		cmocka_unit_test(
			test_spdm_crypt_spdm_get_dmtf_subject_alt_name),
		cmocka_unit_test(test_spdm_crypt_spdm_x509_certificate_check)
	};

	return cmocka_run_group_tests(spdm_crypt_lib_tests,
				      spdm_crypt_lib_setup,
				      spdm_crypt_lib_teardown);
}

int main(void)
{
	spdm_crypt_lib_test_main();
	return 0;
}
