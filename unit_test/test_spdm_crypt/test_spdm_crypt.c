/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"

/* https://lapo.it/asn1js/#MCQGCisGAQQBgxyCEgEMFkFDTUU6V0lER0VUOjEyMzQ1Njc4OTA*/
uint8_t m_libspdm_subject_alt_name_buffer1[] = {
    0x30, 0x24, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
    0x1C, 0x82, 0x12, 0x01, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45,
    0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

/* https://lapo.it/asn1js/#MCYGCisGAQQBgxyCEgGgGAwWQUNNRTpXSURHRVQ6MTIzNDU2Nzg5MA*/
uint8_t m_libspdm_subject_alt_name_buffer2[] = {
    0x30, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
    0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43,
    0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

/* https://lapo.it/asn1js/#MCigJgYKKwYBBAGDHIISAaAYDBZBQ01FOldJREdFVDoxMjM0NTY3ODkw*/
uint8_t m_libspdm_subject_alt_name_buffer3[] = {
    0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01,
    0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43,
    0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

uint8_t m_libspdm_dmtf_oid[] = { 0x2B, 0x06, 0x01, 0x4,  0x01,
                                 0x83, 0x1C, 0x82, 0x12, 0x01 };

void libspdm_test_crypt_spdm_get_dmtf_subject_alt_name_from_bytes(void **state)
{
    size_t common_name_size;
    char common_name[64];
    size_t dmtf_oid_size;
    uint8_t dmtf_oid[64];
    bool status;

    common_name_size = 64;
    dmtf_oid_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    libspdm_zero_mem(dmtf_oid, dmtf_oid_size);
    status = libspdm_get_dmtf_subject_alt_name_from_bytes(
        m_libspdm_subject_alt_name_buffer1, sizeof(m_libspdm_subject_alt_name_buffer1),
        common_name, &common_name_size, dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");

    common_name_size = 64;
    dmtf_oid_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    libspdm_zero_mem(dmtf_oid, dmtf_oid_size);
    status = libspdm_get_dmtf_subject_alt_name_from_bytes(
        m_libspdm_subject_alt_name_buffer2, sizeof(m_libspdm_subject_alt_name_buffer2),
        common_name, &common_name_size, dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");

    common_name_size = 64;
    dmtf_oid_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    libspdm_zero_mem(dmtf_oid, dmtf_oid_size);
    status = libspdm_get_dmtf_subject_alt_name_from_bytes(
        m_libspdm_subject_alt_name_buffer3, sizeof(m_libspdm_subject_alt_name_buffer3),
        common_name, &common_name_size, dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
}

void libspdm_test_crypt_spdm_get_dmtf_subject_alt_name(void **state)
{
    size_t common_name_size;
    char common_name[64];
    size_t dmtf_oid_size;
    uint8_t dmtf_oid[64];
    uint8_t *file_buffer;
    size_t file_buffer_size;
    bool status;

    status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    dmtf_oid_size = 64;
    common_name_size = 64;
    status = libspdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
                                               common_name, &common_name_size,
                                               dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(file_buffer);

    status = libspdm_read_input_file("rsa3072/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    dmtf_oid_size = 64;
    common_name_size = 64;
    status = libspdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
                                               common_name, &common_name_size,
                                               dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(file_buffer);

    status = libspdm_read_input_file("rsa4096/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    dmtf_oid_size = 64;
    common_name_size = 64;
    status = libspdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
                                               common_name, &common_name_size,
                                               dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(file_buffer);

    status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    dmtf_oid_size = 64;
    common_name_size = 64;
    status = libspdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
                                               common_name, &common_name_size,
                                               dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(file_buffer);

    status = libspdm_read_input_file("ecp384/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    dmtf_oid_size = 64;
    common_name_size = 64;
    status = libspdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
                                               common_name, &common_name_size,
                                               dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(file_buffer);

    status = libspdm_read_input_file("ecp521/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    dmtf_oid_size = 64;
    common_name_size = 64;
    status = libspdm_get_dmtf_subject_alt_name(file_buffer, file_buffer_size,
                                               common_name, &common_name_size,
                                               dmtf_oid, &dmtf_oid_size);
    assert_true(status);
    assert_memory_equal(m_libspdm_dmtf_oid, dmtf_oid, sizeof(m_libspdm_dmtf_oid));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(file_buffer);
}

void libspdm_test_crypt_spdm_x509_certificate_check(void **state)
{
    bool status;
    uint8_t *file_buffer;
    size_t file_buffer_size;

    status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                            true);
    assert_true(status);
    free(file_buffer);

    status = libspdm_read_input_file("rsa3072/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                                            true);
    assert_true(status);
    free(file_buffer);

    status = libspdm_read_input_file("rsa4096/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
                                            true);
    assert_true(status);
    free(file_buffer);

    status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                            true);
    assert_true(status);
    free(file_buffer);

    status = libspdm_read_input_file("ecp384/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                                            true);
    assert_true(status);
    free(file_buffer);

    status = libspdm_read_input_file("ecp521/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
                                            true);
    assert_true(status);
    free(file_buffer);

    /*check for leaf cert basic constraints, CA = true,pathlen:none*/
    status = libspdm_read_input_file("ecp256/end_requester_ca_false.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                            true);
    assert_false(status);
    free(file_buffer);


    /*check for leaf cert basic constraints, basic constraints is excluded*/
    status = libspdm_read_input_file("ecp256/end_requester_without_basic_constraint.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                            true);
    assert_true(status);
    free(file_buffer);

    /*cert mismatched negotiated base_aysm_algo check*/
    status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                            true);
    assert_false(status);
    free(file_buffer);

    status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                     (void **)&file_buffer, &file_buffer_size);
    assert_true(status);
    status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                            true);
    assert_false(status);
    free(file_buffer);
}

int libspdm_crypt_lib_setup(void **state)
{
    return 0;
}

int libspdm_crypt_lib_teardown(void **state)
{
    return 0;
}

int libspdm_crypt_lib_test_main(void)
{
    const struct CMUnitTest spdm_crypt_lib_tests[] = {
        cmocka_unit_test(
            libspdm_test_crypt_spdm_get_dmtf_subject_alt_name_from_bytes),

        cmocka_unit_test(libspdm_test_crypt_spdm_get_dmtf_subject_alt_name),

        cmocka_unit_test(libspdm_test_crypt_spdm_x509_certificate_check)
    };

    return cmocka_run_group_tests(spdm_crypt_lib_tests,
                                  libspdm_crypt_lib_setup,
                                  libspdm_crypt_lib_teardown);
}

int main(void)
{
    libspdm_crypt_lib_test_main();
    return 0;
}
