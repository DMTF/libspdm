/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_crypt_lib.h"

/* https://lapo.it/asn1js/#MCQGCisGAQQBgxyCEgEMFkFDTUU6V0lER0VUOjEyMzQ1Njc4OTA*/
static uint8_t m_libspdm_subject_alt_name_buffer1[] = {
    0x30, 0x24, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
    0x1C, 0x82, 0x12, 0x01, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45,
    0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

/* https://lapo.it/asn1js/#MCYGCisGAQQBgxyCEgGgGAwWQUNNRTpXSURHRVQ6MTIzNDU2Nzg5MA*/
static uint8_t m_libspdm_subject_alt_name_buffer2[] = {
    0x30, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
    0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43,
    0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

/* https://lapo.it/asn1js/#MCigJgYKKwYBBAGDHIISAaAYDBZBQ01FOldJREdFVDoxMjM0NTY3ODkw*/
static uint8_t m_libspdm_subject_alt_name_buffer3[] = {
    0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01,
    0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43,
    0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

static uint8_t m_libspdm_dmtf_oid[] = { 0x2B, 0x06, 0x01, 0x4,  0x01,
                                        0x83, 0x1C, 0x82, 0x12, 0x01 };

static void libspdm_test_crypt_spdm_get_dmtf_subject_alt_name_from_bytes(void **state)
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

static void libspdm_test_crypt_spdm_get_dmtf_subject_alt_name(void **state)
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

static void libspdm_test_crypt_spdm_x509_certificate_check(void **state)
{
    bool status;
    uint8_t *file_buffer;
    size_t file_buffer_size;

    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_3072_SUPPORT) && (LIBSPDM_SHA384_SUPPORT)) {
        status = libspdm_read_input_file("rsa3072/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_4096_SUPPORT) && (LIBSPDM_SHA512_SUPPORT)) {
        status = libspdm_read_input_file("rsa4096/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }

    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P384_SUPPORT) && (LIBSPDM_SHA384_SUPPORT)) {
        status = libspdm_read_input_file("ecp384/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P521_SUPPORT) && (LIBSPDM_SHA512_SUPPORT)) {
        status = libspdm_read_input_file("ecp521/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*check for leaf cert basic constraints, CA = true,pathlen:none*/
        status = libspdm_read_input_file("ecp256/end_requester_ca_false.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_false(status);
        free(file_buffer);


        /*check for leaf cert basic constraints, basic constraints is excluded*/
        status = libspdm_read_input_file("ecp256/end_requester_without_basic_constraint.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*check for leaf cert spdm defined eku*/
        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_req_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_req_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_responder_with_spdm_req_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_req_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_3072_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /* cert mismatched negotiated base_aysm_algo check */
        status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_false(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_4096_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*test web cert: cert public key algo is RSA case*/
        status = libspdm_read_input_file("test_web_cert/Google.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("test_web_cert/Amazon.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }

    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*test web cert: ccert public key algo is ECC case*/
        status = libspdm_read_input_file("test_web_cert/GitHub.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("test_web_cert/YouTube.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_12,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);
        free(file_buffer);
    }

    /* Test 1.3 */
    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("ecp256/end_responder.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("ecp256/end_requester_without_basic_constraint.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        /*the expected result is false, because basic_constraint is mandatory in SPDM 1.3*/
        assert_false(status);
        free(file_buffer);
    }

}

static void libspdm_test_crypt_spdm_x509_set_cert_certificate_check(void **state)
{
    bool status;
    uint8_t *file_buffer;
    size_t file_buffer_size;

    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("rsa2048/end_responder.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_set_cert_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        status = libspdm_x509_set_cert_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_false(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_set_cert_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        status = libspdm_x509_set_cert_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_false(status);

        status = libspdm_read_input_file("ecp256/end_requester_ca_false.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_set_cert_certificate_check(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_true(status);
        free(file_buffer);
    }

}

/* Copies data into a buffer one byte longer, so that a test can pass a size one byte larger than
 * the data without reading past the end of an allocation. */
static uint8_t *libspdm_test_copy_with_trailing_byte(const void *data, size_t data_size)
{
    uint8_t *copy;

    copy = malloc(data_size + 1);
    assert_non_null(copy);
    libspdm_copy_mem(copy, data_size + 1, data, data_size);
    copy[data_size] = 0x00;

    return copy;
}

static void libspdm_test_crypt_spdm_verify_cert_chain_data(void **state)
{
    bool status;
    uint8_t *file_buffer;
    size_t file_buffer_size;
    uint8_t *padded_buffer;

    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("rsa2048/bundle_requester.certchain.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_verify_cert_chain_data(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        padded_buffer = libspdm_test_copy_with_trailing_byte(file_buffer, file_buffer_size);
        status = libspdm_verify_cert_chain_data(
            SPDM_MESSAGE_VERSION_13,
            padded_buffer, file_buffer_size + 1,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        free(padded_buffer);
        assert_false(status);

        status = libspdm_verify_cert_chain_data(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("ecp256/bundle_responder.certchain.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_verify_cert_chain_data(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        padded_buffer = libspdm_test_copy_with_trailing_byte(file_buffer, file_buffer_size);
        status = libspdm_verify_cert_chain_data(
            SPDM_MESSAGE_VERSION_13,
            padded_buffer, file_buffer_size + 1,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        free(padded_buffer);
        assert_false(status);

        status = libspdm_verify_cert_chain_data(
            SPDM_MESSAGE_VERSION_13,
            file_buffer, file_buffer_size,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_false(status);
        free(file_buffer);
    }
}


static void libspdm_test_crypt_spdm_verify_certificate_chain_buffer(void **state)
{
    bool status;
    void *data;
    size_t data_size;
    uint8_t *padded_buffer;

    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        if (!libspdm_read_responder_public_certificate_chain(
                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                &data,&data_size,
                NULL, NULL)) {
            assert_true(false);
            return;
        }

        status = libspdm_verify_certificate_chain_buffer(
            SPDM_MESSAGE_VERSION_13,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            data,data_size,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        padded_buffer = libspdm_test_copy_with_trailing_byte(data, data_size);
        status = libspdm_verify_certificate_chain_buffer(
            SPDM_MESSAGE_VERSION_13,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            padded_buffer, data_size + 1,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        free(padded_buffer);
        assert_false(status);

        status = libspdm_verify_certificate_chain_buffer(
            SPDM_MESSAGE_VERSION_13,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            0,
            data,data_size,
            true,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_true(status);
        free(data);
    }

    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        if (!libspdm_read_responder_public_certificate_chain(
                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                &data,&data_size,
                NULL, NULL)) {
            assert_true(false);
            return;
        }

        status = libspdm_verify_certificate_chain_buffer(
            SPDM_MESSAGE_VERSION_13,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            data,data_size,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        assert_true(status);

        padded_buffer = libspdm_test_copy_with_trailing_byte(data, data_size);
        status = libspdm_verify_certificate_chain_buffer(
            SPDM_MESSAGE_VERSION_13,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            padded_buffer, data_size + 1,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
        free(padded_buffer);
        assert_false(status);

        status = libspdm_verify_certificate_chain_buffer(
            SPDM_MESSAGE_VERSION_13,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            0,
            data,data_size,
            false,
            SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
        assert_false(status);
        free(data);
    }
}

static void libspdm_test_crypt_asym_verify(void **state)
{
    spdm_version_number_t spdm_version;
    void *context;
    void *data;
    size_t data_size;
    uint8_t signature[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t sig_size;
    uint8_t signature_endian;
    char *file;
    bool status;

    spdm_version = SPDM_MESSAGE_VERSION_11;

    file = "ecp256/end_responder.key";
    libspdm_read_input_file(file, &data, &data_size);
    status = libspdm_asym_get_private_key_from_pem(
        m_libspdm_use_asym_algo, data, data_size, NULL, &context);

    if (!status) {
        libspdm_zero_mem(data, data_size);
        free(data);
        assert_true(status);
    }

    const uint8_t message[] = {
        0x19, 0x90, 0x2d, 0x02, 0x34, 0x6e, 0xd5, 0x90,
        0x0e, 0x69, 0x51, 0x2f, 0xf2, 0xbd, 0x9d, 0x33,
        0x26, 0x71, 0x8f, 0x62, 0xa0, 0x01, 0xbd, 0xfd,
        0x94, 0xe2, 0x98, 0x17, 0x24, 0xfd, 0xca, 0xf0
    };

    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    libspdm_asym_sign(spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                      SPDM_MEASUREMENTS,
                      m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                      context,
                      message, sizeof(message),
                      signature, &sig_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    status = libspdm_asym_sign(spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                               SPDM_MEASUREMENTS,
                               m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                               context,
                               message, sizeof(message),
                               signature, &sig_size);
    assert_true(status);
#else
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    status = libspdm_hash_all(m_libspdm_use_hash_algo, message, sizeof(message), message_hash);

    assert_true(status);
    status = libspdm_asym_sign_hash(spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                                    SPDM_MEASUREMENTS,
                                    m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                                    context,
                                    message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
                                    signature, &sig_size);
    assert_true(status);
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* Big Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /*  Error: Big Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Big Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    libspdm_copy_signature_swap_endian(
        m_libspdm_use_asym_algo,
        signature, sig_size, signature, sig_size);

    /* Little Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Error: Little Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /* Little Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);
#else
    /* Big Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /*  Error: Big Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Big Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    libspdm_copy_signature_swap_endian(
        m_libspdm_use_asym_algo,
        signature, sig_size, signature, sig_size);

    /* Little Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Error: Little Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /* Little Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MEASUREMENTS,
            m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

#endif
}

static void libspdm_test_crypt_req_asym_verify(void **state)
{
    spdm_version_number_t spdm_version;
    void *context;
    void *data;
    size_t data_size;
    uint8_t signature[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t sig_size;
    uint8_t signature_endian;
    char *file;
    bool status;

    spdm_version = SPDM_MESSAGE_VERSION_11;

    const uint8_t message[] = {
        0x19, 0x90, 0x2d, 0x02, 0x34, 0x6e, 0xd5, 0x90,
        0x0e, 0x69, 0x51, 0x2f, 0xf2, 0xbd, 0x9d, 0x33,
        0x26, 0x71, 0x8f, 0x62, 0xa0, 0x01, 0xbd, 0xfd,
        0x94, 0xe2, 0x98, 0x17, 0x24, 0xfd, 0xca, 0xf0
    };

    file = "rsa2048/end_requester.key";
    status = libspdm_read_input_file(file, &data, &data_size);
    assert_true(status);

    status = libspdm_req_asym_get_private_key_from_pem(m_libspdm_use_req_asym_algo,
                                                       data,
                                                       data_size, NULL,
                                                       &context);
    if (!status) {
        libspdm_zero_mem(data, data_size);
        free(data);
        assert_true(status);
    }
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    status = libspdm_req_asym_sign(spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                                   SPDM_FINISH,
                                   m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
                                   context,
                                   message, sizeof(message),
                                   signature, &sig_size);
    assert_true(status);
#else
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    status = libspdm_hash_all(m_libspdm_use_hash_algo, message, sizeof(message), message_hash);
    assert_true(status);
    status = libspdm_req_asym_sign_hash(spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                                        SPDM_FINISH,
                                        m_libspdm_use_req_asym_algo,
                                        m_libspdm_use_hash_algo, context,
                                        message_hash,
                                        libspdm_get_hash_size(m_libspdm_use_hash_algo),
                                        signature,
                                        &sig_size);
    assert_true(status);
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* Big Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_req_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /*  Error: Big Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_req_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Big Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_req_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    libspdm_copy_signature_swap_endian(
        m_libspdm_use_req_asym_algo,
        signature, sig_size, signature, sig_size);

    /* Little Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_req_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Error: Little Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_req_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /* Little Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_req_asym_verify_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message, sizeof(message),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

#else
    /* Big Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_req_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /*  Error: Big Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_req_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Big Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_req_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    libspdm_copy_signature_swap_endian(
        m_libspdm_use_req_asym_algo,
        signature, sig_size, signature, sig_size);

    /* Little Endian Signature. Little Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    status = libspdm_req_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    /* Error: Little Endian Signature. Big Endian Verify */
    signature_endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    status = libspdm_req_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(!status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    /* Little Endian Signature. Big or Little Endian Verify */
    signature_endian= LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    status = libspdm_req_asym_verify_hash_ex(
        spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            context,
            message_hash, libspdm_get_hash_size(m_libspdm_use_hash_algo),
            signature, sig_size,
            &signature_endian);
    assert_true(status);
    assert_int_equal(signature_endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);
#endif
}

bool libspdm_is_palindrome(const uint8_t *buf, size_t buf_size);

bool libspdm_is_signature_buffer_palindrome(
    uint32_t base_asym_algo, const uint8_t *buf, size_t buf_size);

static void libspdm_test_crypt_palindrome(void **state)
{
    bool status;

    /* Test valid palindrome with even number of elements */
    uint8_t buf1[] = {0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0};
    status = libspdm_is_palindrome(buf1, sizeof(buf1));
    assert_true(status);

    /* Test valid palindrome with odd number of elements */
    uint8_t buf2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    status = libspdm_is_palindrome(buf2, sizeof(buf2));
    assert_true(status);

    /* Test invalid palindrome where inner corner-case element is not matching */
    uint8_t buf3[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 6, 5, 4, 3, 2, 1, 0 };
    status = libspdm_is_palindrome(buf3, sizeof(buf3));
    assert_false(status);

    /* Test invalid palindrome where outer corner-case element is not matching */
    uint8_t buf4[] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 8 };
    status = libspdm_is_palindrome(buf4, sizeof(buf4));
    assert_false(status);

    /* Test invalid palindrome where middle element is not matching */
    uint8_t buf5[] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 4, 2, 1, 0 };
    status = libspdm_is_palindrome(buf5, sizeof(buf5));
    assert_false(status);
}

static void libspdm_test_crypt_rsa_palindrome(void **state)
{
    /* Test RSA Buffers as palindrome */
    int i;
    bool status;

    const uint32_t rsa_algos[] = {
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096
    };

    /* Palindrome for RSA */
    uint8_t buf0[] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0 };

    /* Not Palindrome cases for RSA */

    /* Test invalid palindrome where inner corner-case element is not matching */
    uint8_t buf1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 6, 5, 4, 3, 2, 1, 0 };

    /* Test invalid palindrome where outer corner-case element is not matching */
    uint8_t buf2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 8 };

    /* Test invalid palindrome where middle element is not matching */
    uint8_t buf3[] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 4, 2, 1, 0 };

    /* Test each of these buffers against each RSA algo type */
    for (i = 0; i < (sizeof(rsa_algos) / sizeof(rsa_algos[0])); i++) {
        /* Test case where buffer is palindrome */
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf0, sizeof(buf0));
        assert_true(status);

        /* Test cases where buffer is NOT palindrome */
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf1, sizeof(buf1));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf2, sizeof(buf2));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf3, sizeof(buf3));
        assert_false(status);
    }
}

static void libspdm_test_crypt_ecdsa_palindrome(void **state)
{
    int i;
    bool status;

    /* Test ECDSA Buffers as palindrome */
    const uint32_t ecdsa_algos[] = {
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521
    };

    /* Test for valid ECDSA buffer palindrome */
    uint8_t buf0[] = { 0, 1, 2, 3, 3, 2, 1, 0, 0, 1, 2, 3, 3, 2, 1, 0 };

    /* Tests for ECDSA buffer not palidrome */

    /* Test for invalid palindrome where outer element of 1st buffer does not match */
    uint8_t buf1[] = { 0, 1, 2, 3, 3, 2, 1, 1, 0, 1, 2, 3, 3, 2, 1, 0 };

    /* Test for invalid palindrome where outer element of 2nd buffer does not match */
    uint8_t buf2[] = { 0, 1, 2, 3, 3, 2, 1, 0, 0, 1, 2, 3, 3, 2, 1, 1 };

    /* Test for invalid palindrome where inner element of 1st buffer does not match */
    uint8_t buf3[] = { 0, 1, 2, 3, 4, 2, 1, 0, 0, 1, 2, 3, 3, 2, 1, 0 };

    /* Test for invalid palindrome where inner element of 2nd buffer does not match */
    uint8_t buf4[] = { 0, 1, 2, 3, 3, 2, 1, 0, 0, 1, 2, 3, 4, 2, 1, 0 };

    /* Test for invalid palindrome where middle element of 1st buffer does not match */
    uint8_t buf5[] = { 0, 1, 2, 3, 3, 2, 0, 0, 0, 1, 2, 3, 3, 2, 1, 0 };

    /* Test for invalid palindrome where middle element of 2nd buffer does not match */
    uint8_t buf6[] = { 0, 1, 2, 3, 3, 2, 1, 0, 0, 1, 2, 3, 3, 0, 1, 0 };

    /* Test each of the buffers against each ECDSA algo type */
    for (i = 0; i < (sizeof(ecdsa_algos) / sizeof(ecdsa_algos[0])); i++) {
        /* Test case where buffer is palindrome */
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf0, sizeof(buf0));
        assert_true(status);

        /* Test cases where buffer is NOT palindrome */
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf1, sizeof(buf1));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf2, sizeof(buf2));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf3, sizeof(buf3));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf4, sizeof(buf4));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf5, sizeof(buf5));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf6, sizeof(buf6));
        assert_false(status);
    }
}

/* These tests sweep every algorithm the specification defines.
 *
 * A cryptlib may stub an algorithm that spdm_lib_config.h enables. The Mbed TLS backend, for
 * example, does not implement SM3. The sweep therefore does not demand success. It probes with
 * the one-shot entry point and requires the incremental entry points to agree with it. */
typedef struct {
    uint32_t base_hash_algo;
    uint32_t measurement_hash_algo;
    uint32_t hash_size;
    uint32_t measurement_hash_size;
    size_t hash_nid;
} libspdm_hash_algo_entry_t;

static const libspdm_hash_algo_entry_t m_libspdm_hash_algo_table[] = {
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
      LIBSPDM_SHA256_SUPPORT ? 32 : 0, 32, LIBSPDM_CRYPTO_NID_SHA256 },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
      LIBSPDM_SHA384_SUPPORT ? 48 : 0, 48, LIBSPDM_CRYPTO_NID_SHA384 },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
      LIBSPDM_SHA512_SUPPORT ? 64 : 0, 64, LIBSPDM_CRYPTO_NID_SHA512 },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,
      LIBSPDM_SHA3_256_SUPPORT ? 32 : 0, 32, LIBSPDM_CRYPTO_NID_SHA3_256 },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,
      LIBSPDM_SHA3_384_SUPPORT ? 48 : 0, 48, LIBSPDM_CRYPTO_NID_SHA3_384 },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,
      LIBSPDM_SHA3_512_SUPPORT ? 64 : 0, 64, LIBSPDM_CRYPTO_NID_SHA3_512 },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256,
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256,
      LIBSPDM_SM3_256_SUPPORT ? 32 : 0, 32, LIBSPDM_CRYPTO_NID_SM3_256 },
};

#define LIBSPDM_HASH_ALGO_TABLE_COUNT \
    (sizeof(m_libspdm_hash_algo_table) / sizeof(m_libspdm_hash_algo_table[0]))

/* Split point for the incremental tests, so that the update entry points are driven more than
 * once and libspdm_hash_duplicate is exercised against a context that already holds data. */
#define LIBSPDM_HASH_SWEEP_SPLIT 16

static const uint8_t m_libspdm_hash_sweep_message[] = {
    0x19, 0x90, 0x2d, 0x02, 0x34, 0x6e, 0xd5, 0x90,
    0x0e, 0x69, 0x51, 0x2f, 0xf2, 0xbd, 0x9d, 0x33,
    0x26, 0x71, 0x8f, 0x62, 0xa0, 0x01, 0xbd, 0xfd,
    0x94, 0xe2, 0x98, 0x17, 0x24, 0xfd, 0xca, 0xf0
};

static const uint8_t m_libspdm_hash_sweep_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t m_libspdm_hash_sweep_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t m_libspdm_hash_sweep_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

static void libspdm_test_crypt_hash_size_and_nid(void **state)
{
    size_t index;
    const libspdm_hash_algo_entry_t *entry;

    for (index = 0; index < LIBSPDM_HASH_ALGO_TABLE_COUNT; index++) {
        entry = &m_libspdm_hash_algo_table[index];

        assert_int_equal(libspdm_get_hash_size(entry->base_hash_algo), entry->hash_size);
        assert_int_equal(libspdm_get_hash_nid(entry->base_hash_algo), entry->hash_nid);
        assert_int_equal(libspdm_get_measurement_hash_size(entry->measurement_hash_algo),
                         entry->measurement_hash_size);
    }

    assert_int_equal(libspdm_get_measurement_hash_size(
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY), 0xFFFFFFFF);

    /* Unlike the operational entry points, which assert on an unknown algorithm, the size and
     * NID getters return a benign value. */
    assert_int_equal(libspdm_get_hash_size(0), 0);
    assert_int_equal(libspdm_get_hash_nid(0), LIBSPDM_CRYPTO_NID_NULL);
    assert_int_equal(libspdm_get_measurement_hash_size(0), 0);
}

static void libspdm_test_crypt_hash_all_algos(void **state)
{
    size_t index;
    const libspdm_hash_algo_entry_t *entry;
    uint8_t one_shot[LIBSPDM_MAX_HASH_SIZE];
    uint8_t incremental[LIBSPDM_MAX_HASH_SIZE];
    uint8_t duplicated[LIBSPDM_MAX_HASH_SIZE];
    void *context;
    void *copy;
    bool one_shot_result;

    for (index = 0; index < LIBSPDM_HASH_ALGO_TABLE_COUNT; index++) {
        entry = &m_libspdm_hash_algo_table[index];

        /* The algorithm is compiled out, so its arms assert rather than dispatch. */
        if (entry->hash_size == 0) {
            continue;
        }

        one_shot_result = libspdm_hash_all(entry->base_hash_algo,
                                           m_libspdm_hash_sweep_message,
                                           sizeof(m_libspdm_hash_sweep_message), one_shot);

        context = libspdm_hash_new(entry->base_hash_algo);
        if (context == NULL) {
            /* The cryptlib stubs this algorithm; the one-shot entry point must say so too. */
            assert_false(one_shot_result);
            continue;
        }

        assert_true(one_shot_result);
        assert_true(libspdm_hash_init(entry->base_hash_algo, context));
        assert_true(libspdm_hash_update(entry->base_hash_algo, context,
                                        m_libspdm_hash_sweep_message,
                                        LIBSPDM_HASH_SWEEP_SPLIT));

        copy = libspdm_hash_new(entry->base_hash_algo);
        assert_non_null(copy);
        assert_true(libspdm_hash_duplicate(entry->base_hash_algo, context, copy));

        assert_true(libspdm_hash_update(entry->base_hash_algo, context,
                                        m_libspdm_hash_sweep_message + LIBSPDM_HASH_SWEEP_SPLIT,
                                        sizeof(m_libspdm_hash_sweep_message) -
                                        LIBSPDM_HASH_SWEEP_SPLIT));
        assert_true(libspdm_hash_final(entry->base_hash_algo, context, incremental));

        assert_true(libspdm_hash_update(entry->base_hash_algo, copy,
                                        m_libspdm_hash_sweep_message + LIBSPDM_HASH_SWEEP_SPLIT,
                                        sizeof(m_libspdm_hash_sweep_message) -
                                        LIBSPDM_HASH_SWEEP_SPLIT));
        assert_true(libspdm_hash_final(entry->base_hash_algo, copy, duplicated));

        assert_memory_equal(one_shot, incremental, entry->hash_size);
        assert_memory_equal(one_shot, duplicated, entry->hash_size);

        libspdm_hash_free(entry->base_hash_algo, copy);
        libspdm_hash_free(entry->base_hash_algo, context);
    }
}

static void libspdm_test_crypt_hmac_all_algos(void **state)
{
    size_t index;
    const libspdm_hash_algo_entry_t *entry;
    uint8_t one_shot[LIBSPDM_MAX_HASH_SIZE];
    uint8_t incremental[LIBSPDM_MAX_HASH_SIZE];
    void *context;
    bool one_shot_result;

    for (index = 0; index < LIBSPDM_HASH_ALGO_TABLE_COUNT; index++) {
        entry = &m_libspdm_hash_algo_table[index];

        if (entry->hash_size == 0) {
            continue;
        }

        one_shot_result = libspdm_hmac_all(entry->base_hash_algo,
                                           m_libspdm_hash_sweep_message,
                                           sizeof(m_libspdm_hash_sweep_message),
                                           m_libspdm_hash_sweep_key,
                                           sizeof(m_libspdm_hash_sweep_key), one_shot);

        context = libspdm_hmac_new(entry->base_hash_algo);
        if (context == NULL) {
            assert_false(one_shot_result);
            continue;
        }

        assert_true(one_shot_result);
        assert_true(libspdm_hmac_init(entry->base_hash_algo, context,
                                      m_libspdm_hash_sweep_key,
                                      sizeof(m_libspdm_hash_sweep_key)));
        assert_true(libspdm_hmac_update(entry->base_hash_algo, context,
                                        m_libspdm_hash_sweep_message,
                                        LIBSPDM_HASH_SWEEP_SPLIT));
        assert_true(libspdm_hmac_update(entry->base_hash_algo, context,
                                        m_libspdm_hash_sweep_message + LIBSPDM_HASH_SWEEP_SPLIT,
                                        sizeof(m_libspdm_hash_sweep_message) -
                                        LIBSPDM_HASH_SWEEP_SPLIT));
        assert_true(libspdm_hmac_final(entry->base_hash_algo, context, incremental));

        assert_memory_equal(one_shot, incremental, entry->hash_size);

        libspdm_hmac_free(entry->base_hash_algo, context);
    }
}

static void libspdm_test_crypt_hkdf_all_algos(void **state)
{
    size_t index;
    const libspdm_hash_algo_entry_t *entry;
    uint8_t prk[LIBSPDM_MAX_HASH_SIZE];
    uint8_t okm[64];
    bool extracted;

    for (index = 0; index < LIBSPDM_HASH_ALGO_TABLE_COUNT; index++) {
        entry = &m_libspdm_hash_algo_table[index];

        if (entry->hash_size == 0) {
            continue;
        }

        /* The pseudorandom key is the size of the digest, which is what expand requires. */
        extracted = libspdm_hkdf_extract(entry->base_hash_algo,
                                         m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         m_libspdm_hash_sweep_salt,
                                         sizeof(m_libspdm_hash_sweep_salt),
                                         prk, entry->hash_size);

        /* Extract and expand are backed by the same digest, so they stand or fall together. */
        assert_int_equal(libspdm_hkdf_expand(entry->base_hash_algo, prk, entry->hash_size,
                                             m_libspdm_hash_sweep_info,
                                             sizeof(m_libspdm_hash_sweep_info),
                                             okm, sizeof(okm)), extracted);
    }
}

/* The key, IV and tag sizes of each AEAD cipher suite, or 0 when the suite is compiled out. */
typedef struct {
    uint16_t aead_cipher_suite;
    uint32_t key_size;
    uint32_t iv_size;
    uint32_t tag_size;
} libspdm_aead_suite_entry_t;

static const libspdm_aead_suite_entry_t m_libspdm_aead_suite_table[] = {
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
      LIBSPDM_AEAD_AES_128_GCM_SUPPORT ? 16 : 0,
      LIBSPDM_AEAD_AES_128_GCM_SUPPORT ? 12 : 0,
      LIBSPDM_AEAD_AES_128_GCM_SUPPORT ? 16 : 0 },
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
      LIBSPDM_AEAD_AES_256_GCM_SUPPORT ? 32 : 0,
      LIBSPDM_AEAD_AES_256_GCM_SUPPORT ? 12 : 0,
      LIBSPDM_AEAD_AES_256_GCM_SUPPORT ? 16 : 0 },
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
      LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT ? 32 : 0,
      LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT ? 12 : 0,
      LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT ? 16 : 0 },
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM,
      LIBSPDM_AEAD_SM4_128_GCM_SUPPORT ? 16 : 0,
      LIBSPDM_AEAD_SM4_128_GCM_SUPPORT ? 12 : 0,
      LIBSPDM_AEAD_SM4_128_GCM_SUPPORT ? 16 : 0 },
};

static void libspdm_test_crypt_aead_all_suites(void **state)
{
    size_t index;
    const libspdm_aead_suite_entry_t *entry;
    uint8_t tag[LIBSPDM_MAX_AEAD_TAG_SIZE];
    uint8_t cipher_text[sizeof(m_libspdm_hash_sweep_message)];
    uint8_t plain_text[sizeof(m_libspdm_hash_sweep_message)];
    size_t cipher_text_size;
    size_t plain_text_size;
    spdm_version_number_t secured_message_version;

    secured_message_version = SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_aead_suite_table); index++) {
        entry = &m_libspdm_aead_suite_table[index];

        assert_int_equal(libspdm_get_aead_key_size(entry->aead_cipher_suite), entry->key_size);
        assert_int_equal(libspdm_get_aead_iv_size(entry->aead_cipher_suite), entry->iv_size);
        assert_int_equal(libspdm_get_aead_tag_size(entry->aead_cipher_suite), entry->tag_size);

        /* The suite is compiled out, so its arms assert rather than dispatch. */
        if (entry->key_size == 0) {
            continue;
        }

        /* The sweep reuses the hash sweep's inputs: its key, its salt as the IV, and its info as
         * the associated data. */
        cipher_text_size = sizeof(cipher_text);
        assert_true(libspdm_aead_encryption(secured_message_version, entry->aead_cipher_suite,
                                            m_libspdm_hash_sweep_key, entry->key_size,
                                            m_libspdm_hash_sweep_salt, entry->iv_size,
                                            m_libspdm_hash_sweep_info,
                                            sizeof(m_libspdm_hash_sweep_info),
                                            m_libspdm_hash_sweep_message,
                                            sizeof(m_libspdm_hash_sweep_message),
                                            tag, entry->tag_size,
                                            cipher_text, &cipher_text_size));
        assert_int_equal(cipher_text_size, sizeof(m_libspdm_hash_sweep_message));
        assert_memory_not_equal(cipher_text, m_libspdm_hash_sweep_message, cipher_text_size);

        plain_text_size = sizeof(plain_text);
        assert_true(libspdm_aead_decryption(secured_message_version, entry->aead_cipher_suite,
                                            m_libspdm_hash_sweep_key, entry->key_size,
                                            m_libspdm_hash_sweep_salt, entry->iv_size,
                                            m_libspdm_hash_sweep_info,
                                            sizeof(m_libspdm_hash_sweep_info),
                                            cipher_text, cipher_text_size,
                                            tag, entry->tag_size,
                                            plain_text, &plain_text_size));
        assert_int_equal(plain_text_size, sizeof(m_libspdm_hash_sweep_message));
        assert_memory_equal(plain_text, m_libspdm_hash_sweep_message, plain_text_size);

        /* Decryption authenticates the cipher text, so a modified tag is rejected. */
        tag[0] ^= 0x01;
        plain_text_size = sizeof(plain_text);
        assert_false(libspdm_aead_decryption(secured_message_version, entry->aead_cipher_suite,
                                             m_libspdm_hash_sweep_key, entry->key_size,
                                             m_libspdm_hash_sweep_salt, entry->iv_size,
                                             m_libspdm_hash_sweep_info,
                                             sizeof(m_libspdm_hash_sweep_info),
                                             cipher_text, cipher_text_size,
                                             tag, entry->tag_size,
                                             plain_text, &plain_text_size));
    }

    /* Unlike encryption and decryption, which assert on an unknown suite, the size getters return
     * 0. */
    assert_int_equal(libspdm_get_aead_key_size(0), 0);
    assert_int_equal(libspdm_get_aead_iv_size(0), 0);
    assert_int_equal(libspdm_get_aead_tag_size(0), 0);
}

/* The public key and shared secret sizes of each DHE group, or 0 when the group is compiled out. */
typedef struct {
    uint16_t dhe_named_group;
    uint32_t pub_key_size;
    uint32_t shared_secret_size;
} libspdm_dhe_group_entry_t;

static const libspdm_dhe_group_entry_t m_libspdm_dhe_group_table[] = {
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
      LIBSPDM_FFDHE_2048_SUPPORT ? 256 : 0, LIBSPDM_FFDHE_2048_SUPPORT ? 256 : 0 },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
      LIBSPDM_FFDHE_3072_SUPPORT ? 384 : 0, LIBSPDM_FFDHE_3072_SUPPORT ? 384 : 0 },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
      LIBSPDM_FFDHE_4096_SUPPORT ? 512 : 0, LIBSPDM_FFDHE_4096_SUPPORT ? 512 : 0 },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
      LIBSPDM_ECDHE_P256_SUPPORT ? 32 * 2 : 0, LIBSPDM_ECDHE_P256_SUPPORT ? 32 : 0 },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
      LIBSPDM_ECDHE_P384_SUPPORT ? 48 * 2 : 0, LIBSPDM_ECDHE_P384_SUPPORT ? 48 : 0 },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
      LIBSPDM_ECDHE_P521_SUPPORT ? 66 * 2 : 0, LIBSPDM_ECDHE_P521_SUPPORT ? 66 : 0 },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256,
      LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT ? 32 * 2 : 0,
      LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT ? 32 : 0 },
};

static void libspdm_test_crypt_dhe_all_groups(void **state)
{
    size_t index;
    const libspdm_dhe_group_entry_t *entry;
    spdm_version_number_t spdm_version;
    void *initiator;
    void *responder;
    uint8_t initiator_pub_key[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint8_t responder_pub_key[LIBSPDM_MAX_DHE_KEY_SIZE];
    size_t initiator_pub_key_size;
    size_t responder_pub_key_size;
    uint8_t initiator_secret[LIBSPDM_MAX_DHE_SS_SIZE];
    uint8_t responder_secret[LIBSPDM_MAX_DHE_SS_SIZE];
    size_t initiator_secret_size;
    size_t responder_secret_size;

    spdm_version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_dhe_group_table); index++) {
        entry = &m_libspdm_dhe_group_table[index];

        assert_int_equal(libspdm_get_dhe_pub_key_size(entry->dhe_named_group),
                         entry->pub_key_size);
        assert_int_equal(libspdm_get_dhe_shared_secret_size(entry->dhe_named_group),
                         entry->shared_secret_size);

        /* The group is compiled out, so its arms assert rather than dispatch. */
        if (entry->pub_key_size == 0) {
            continue;
        }

        initiator = libspdm_dhe_new(spdm_version, entry->dhe_named_group, true);
        assert_non_null(initiator);
        responder = libspdm_dhe_new(spdm_version, entry->dhe_named_group, false);
        assert_non_null(responder);

        initiator_pub_key_size = sizeof(initiator_pub_key);
        assert_true(libspdm_dhe_generate_key(entry->dhe_named_group, initiator,
                                             initiator_pub_key, &initiator_pub_key_size));
        assert_int_equal(initiator_pub_key_size, entry->pub_key_size);

        responder_pub_key_size = sizeof(responder_pub_key);
        assert_true(libspdm_dhe_generate_key(entry->dhe_named_group, responder,
                                             responder_pub_key, &responder_pub_key_size));
        assert_int_equal(responder_pub_key_size, entry->pub_key_size);

        /* Each side combines its own private key with the other's public key, and both arrive at
         * the same secret. */
        initiator_secret_size = sizeof(initiator_secret);
        assert_true(libspdm_dhe_compute_key(entry->dhe_named_group, initiator,
                                            responder_pub_key, responder_pub_key_size,
                                            initiator_secret, &initiator_secret_size));
        assert_int_equal(initiator_secret_size, entry->shared_secret_size);

        responder_secret_size = sizeof(responder_secret);
        assert_true(libspdm_dhe_compute_key(entry->dhe_named_group, responder,
                                            initiator_pub_key, initiator_pub_key_size,
                                            responder_secret, &responder_secret_size));
        assert_int_equal(responder_secret_size, entry->shared_secret_size);

        assert_memory_equal(initiator_secret, responder_secret, entry->shared_secret_size);

        libspdm_dhe_free(entry->dhe_named_group, initiator);
        libspdm_dhe_free(entry->dhe_named_group, responder);
    }

    /* Unlike the other entry points, which assert on an unknown group, these return benign
     * values. */
    assert_int_equal(libspdm_get_dhe_pub_key_size(0), 0);
    assert_int_equal(libspdm_get_dhe_shared_secret_size(0), 0);
    assert_null(libspdm_dhe_new(spdm_version, 0, true));

    /* Freeing no context does nothing. */
    libspdm_dhe_free(SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, NULL);
}

/* The asymmetric algorithms, the sample_key directory that holds their keys and certificates, the
 * hash algorithm each one signs with, whether SPDM 1.0 and 1.1 define it (SM2 and EdDSA arrived in
 * SPDM 1.2), and its signature size, or 0 when the algorithm is compiled out. */
typedef struct {
    uint32_t base_asym_algo;
    const char *key_dir;
    uint32_t base_hash_algo;
    bool spdm_10_11;
    uint32_t signature_size;
} libspdm_asym_algo_entry_t;

static const libspdm_asym_algo_entry_t m_libspdm_asym_algo_table[] = {
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048, "rsa2048",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_RSA_SSA_2048_SUPPORT ? 256 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048, "rsa2048",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_RSA_PSS_2048_SUPPORT ? 256 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072, "rsa3072",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_RSA_SSA_3072_SUPPORT ? 384 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072, "rsa3072",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_RSA_PSS_3072_SUPPORT ? 384 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096, "rsa4096",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_RSA_SSA_4096_SUPPORT ? 512 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096, "rsa4096",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_RSA_PSS_4096_SUPPORT ? 512 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, "ecp256",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_ECDSA_P256_SUPPORT ? 32 * 2 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384, "ecp384",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_ECDSA_P384_SUPPORT ? 48 * 2 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521, "ecp521",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
      LIBSPDM_ECDSA_P521_SUPPORT ? 66 * 2 : 0 },
    /* The SM2 signature algorithm is defined with SM3. */
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256, "sm2",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256, false,
      LIBSPDM_SM2_DSA_P256_SUPPORT ? 32 * 2 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519, "ed25519",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, false,
      LIBSPDM_EDDSA_ED25519_SUPPORT ? 32 * 2 : 0 },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448, "ed448",
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, false,
      LIBSPDM_EDDSA_ED448_SUPPORT ? 57 * 2 : 0 },
};

/* Reads sample_key/<key_dir>/<file_name>. */
static void libspdm_test_read_key_file(const char *key_dir, const char *file_name,
                                       void **data, size_t *data_size)
{
    char path[64];
    size_t dir_length;
    size_t name_length;

    dir_length = strlen(key_dir);
    name_length = strlen(file_name);
    assert_true(dir_length + 1 + name_length < sizeof(path));

    libspdm_copy_mem(path, sizeof(path), key_dir, dir_length);
    path[dir_length] = '/';
    libspdm_copy_mem(path + dir_length + 1, sizeof(path) - dir_length - 1,
                     file_name, name_length + 1);

    assert_true(libspdm_read_input_file(path, data, data_size));
}

/* The Responder and the Requester sign and verify through separate entry points. These wrappers
 * let one sweep drive either set. */
static bool libspdm_test_asym_sign(bool is_requester, spdm_version_number_t spdm_version,
                                   uint8_t op_code, const libspdm_asym_algo_entry_t *entry,
                                   void *context, const uint8_t *message, size_t message_size,
                                   uint8_t *signature, size_t *sig_size)
{
    if (is_requester) {
        return libspdm_req_asym_sign(spdm_version, op_code, (uint16_t)entry->base_asym_algo,
                                     entry->base_hash_algo, context, message, message_size,
                                     signature, sig_size);
    }
    return libspdm_asym_sign(spdm_version, op_code, entry->base_asym_algo,
                             entry->base_hash_algo, context, message, message_size,
                             signature, sig_size);
}

static bool libspdm_test_asym_sign_hash(bool is_requester, spdm_version_number_t spdm_version,
                                        uint8_t op_code, const libspdm_asym_algo_entry_t *entry,
                                        void *context, const uint8_t *message_hash,
                                        size_t hash_size, uint8_t *signature, size_t *sig_size)
{
    if (is_requester) {
        return libspdm_req_asym_sign_hash(spdm_version, op_code,
                                          (uint16_t)entry->base_asym_algo,
                                          entry->base_hash_algo, context, message_hash,
                                          hash_size, signature, sig_size);
    }
    return libspdm_asym_sign_hash(spdm_version, op_code, entry->base_asym_algo,
                                  entry->base_hash_algo, context, message_hash, hash_size,
                                  signature, sig_size);
}

static bool libspdm_test_asym_verify_ex(bool is_requester, spdm_version_number_t spdm_version,
                                        uint8_t op_code, const libspdm_asym_algo_entry_t *entry,
                                        void *context, const uint8_t *message,
                                        size_t message_size, const uint8_t *signature,
                                        size_t sig_size, uint8_t *endian)
{
    if (is_requester) {
        return libspdm_req_asym_verify_ex(spdm_version, op_code,
                                          (uint16_t)entry->base_asym_algo,
                                          entry->base_hash_algo, context, message, message_size,
                                          signature, sig_size, endian);
    }
    return libspdm_asym_verify_ex(spdm_version, op_code, entry->base_asym_algo,
                                  entry->base_hash_algo, context, message, message_size,
                                  signature, sig_size, endian);
}

static bool libspdm_test_asym_verify(bool is_requester, spdm_version_number_t spdm_version,
                                     uint8_t op_code, const libspdm_asym_algo_entry_t *entry,
                                     void *context, const uint8_t *message, size_t message_size,
                                     const uint8_t *signature, size_t sig_size)
{
    if (is_requester) {
        return libspdm_req_asym_verify(spdm_version, op_code, (uint16_t)entry->base_asym_algo,
                                       entry->base_hash_algo, context, message, message_size,
                                       signature, sig_size);
    }
    return libspdm_asym_verify(spdm_version, op_code, entry->base_asym_algo,
                               entry->base_hash_algo, context, message, message_size,
                               signature, sig_size);
}

static bool libspdm_test_asym_verify_hash(bool is_requester, spdm_version_number_t spdm_version,
                                          uint8_t op_code, const libspdm_asym_algo_entry_t *entry,
                                          void *context, const uint8_t *message_hash,
                                          size_t hash_size, const uint8_t *signature,
                                          size_t sig_size)
{
    if (is_requester) {
        return libspdm_req_asym_verify_hash(spdm_version, op_code,
                                            (uint16_t)entry->base_asym_algo,
                                            entry->base_hash_algo, context, message_hash,
                                            hash_size, signature, sig_size);
    }
    return libspdm_asym_verify_hash(spdm_version, op_code, entry->base_asym_algo,
                                    entry->base_hash_algo, context, message_hash, hash_size,
                                    signature, sig_size);
}

/* Loads the private key, and the public key from both its DER encoding and the leaf certificate,
 * of the given role. */
static void libspdm_test_asym_load_keys(bool is_requester, const libspdm_asym_algo_entry_t *entry,
                                        void **private_context, void **der_context,
                                        void **cert_context)
{
    void *data;
    size_t data_size;

    libspdm_test_read_key_file(entry->key_dir,
                               is_requester ? "end_requester.key" : "end_responder.key",
                               &data, &data_size);
    if (is_requester) {
        assert_true(libspdm_req_asym_get_private_key_from_pem((uint16_t)entry->base_asym_algo,
                                                              data, data_size, NULL,
                                                              private_context));
    } else {
        assert_true(libspdm_asym_get_private_key_from_pem(entry->base_asym_algo,
                                                          data, data_size, NULL,
                                                          private_context));
    }
    libspdm_zero_mem(data, data_size);
    free(data);

    libspdm_test_read_key_file(entry->key_dir,
                               is_requester ? "end_requester.key.pub.der" :
                               "end_responder.key.pub.der",
                               &data, &data_size);
    if (is_requester) {
        assert_true(libspdm_req_asym_get_public_key_from_der((uint16_t)entry->base_asym_algo,
                                                             data, data_size, der_context));
    } else {
        assert_true(libspdm_asym_get_public_key_from_der(entry->base_asym_algo,
                                                         data, data_size, der_context));
    }
    free(data);

    libspdm_test_read_key_file(entry->key_dir,
                               is_requester ? "end_requester.cert.der" : "end_responder.cert.der",
                               &data, &data_size);
    if (is_requester) {
        assert_true(libspdm_req_asym_get_public_key_from_x509((uint16_t)entry->base_asym_algo,
                                                              data, data_size, cert_context));
    } else {
        assert_true(libspdm_asym_get_public_key_from_x509(entry->base_asym_algo,
                                                          data, data_size, cert_context));
    }
    free(data);
}

/* SPDM 1.0 and 1.1 sign the digest of the message itself. A signature may also arrive in
 * little-endian order, which verification can be told to accept. */
static void libspdm_test_asym_sweep_spdm_11(bool is_requester,
                                            const libspdm_asym_algo_entry_t *entry,
                                            void *private_context, void *der_context,
                                            void *cert_context)
{
    spdm_version_number_t spdm_version;
    uint8_t op_code;
    uint8_t message[sizeof(m_libspdm_hash_sweep_message)];
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t hash_size;
    uint8_t signature[LIBSPDM_MAX_ASYM_SIG_SIZE];
    uint8_t swapped_signature[LIBSPDM_MAX_ASYM_SIG_SIZE];
    size_t sig_size;
    uint8_t endian;

    spdm_version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    op_code = is_requester ? SPDM_FINISH : SPDM_MEASUREMENTS;
    hash_size = libspdm_get_hash_size(entry->base_hash_algo);
    assert_true(libspdm_hash_all(entry->base_hash_algo, m_libspdm_hash_sweep_message,
                                 sizeof(m_libspdm_hash_sweep_message), message_hash));

    /* A signature over the message verifies against the message and against its digest, with
     * either public key. */
    sig_size = sizeof(signature);
    assert_true(libspdm_test_asym_sign(is_requester, spdm_version, op_code, entry,
                                       private_context, m_libspdm_hash_sweep_message,
                                       sizeof(m_libspdm_hash_sweep_message),
                                       signature, &sig_size));
    assert_int_equal(sig_size, entry->signature_size);
    assert_true(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry, der_context,
                                         m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         signature, sig_size));
    assert_true(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry,
                                         cert_context, m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         signature, sig_size));
    assert_true(libspdm_test_asym_verify_hash(is_requester, spdm_version, op_code, entry,
                                              der_context, message_hash, hash_size,
                                              signature, sig_size));

    /* The signature does not cover a different message. */
    libspdm_copy_mem(message, sizeof(message), m_libspdm_hash_sweep_message,
                     sizeof(m_libspdm_hash_sweep_message));
    message[0] ^= 0x01;
    assert_false(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry,
                                          der_context, message, sizeof(message),
                                          signature, sig_size));

    /* Accepting either order detects the order of the signature. */
    endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    assert_true(libspdm_test_asym_verify_ex(is_requester, spdm_version, op_code, entry,
                                            der_context, m_libspdm_hash_sweep_message,
                                            sizeof(m_libspdm_hash_sweep_message),
                                            signature, sig_size, &endian));
    assert_int_equal(endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY);

    libspdm_copy_signature_swap_endian(entry->base_asym_algo,
                                       swapped_signature, sizeof(swapped_signature),
                                       signature, sig_size);

    endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    assert_true(libspdm_test_asym_verify_ex(is_requester, spdm_version, op_code, entry,
                                            der_context, m_libspdm_hash_sweep_message,
                                            sizeof(m_libspdm_hash_sweep_message),
                                            swapped_signature, sig_size, &endian));
    assert_int_equal(endian, LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY);

    endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;
    assert_true(libspdm_test_asym_verify_ex(is_requester, spdm_version, op_code, entry,
                                            der_context, m_libspdm_hash_sweep_message,
                                            sizeof(m_libspdm_hash_sweep_message),
                                            swapped_signature, sig_size, &endian));

    endian = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;
    assert_false(libspdm_test_asym_verify_ex(is_requester, spdm_version, op_code, entry,
                                             der_context, m_libspdm_hash_sweep_message,
                                             sizeof(m_libspdm_hash_sweep_message),
                                             swapped_signature, sig_size, &endian));

    /* A signature over the digest verifies against the message. */
    sig_size = sizeof(signature);
    assert_true(libspdm_test_asym_sign_hash(is_requester, spdm_version, op_code, entry,
                                            private_context, message_hash, hash_size,
                                            signature, &sig_size));
    assert_int_equal(sig_size, entry->signature_size);
    assert_true(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry, der_context,
                                         m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         signature, sig_size));
}

/* SPDM 1.2 and later sign a signing context, which names the SPDM version and the message that
 * carries the signature, followed by the digest of the message. */
static void libspdm_test_asym_sweep_spdm_12(bool is_requester,
                                            const libspdm_asym_algo_entry_t *entry,
                                            void *private_context, void *der_context,
                                            void *cert_context)
{
    spdm_version_number_t spdm_version;
    uint8_t op_code;
    uint8_t other_op_code;
    uint8_t message[sizeof(m_libspdm_hash_sweep_message)];
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t hash_size;
    uint8_t signature[LIBSPDM_MAX_ASYM_SIG_SIZE];
    size_t sig_size;

    spdm_version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    op_code = is_requester ? SPDM_FINISH : SPDM_MEASUREMENTS;
    other_op_code = SPDM_CHALLENGE_AUTH;
    hash_size = libspdm_get_hash_size(entry->base_hash_algo);
    assert_true(libspdm_hash_all(entry->base_hash_algo, m_libspdm_hash_sweep_message,
                                 sizeof(m_libspdm_hash_sweep_message), message_hash));

    sig_size = sizeof(signature);
    assert_true(libspdm_test_asym_sign(is_requester, spdm_version, op_code, entry,
                                       private_context, m_libspdm_hash_sweep_message,
                                       sizeof(m_libspdm_hash_sweep_message),
                                       signature, &sig_size));
    assert_int_equal(sig_size, entry->signature_size);
    assert_true(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry, der_context,
                                         m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         signature, sig_size));
    assert_true(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry,
                                         cert_context, m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         signature, sig_size));
    assert_true(libspdm_test_asym_verify_hash(is_requester, spdm_version, op_code, entry,
                                              der_context, message_hash, hash_size,
                                              signature, sig_size));

    /* The signature does not cover a different message, another message's signing context, or
     * another SPDM version's. */
    libspdm_copy_mem(message, sizeof(message), m_libspdm_hash_sweep_message,
                     sizeof(m_libspdm_hash_sweep_message));
    message[0] ^= 0x01;
    assert_false(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry,
                                          der_context, message, sizeof(message),
                                          signature, sig_size));
    assert_false(libspdm_test_asym_verify(is_requester, spdm_version, other_op_code, entry,
                                          der_context, m_libspdm_hash_sweep_message,
                                          sizeof(m_libspdm_hash_sweep_message),
                                          signature, sig_size));
    assert_false(libspdm_test_asym_verify(is_requester,
                                          SPDM_MESSAGE_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
                                          op_code, entry, der_context,
                                          m_libspdm_hash_sweep_message,
                                          sizeof(m_libspdm_hash_sweep_message),
                                          signature, sig_size));

    /* A signature over the digest verifies against the message. */
    sig_size = sizeof(signature);
    assert_true(libspdm_test_asym_sign_hash(is_requester, spdm_version, op_code, entry,
                                            private_context, message_hash, hash_size,
                                            signature, &sig_size));
    assert_int_equal(sig_size, entry->signature_size);
    assert_true(libspdm_test_asym_verify(is_requester, spdm_version, op_code, entry, der_context,
                                         m_libspdm_hash_sweep_message,
                                         sizeof(m_libspdm_hash_sweep_message),
                                         signature, sig_size));
}

static void libspdm_test_asym_sweep(bool is_requester)
{
    size_t index;
    const libspdm_asym_algo_entry_t *entry;
    uint32_t signature_size;
    void *private_context;
    void *der_context;
    void *cert_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_asym_algo_table); index++) {
        entry = &m_libspdm_asym_algo_table[index];

        if (is_requester) {
            signature_size =
                libspdm_get_req_asym_signature_size((uint16_t)entry->base_asym_algo);
        } else {
            signature_size = libspdm_get_asym_signature_size(entry->base_asym_algo);
        }
        assert_int_equal(signature_size, entry->signature_size);

        /* The algorithm is compiled out, so its arms assert rather than dispatch. */
        if (entry->signature_size == 0) {
            continue;
        }

        libspdm_test_asym_load_keys(is_requester, entry,
                                    &private_context, &der_context, &cert_context);

        if (entry->spdm_10_11) {
            libspdm_test_asym_sweep_spdm_11(is_requester, entry,
                                            private_context, der_context, cert_context);
        }
        libspdm_test_asym_sweep_spdm_12(is_requester, entry,
                                        private_context, der_context, cert_context);

        if (is_requester) {
            libspdm_req_asym_free((uint16_t)entry->base_asym_algo, private_context);
            libspdm_req_asym_free((uint16_t)entry->base_asym_algo, der_context);
            libspdm_req_asym_free((uint16_t)entry->base_asym_algo, cert_context);
        } else {
            libspdm_asym_free(entry->base_asym_algo, private_context);
            libspdm_asym_free(entry->base_asym_algo, der_context);
            libspdm_asym_free(entry->base_asym_algo, cert_context);
        }
    }

    /* Unlike the other entry points, which assert on an unknown algorithm, the size getter
     * returns 0. */
    if (is_requester) {
        assert_int_equal(libspdm_get_req_asym_signature_size(0), 0);
    } else {
        assert_int_equal(libspdm_get_asym_signature_size(0), 0);
    }
}

/* The signing contexts of DSP0274, one for each signer and message that carries a signature. */
typedef struct {
    bool is_requester;
    uint8_t op_code;
    const char *spdm_context;
} libspdm_signing_context_entry_t;

static const libspdm_signing_context_entry_t m_libspdm_signing_context_table[] = {
    { false, SPDM_CHALLENGE_AUTH, "responder-challenge_auth signing" },
    { true, SPDM_CHALLENGE_AUTH, "requester-challenge_auth signing" },
    { false, SPDM_MEASUREMENTS, "responder-measurements signing" },
    { false, SPDM_KEY_EXCHANGE_RSP, "responder-key_exchange_rsp signing" },
    { true, SPDM_FINISH, "requester-finish signing" },
    { false, SPDM_ENDPOINT_INFO, "responder-endpoint_info signing" },
    { true, SPDM_ENDPOINT_INFO, "requester-endpoint_info signing" },
};

static void libspdm_test_crypt_signing_context(void **state)
{
    static const uint8_t versions[] = {
        SPDM_MESSAGE_VERSION_12, SPDM_MESSAGE_VERSION_13, SPDM_MESSAGE_VERSION_14
    };
    size_t version_index;
    size_t index;
    const libspdm_signing_context_entry_t *entry;
    spdm_version_number_t spdm_version;
    const void *context;
    size_t context_size;
    size_t spdm_context_size;
    uint8_t expected[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE];
    uint8_t actual[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE];
    uint8_t *prefix;
    size_t repeat;

    /* combined_spdm_prefix is 100 bytes: spdm_prefix, which is "dmtf-spdm-v<version>.*" four
     * times, then zeros, then spdm_context at the end. */
    assert_int_equal(SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE, 100);

    for (version_index = 0; version_index < LIBSPDM_ARRAY_SIZE(versions); version_index++) {
        spdm_version = (spdm_version_number_t)versions[version_index] <<
                       SPDM_VERSION_NUMBER_SHIFT_BIT;

        for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_signing_context_table); index++) {
            entry = &m_libspdm_signing_context_table[index];
            spdm_context_size = strlen(entry->spdm_context);

            context = libspdm_get_signing_context_string(spdm_version, entry->op_code,
                                                         entry->is_requester, &context_size);
            assert_int_equal(context_size, spdm_context_size);
            assert_memory_equal(context, entry->spdm_context, spdm_context_size);

            libspdm_zero_mem(expected, sizeof(expected));
            for (repeat = 0; repeat < 4; repeat++) {
                prefix = expected + repeat * 16;
                libspdm_copy_mem(prefix, 16, "dmtf-spdm-v", 11);
                prefix[11] = (uint8_t)('0' + (versions[version_index] >> 4));
                prefix[12] = '.';
                prefix[13] = (uint8_t)('0' + (versions[version_index] & 0xF));
                prefix[14] = '.';
                prefix[15] = '*';
            }
            libspdm_copy_mem(expected + sizeof(expected) - spdm_context_size, spdm_context_size,
                             entry->spdm_context, spdm_context_size);

            libspdm_set_mem(actual, sizeof(actual), 0xFF);
            libspdm_create_signing_context(spdm_version, entry->op_code, entry->is_requester,
                                           actual);
            assert_memory_equal(actual, expected, sizeof(expected));
        }
    }
}

static void libspdm_test_crypt_asym_all_algos(void **state)
{
    libspdm_test_asym_sweep(false);
}

static void libspdm_test_crypt_req_asym_all_algos(void **state)
{
    libspdm_test_asym_sweep(true);
}

/* The signature sizes of FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), or 0 when the parameter set is
 * compiled out. */
typedef struct {
    uint32_t pqc_asym_algo;
    uint32_t signature_size;
} libspdm_pqc_asym_algo_entry_t;

static const libspdm_pqc_asym_algo_entry_t m_libspdm_pqc_asym_algo_table[] = {
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44, LIBSPDM_ML_DSA_44_SUPPORT ? 2420 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65, LIBSPDM_ML_DSA_65_SUPPORT ? 3309 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87, LIBSPDM_ML_DSA_87_SUPPORT ? 4627 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S,
      LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT ? 7856 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S,
      LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT ? 7856 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F,
      LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT ? 17088 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F,
      LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT ? 17088 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S,
      LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT ? 16224 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S,
      LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT ? 16224 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F,
      LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT ? 35664 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F,
      LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT ? 35664 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S,
      LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT ? 29792 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S,
      LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT ? 29792 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F,
      LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT ? 49856 : 0 },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F,
      LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT ? 49856 : 0 },
};

static void libspdm_test_crypt_pqc_asym_signature_size(void **state)
{
    size_t index;
    const libspdm_pqc_asym_algo_entry_t *entry;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_pqc_asym_algo_table); index++) {
        entry = &m_libspdm_pqc_asym_algo_table[index];

        assert_int_equal(libspdm_get_pqc_asym_signature_size(entry->pqc_asym_algo),
                         entry->signature_size);
        assert_int_equal(libspdm_get_req_pqc_asym_signature_size(entry->pqc_asym_algo),
                         entry->signature_size);
    }

    /* Unlike the other entry points, which assert on an unknown algorithm, the size getters
     * return 0. */
    assert_int_equal(libspdm_get_pqc_asym_signature_size(0), 0);
    assert_int_equal(libspdm_get_req_pqc_asym_signature_size(0), 0);

    /* Freeing no context does nothing. */
    libspdm_pqc_asym_free(SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44, NULL);
    libspdm_req_pqc_asym_free(SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44, NULL);
}

/* The encapsulation key, cipher text and shared secret sizes of FIPS 203 (ML-KEM), or 0 when the
 * parameter set is compiled out. */
typedef struct {
    uint32_t kem_alg;
    uint32_t encap_key_size;
    uint32_t cipher_text_size;
    uint32_t shared_secret_size;
} libspdm_kem_algo_entry_t;

static const libspdm_kem_algo_entry_t m_libspdm_kem_algo_table[] = {
    { SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512, LIBSPDM_ML_KEM_512_SUPPORT ? 800 : 0,
      LIBSPDM_ML_KEM_512_SUPPORT ? 768 : 0, LIBSPDM_ML_KEM_512_SUPPORT ? 32 : 0 },
    { SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768, LIBSPDM_ML_KEM_768_SUPPORT ? 1184 : 0,
      LIBSPDM_ML_KEM_768_SUPPORT ? 1088 : 0, LIBSPDM_ML_KEM_768_SUPPORT ? 32 : 0 },
    { SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024, LIBSPDM_ML_KEM_1024_SUPPORT ? 1568 : 0,
      LIBSPDM_ML_KEM_1024_SUPPORT ? 1568 : 0, LIBSPDM_ML_KEM_1024_SUPPORT ? 32 : 0 },
};

static void libspdm_test_crypt_kem_all_algos(void **state)
{
    size_t index;
    const libspdm_kem_algo_entry_t *entry;
    spdm_version_number_t spdm_version;
    void *initiator;
    void *responder;
    uint8_t encap_key[LIBSPDM_MAX_KEM_ENCAP_KEY_SIZE];
    size_t encap_key_size;
    uint8_t cipher_text[LIBSPDM_MAX_KEM_CT_SIZE];
    size_t cipher_text_size;
    uint8_t initiator_secret[LIBSPDM_MAX_KEM_SS_SIZE];
    uint8_t responder_secret[LIBSPDM_MAX_KEM_SS_SIZE];
    size_t initiator_secret_size;
    size_t responder_secret_size;

    spdm_version = SPDM_MESSAGE_VERSION_14 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_kem_algo_table); index++) {
        entry = &m_libspdm_kem_algo_table[index];

        assert_int_equal(libspdm_get_kem_encap_key_size(entry->kem_alg), entry->encap_key_size);
        assert_int_equal(libspdm_get_kem_cipher_text_size(entry->kem_alg),
                         entry->cipher_text_size);
        assert_int_equal(libspdm_get_kem_shared_secret_size(entry->kem_alg),
                         entry->shared_secret_size);

        /* The parameter set is compiled out, so its arms assert rather than dispatch. */
        if (entry->encap_key_size == 0) {
            continue;
        }

        initiator = libspdm_kem_new(spdm_version, entry->kem_alg, true);
        assert_non_null(initiator);
        responder = libspdm_kem_new(spdm_version, entry->kem_alg, false);
        assert_non_null(responder);

        /* The initiator publishes an encapsulation key, the responder encapsulates a secret to
         * it, and the initiator decapsulates the same secret. */
        encap_key_size = sizeof(encap_key);
        assert_true(libspdm_kem_generate_key(entry->kem_alg, initiator,
                                             encap_key, &encap_key_size));
        assert_int_equal(encap_key_size, entry->encap_key_size);

        cipher_text_size = sizeof(cipher_text);
        responder_secret_size = sizeof(responder_secret);
        assert_true(libspdm_kem_encapsulate(entry->kem_alg, responder,
                                            encap_key, encap_key_size,
                                            cipher_text, &cipher_text_size,
                                            responder_secret, &responder_secret_size));
        assert_int_equal(cipher_text_size, entry->cipher_text_size);
        assert_int_equal(responder_secret_size, entry->shared_secret_size);

        initiator_secret_size = sizeof(initiator_secret);
        assert_true(libspdm_kem_decapsulate(entry->kem_alg, initiator,
                                            cipher_text, cipher_text_size,
                                            initiator_secret, &initiator_secret_size));
        assert_int_equal(initiator_secret_size, entry->shared_secret_size);

        assert_memory_equal(initiator_secret, responder_secret, entry->shared_secret_size);

        libspdm_kem_free(entry->kem_alg, initiator);
        libspdm_kem_free(entry->kem_alg, responder);
    }

    /* Unlike the other entry points, which assert on an unknown algorithm, these return benign
     * values. */
    assert_int_equal(libspdm_get_kem_encap_key_size(0), 0);
    assert_int_equal(libspdm_get_kem_cipher_text_size(0), 0);
    assert_int_equal(libspdm_get_kem_shared_secret_size(0), 0);
    assert_null(libspdm_kem_new(spdm_version, 0, true));

    /* Freeing no context does nothing. */
    libspdm_kem_free(SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512, NULL);
}

static void libspdm_test_crypt_x509_certificate_check_all_algos(void **state)
{
    size_t cert_index;
    size_t algo_index;
    const libspdm_asym_algo_entry_t *cert_entry;
    const libspdm_asym_algo_entry_t *algo_entry;
    void *cert;
    size_t cert_size;
    bool expected;

    for (cert_index = 0; cert_index < LIBSPDM_ARRAY_SIZE(m_libspdm_asym_algo_table);
         cert_index++) {
        cert_entry = &m_libspdm_asym_algo_table[cert_index];

        /* The RSA signature schemes share their keys, and so their certificates. */
        if ((cert_index > 0) &&
            (strcmp(cert_entry->key_dir, m_libspdm_asym_algo_table[cert_index - 1].key_dir) ==
             0)) {
            continue;
        }

        libspdm_test_read_key_file(cert_entry->key_dir, "end_responder.cert.der",
                                   &cert, &cert_size);

        /* The leaf certificate passes the check only for the algorithms that use its key. */
        for (algo_index = 0; algo_index < LIBSPDM_ARRAY_SIZE(m_libspdm_asym_algo_table);
             algo_index++) {
            algo_entry = &m_libspdm_asym_algo_table[algo_index];

            /* The check skips the public key algorithm for SM2 and extracts the key, which
             * asserts when SM2 is compiled out. */
            if ((algo_entry->base_asym_algo ==
                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256) &&
                (algo_entry->signature_size == 0)) {
                continue;
            }

            expected = (strcmp(algo_entry->key_dir, cert_entry->key_dir) == 0) &&
                       (algo_entry->signature_size != 0);
            assert_int_equal(libspdm_x509_certificate_check(
                                 SPDM_MESSAGE_VERSION_12, cert, cert_size,
                                 algo_entry->base_asym_algo, 0,
                                 SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                 false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT),
                             expected);
        }

        /* None of the certificates holds a PQC key. */
        for (algo_index = 0; algo_index < LIBSPDM_ARRAY_SIZE(m_libspdm_pqc_asym_algo_table);
             algo_index++) {
            assert_false(libspdm_x509_certificate_check(
                             SPDM_MESSAGE_VERSION_12, cert, cert_size,
                             0, m_libspdm_pqc_asym_algo_table[algo_index].pqc_asym_algo,
                             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                             false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
        }

        free(cert);
    }
}

static void libspdm_test_crypt_no_certificate(void **state)
{
    assert_false(libspdm_x509_certificate_check(
                     SPDM_MESSAGE_VERSION_12, NULL, 0,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
    assert_false(libspdm_x509_set_cert_certificate_check(
                     SPDM_MESSAGE_VERSION_12, NULL, 0,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
    assert_false(libspdm_is_root_certificate(NULL, 0));
}

static void libspdm_test_crypt_responder_certificate_eku(void **state)
{
#if LIBSPDM_RSA_SSA_2048_SUPPORT
    void *cert;
    size_t cert_size;

    /* A Responder certificate may carry the Responder authentication EKU, with or without the
     * Requester one, but not the Requester one alone. */
    libspdm_test_read_key_file("rsa2048", "end_responder_with_spdm_rsp_eku.cert.der",
                               &cert, &cert_size);
    assert_true(libspdm_x509_certificate_check(
                    SPDM_MESSAGE_VERSION_12, cert, cert_size,
                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048, 0,
                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                    false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
    free(cert);

    libspdm_test_read_key_file("rsa2048", "end_responder_with_spdm_req_eku.cert.der",
                               &cert, &cert_size);
    assert_false(libspdm_x509_certificate_check(
                     SPDM_MESSAGE_VERSION_12, cert, cert_size,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048, 0,
                     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
    free(cert);
#else
    skip();
#endif /* LIBSPDM_RSA_SSA_2048_SUPPORT */
}

static void libspdm_test_crypt_is_root_certificate(void **state)
{
    void *cert;
    size_t cert_size;

    /* Only the self-signed CA certificate at the top of the chain is a root. */
    libspdm_test_read_key_file("ecp256", "ca.cert.der", &cert, &cert_size);
    assert_true(libspdm_is_root_certificate(cert, cert_size));
    free(cert);

    libspdm_test_read_key_file("ecp256", "inter.cert.der", &cert, &cert_size);
    assert_false(libspdm_is_root_certificate(cert, cert_size));
    free(cert);

    libspdm_test_read_key_file("ecp256", "end_responder.cert.der", &cert, &cert_size);
    assert_false(libspdm_is_root_certificate(cert, cert_size));
    free(cert);
}

static void libspdm_test_crypt_spdm_get_dmtf_subject_alt_name_buffer_size(void **state)
{
    size_t common_name_size;
    char common_name[64];
    size_t dmtf_oid_size;
    uint8_t dmtf_oid[64];
    uint8_t not_a_sequence[sizeof(m_libspdm_subject_alt_name_buffer1)];
    void *cert;
    size_t cert_size;
    size_t needed_size;

    /* A buffer that is too small is reported with the size that it needs. The name needs room
     * for a terminating NUL. */
    common_name_size = sizeof(common_name);
    dmtf_oid_size = sizeof(m_libspdm_dmtf_oid) - 1;
    assert_false(libspdm_get_dmtf_subject_alt_name_from_bytes(
                     m_libspdm_subject_alt_name_buffer1,
                     sizeof(m_libspdm_subject_alt_name_buffer1),
                     common_name, &common_name_size, dmtf_oid, &dmtf_oid_size));
    assert_int_equal(dmtf_oid_size, sizeof(m_libspdm_dmtf_oid));

    common_name_size = strlen("ACME:WIDGET:1234567890");
    dmtf_oid_size = sizeof(dmtf_oid);
    assert_false(libspdm_get_dmtf_subject_alt_name_from_bytes(
                     m_libspdm_subject_alt_name_buffer1,
                     sizeof(m_libspdm_subject_alt_name_buffer1),
                     common_name, &common_name_size, dmtf_oid, &dmtf_oid_size));
    assert_int_equal(common_name_size, strlen("ACME:WIDGET:1234567890") + 1);

    /* There is nowhere to put the name. */
    common_name_size = sizeof(common_name);
    dmtf_oid_size = sizeof(dmtf_oid);
    assert_false(libspdm_get_dmtf_subject_alt_name_from_bytes(
                     m_libspdm_subject_alt_name_buffer1,
                     sizeof(m_libspdm_subject_alt_name_buffer1),
                     NULL, &common_name_size, dmtf_oid, &dmtf_oid_size));

    /* The encoding is a SET rather than a SEQUENCE. */
    libspdm_copy_mem(not_a_sequence, sizeof(not_a_sequence),
                     m_libspdm_subject_alt_name_buffer1,
                     sizeof(m_libspdm_subject_alt_name_buffer1));
    not_a_sequence[0] = 0x31;
    common_name_size = sizeof(common_name);
    dmtf_oid_size = sizeof(dmtf_oid);
    assert_false(libspdm_get_dmtf_subject_alt_name_from_bytes(
                     not_a_sequence, sizeof(not_a_sequence),
                     common_name, &common_name_size, dmtf_oid, &dmtf_oid_size));

    /* A certificate without a subject alternative name has no name to return. */
    libspdm_test_read_key_file("ecp256", "ca.cert.der", &cert, &cert_size);
    common_name_size = sizeof(common_name);
    dmtf_oid_size = sizeof(dmtf_oid);
    assert_false(libspdm_get_dmtf_subject_alt_name(cert, cert_size, common_name,
                                                   &common_name_size,
                                                   dmtf_oid, &dmtf_oid_size));
    assert_int_equal(common_name_size, 0);
    free(cert);

    /* A name buffer smaller than the extension is reported with the extension's size, which then
     * suffices. */
    libspdm_test_read_key_file("ecp256", "end_requester.cert.der", &cert, &cert_size);
    common_name_size = 1;
    dmtf_oid_size = sizeof(dmtf_oid);
    assert_false(libspdm_get_dmtf_subject_alt_name(cert, cert_size, common_name,
                                                   &common_name_size,
                                                   dmtf_oid, &dmtf_oid_size));
    needed_size = common_name_size;
    assert_true(needed_size > 1);
    assert_true(needed_size <= sizeof(common_name));
    assert_true(libspdm_get_dmtf_subject_alt_name(cert, cert_size, common_name,
                                                  &common_name_size,
                                                  dmtf_oid, &dmtf_oid_size));
    assert_string_equal(common_name, "ACME:WIDGET:1234567890");
    free(cert);
}

static void libspdm_test_crypt_spdm_verify_cert_chain_data_malformed(void **state)
{
    uint8_t *cert_chain_data;
    size_t cert_chain_data_size;
    uint8_t not_a_certificate[64];

    /* A chain longer than a certificate chain can be once its header and root hash are added. */
    cert_chain_data_size = SPDM_MAX_CERTIFICATE_CHAIN_SIZE -
                           (sizeof(spdm_cert_chain_t) + LIBSPDM_MAX_HASH_SIZE) + 1;
    cert_chain_data = calloc(1, cert_chain_data_size);
    assert_non_null(cert_chain_data);
    assert_false(libspdm_verify_cert_chain_data(
                     SPDM_MESSAGE_VERSION_13, cert_chain_data, cert_chain_data_size,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
    free(cert_chain_data);

    /* Bytes that do not hold a certificate. */
    libspdm_set_mem(not_a_certificate, sizeof(not_a_certificate), 0xFF);
    assert_false(libspdm_verify_cert_chain_data(
                     SPDM_MESSAGE_VERSION_13, not_a_certificate, sizeof(not_a_certificate),
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
}

static void libspdm_test_crypt_spdm_verify_certificate_chain_buffer_malformed(void **state)
{
#if (LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t buffer[sizeof(spdm_cert_chain_t) + LIBSPDM_MAX_HASH_SIZE + 64];
    spdm_cert_chain_t *cert_chain_header;
    size_t hash_size;
    size_t buffer_size;
    void *data;
    size_t data_size;

    hash_size = libspdm_get_hash_size(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256);
    cert_chain_header = (spdm_cert_chain_t *)buffer;

    /* The buffer holds the header and the root hash, but no certificate. */
    libspdm_zero_mem(buffer, sizeof(buffer));
    buffer_size = sizeof(spdm_cert_chain_t) + hash_size;
    cert_chain_header->length = (uint16_t)buffer_size;
    assert_false(libspdm_verify_certificate_chain_buffer(
                     SPDM_MESSAGE_VERSION_13, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     buffer, buffer_size, false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));

    /* The bytes after the header and the root hash do not hold a certificate. */
    buffer_size = sizeof(spdm_cert_chain_t) + hash_size + 64;
    libspdm_set_mem(buffer + sizeof(spdm_cert_chain_t) + hash_size, 64, 0xFF);
    cert_chain_header->length = (uint16_t)buffer_size;
    assert_false(libspdm_verify_certificate_chain_buffer(
                     SPDM_MESSAGE_VERSION_13, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     buffer, buffer_size, false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));

    /* The root hash does not match the root certificate. */
    assert_true(libspdm_read_responder_public_certificate_chain(
                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                    &data, &data_size, NULL, NULL));
    ((uint8_t *)data)[sizeof(spdm_cert_chain_t)] ^= 0x01;
    assert_false(libspdm_verify_certificate_chain_buffer(
                     SPDM_MESSAGE_VERSION_13, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
                     data, data_size, false, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT));
    free(data);
#else
    skip();
#endif /* (LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT) */
}

static void libspdm_test_crypt_verify_req_info(void **state)
{
    /* A CertificationRequestInfo is a SEQUENCE of an INTEGER version, a subject SEQUENCE, a
     * subjectPKInfo SEQUENCE and [0] attributes, which libspdm checks for structure alone. */
    uint8_t no_attributes[] = {
        0x30, 0x09, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00, 0xA0, 0x00
    };
    uint8_t one_attribute[] = {
        0x30, 0x0B, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00, 0xA0, 0x02, 0x30, 0x00
    };
    uint8_t trailing_byte[] = {
        0x30, 0x09, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00, 0xA0, 0x00, 0x05
    };
    uint8_t not_a_sequence[] = { 0x31, 0x00 };
    uint8_t no_version[] = { 0x30, 0x02, 0x30, 0x00 };
    uint8_t no_subject[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    uint8_t no_subject_pk_info[] = { 0x30, 0x05, 0x02, 0x01, 0x00, 0x30, 0x00 };
    uint8_t no_attributes_tag[] = { 0x30, 0x07, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00 };

    /* Requester info is optional. */
    assert_true(libspdm_verify_req_info(no_attributes, 0));

    assert_true(libspdm_verify_req_info(no_attributes, sizeof(no_attributes)));
    assert_true(libspdm_verify_req_info(one_attribute, sizeof(one_attribute)));

    assert_false(libspdm_verify_req_info(trailing_byte, sizeof(trailing_byte)));
    assert_false(libspdm_verify_req_info(not_a_sequence, sizeof(not_a_sequence)));
    assert_false(libspdm_verify_req_info(no_version, sizeof(no_version)));
    assert_false(libspdm_verify_req_info(no_subject, sizeof(no_subject)));
    assert_false(libspdm_verify_req_info(no_subject_pk_info, sizeof(no_subject_pk_info)));
    assert_false(libspdm_verify_req_info(no_attributes_tag, sizeof(no_attributes_tag)));
}

static int libspdm_crypt_lib_setup(void **state)
{
    return 0;
}

static int libspdm_crypt_lib_teardown(void **state)
{
    return 0;
}

static int libspdm_crypt_lib_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_crypt_spdm_get_dmtf_subject_alt_name_from_bytes),
        cmocka_unit_test(libspdm_test_crypt_spdm_get_dmtf_subject_alt_name),
        cmocka_unit_test(libspdm_test_crypt_spdm_x509_certificate_check),
        cmocka_unit_test(libspdm_test_crypt_spdm_x509_set_cert_certificate_check),
        cmocka_unit_test(libspdm_test_crypt_spdm_verify_cert_chain_data),
        cmocka_unit_test(libspdm_test_crypt_spdm_verify_certificate_chain_buffer),
        cmocka_unit_test(libspdm_test_crypt_asym_verify),
        cmocka_unit_test(libspdm_test_crypt_req_asym_verify),
        cmocka_unit_test(libspdm_test_crypt_palindrome),
        cmocka_unit_test(libspdm_test_crypt_rsa_palindrome),
        cmocka_unit_test(libspdm_test_crypt_ecdsa_palindrome),
        cmocka_unit_test(libspdm_test_crypt_hash_size_and_nid),
        cmocka_unit_test(libspdm_test_crypt_hash_all_algos),
        cmocka_unit_test(libspdm_test_crypt_hmac_all_algos),
        cmocka_unit_test(libspdm_test_crypt_hkdf_all_algos),
        cmocka_unit_test(libspdm_test_crypt_aead_all_suites),
        cmocka_unit_test(libspdm_test_crypt_dhe_all_groups),
        cmocka_unit_test(libspdm_test_crypt_signing_context),
        cmocka_unit_test(libspdm_test_crypt_asym_all_algos),
        cmocka_unit_test(libspdm_test_crypt_req_asym_all_algos),
        cmocka_unit_test(libspdm_test_crypt_pqc_asym_signature_size),
        cmocka_unit_test(libspdm_test_crypt_kem_all_algos),
        cmocka_unit_test(libspdm_test_crypt_x509_certificate_check_all_algos),
        cmocka_unit_test(libspdm_test_crypt_no_certificate),
        cmocka_unit_test(libspdm_test_crypt_responder_certificate_eku),
        cmocka_unit_test(libspdm_test_crypt_is_root_certificate),
        cmocka_unit_test(libspdm_test_crypt_spdm_get_dmtf_subject_alt_name_buffer_size),
        cmocka_unit_test(libspdm_test_crypt_spdm_verify_cert_chain_data_malformed),
        cmocka_unit_test(libspdm_test_crypt_spdm_verify_certificate_chain_buffer_malformed),
        cmocka_unit_test(libspdm_test_crypt_verify_req_info),
    };

    return cmocka_run_group_tests(test_cases,
                                  libspdm_crypt_lib_setup,
                                  libspdm_crypt_lib_teardown);
}

int main(void)
{
    int return_value = 0;

    if (libspdm_crypt_lib_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
