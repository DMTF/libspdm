/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"

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

bool check_length(void *data, size_t data_len, size_t *length, size_t *byte_consumed,
                  bool is_increase_length) {
    uint8_t *length_byte;
    size_t combined;

    if (data == NULL || length == NULL || byte_consumed == NULL || data_len < 1) {
        return false;
    }

    length_byte = (uint8_t *)data;

    if ((length_byte[0] & 0x80) == 0) {
        *length = length_byte[0];
        *byte_consumed = 1;
    } else if(length_byte[0] == 0x81) {
        if (data_len < 2) {
            return false;
        }

        if(is_increase_length ) {
            length_byte[1]++;
        }

        if (length_byte[1] < 0x80) {
            return false;
        }

        *length = (size_t)length_byte[1];
        *byte_consumed = 2;
    } else if (length_byte[0] == 0x82) {
        if (data_len < 3) {
            return false;
        }

        if(is_increase_length ) {
            length_byte[2]++;
        }

        combined = (size_t)(length_byte[1] << 8) | length_byte[2];

        if (combined < 0x100) {
            return false;
        }

        *length = combined;
        *byte_consumed = 3;
    } else {
        return false;
    }

    return true;
}

bool convert_normalized_to_non_normalized(uint8_t *data, size_t *data_length) {
    size_t payload_length;
    size_t bytes_consumed;
    size_t index;
    size_t length;
    uint8_t temp[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    length = *data_length;

    /* Certificate SEQUENCE */
    index = 1;
    check_length(data + index, length, &payload_length, &bytes_consumed, false);

    if (length < 1 + payload_length + bytes_consumed) {
        return false;
    }

    /* tbsCertificate TBSCertificate SEQUENCE*/
    index += 1 + bytes_consumed;
    check_length(data + index, length - index, &payload_length, &bytes_consumed, false);

    index += 1 + bytes_consumed;
    check_length(data + index, length - index, &payload_length, &bytes_consumed, false);

    if(payload_length < 0x7F) {
        /* The definite form of length encoding shall be used, encoded in the minimum number of octets
         * Use non canonical encoding format , length encoding is : 0x81 0x03*/
        temp[0] = 0x81;
        memmove(temp + 1, data + index, length - index);
        libspdm_copy_mem(data + index, length - index + 1, temp,  length - index + 1);
        length += 1;

        /* Increase the length of Certificate SEQUENCE and tbsCertificate SEQUENCE */
        for (size_t i = 1; i < index; i++) {

            check_length(data + i, length -i, &payload_length, &bytes_consumed, true);

            i += bytes_consumed;
        }
    }

    *data_length = length;

    return true;
}

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
    uint8_t buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t buffer_size;

    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_3072_SUPPORT) && (LIBSPDM_SHA384_SUPPORT)) {
        status = libspdm_read_input_file("rsa3072/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_4096_SUPPORT) && (LIBSPDM_SHA512_SUPPORT)) {
        status = libspdm_read_input_file("rsa4096/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }

    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P384_SUPPORT) && (LIBSPDM_SHA384_SUPPORT)) {
        status = libspdm_read_input_file("ecp384/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P521_SUPPORT) && (LIBSPDM_SHA512_SUPPORT)) {
        status = libspdm_read_input_file("ecp521/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*check for leaf cert basic constraints, CA = true,pathlen:none*/
        status = libspdm_read_input_file("ecp256/end_requester_ca_false.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_false(status);
        free(file_buffer);


        /*check for leaf cert basic constraints, basic constraints is excluded*/
        status = libspdm_read_input_file("ecp256/end_requester_without_basic_constraint.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*check for leaf cert spdm defined eku*/
        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_req_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_true(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_req_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_true(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_responder_with_spdm_req_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_true(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_req_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("rsa2048/end_requester_with_spdm_rsp_eku.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_3072_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /* cert mismatched negotiated base_aysm_algo check */
        status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_false(status);
        free(file_buffer);

        status = libspdm_read_input_file("ecp256/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_false(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_4096_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*test web cert: cert public key algo is RSA case*/
        status = libspdm_read_input_file("test_web_cert/Google.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("test_web_cert/Amazon.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_true(status);
        free(file_buffer);
    }

    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        /*test web cert: ccert public key algo is ECC case*/
        status = libspdm_read_input_file("test_web_cert/GitHub.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_true(status);
        free(file_buffer);
    }
    if ((LIBSPDM_ECDSA_P256_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("test_web_cert/YouTube.cer",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);
        status = libspdm_x509_certificate_check(file_buffer, file_buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                false, true);
        assert_true(status);
        free(file_buffer);
    }

    if ((LIBSPDM_RSA_SSA_2048_SUPPORT) && (LIBSPDM_SHA256_SUPPORT)) {
        status = libspdm_read_input_file("rsa2048/end_requester.cert.der",
                                         (void **)&file_buffer, &file_buffer_size);
        assert_true(status);

        libspdm_copy_mem(buffer, file_buffer_size, file_buffer, file_buffer_size);
        buffer_size = file_buffer_size;

        /* Canonical length encoding is modified to non canonical length encoding format */
        convert_normalized_to_non_normalized(buffer, &buffer_size);

        status = libspdm_x509_certificate_check(buffer, buffer_size,
                                                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                                                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                                true, true);
        assert_false(status);
        free(file_buffer);
    }
}

void libspdm_test_crypt_asym_verify(void **state)
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

void libspdm_test_crypt_req_asym_verify(void **state)
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

void libspdm_test_crypt_palindrome(void **state)
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

void libspdm_test_crypt_rsa_palindrome(void **state)
{
    /* Test RSA Buffers as palindrone */
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
        /* Test case where buffer is palindrone */
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf0, sizeof(buf0));
        assert_true(status);

        /* Test cases where buffer is NOT palindrone */
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf1, sizeof(buf1));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf2, sizeof(buf2));
        assert_false(status);
        status = libspdm_is_signature_buffer_palindrome(rsa_algos[i], buf3, sizeof(buf3));
        assert_false(status);
    }
}

void libspdm_test_crypt_ecdsa_palindrome(void **state)
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
        /* Test case where buffer is palindrone */
        status = libspdm_is_signature_buffer_palindrome(ecdsa_algos[i], buf0, sizeof(buf0));
        assert_true(status);

        /* Test cases where buffer is NOT palindrone */
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

        cmocka_unit_test(libspdm_test_crypt_spdm_x509_certificate_check),

        cmocka_unit_test(libspdm_test_crypt_asym_verify),

        cmocka_unit_test(libspdm_test_crypt_req_asym_verify),

        cmocka_unit_test(libspdm_test_crypt_palindrome),

        cmocka_unit_test(libspdm_test_crypt_rsa_palindrome),

        cmocka_unit_test(libspdm_test_crypt_ecdsa_palindrome),
    };

    return cmocka_run_group_tests(spdm_crypt_lib_tests,
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
