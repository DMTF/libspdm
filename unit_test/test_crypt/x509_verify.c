/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "test_crypt.h"
#include "industry_standard/spdm.h"
#include "spdm_device_secret_lib_sample/spdm_device_secret_lib_internal.h"
#include "library/spdm_device_secret_lib.h"

static uint8_t m_libspdm_oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };

/*ECC 256 req_info(include right req_info attribute)*/
static uint8_t right_req_info[] = {
    0x30, 0x81, 0xBF, 0x02, 0x01, 0x00, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4C, 0x74,
    0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xDB, 0xC2, 0xB2, 0xB7,
    0x83, 0x3C, 0xC8, 0x85, 0xE4, 0x3D, 0xE1, 0xF3, 0xBA, 0xE2, 0xF2, 0x90, 0x8E, 0x30, 0x25, 0x14,
    0xE1, 0xF7, 0xA9, 0x82, 0x29, 0xDB, 0x9D, 0x76, 0x2F, 0x80, 0x11, 0x32, 0xEE, 0xAB, 0xE2, 0x68,
    0xD1, 0x22, 0xE7, 0xBD, 0xB4, 0x71, 0x27, 0xC8, 0x79, 0xFB, 0xDC, 0x7C, 0x9E, 0x33, 0xA6, 0x67,
    0xC2, 0x10, 0x47, 0x36, 0x32, 0xC5, 0xA1, 0xAA, 0x6B, 0x2B, 0xAA, 0xC9, 0xA0, 0x18, 0x30, 0x16,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07, 0x31, 0x09, 0x0C, 0x07, 0x74,
    0x65, 0x73, 0x74, 0x31, 0x32, 0x33
};

/*ECC 256 req_info(include wrong req_info attribute, oid is wrong)*/
static uint8_t wrong_req_info[] = {
    0x30, 0x81, 0xBF, 0x02, 0x01, 0x00, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4C, 0x74,
    0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xDB, 0xC2, 0xB2, 0xB7,
    0x83, 0x3C, 0xC8, 0x85, 0xE4, 0x3D, 0xE1, 0xF3, 0xBA, 0xE2, 0xF2, 0x90, 0x8E, 0x30, 0x25, 0x14,
    0xE1, 0xF7, 0xA9, 0x82, 0x29, 0xDB, 0x9D, 0x76, 0x2F, 0x80, 0x11, 0x32, 0xEE, 0xAB, 0xE2, 0x68,
    0xD1, 0x22, 0xE7, 0xBD, 0xB4, 0x71, 0x27, 0xC8, 0x79, 0xFB, 0xDC, 0x7C, 0x9E, 0x33, 0xA6, 0x67,
    0xC2, 0x10, 0x47, 0x36, 0x32, 0xC5, 0xA1, 0xAA, 0x6B, 0x2B, 0xAA, 0xC9, 0xA0, 0x18, 0x30, 0x16,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,       0x09, 0x07, 0x31, 0x09, 0x0C, 0x07, 0x74,
    0x65, 0x73, 0x74, 0x31, 0x32, 0x33
};


/**
 * save the CSR
 *
 * @param[out] csr_len               CSR len for DER format
 * @param[in]  csr_pointer           csr_pointer is address to store CSR.
 * @param[in]  base_asym_algo        To distinguish file
 *
 * @retval true                      successfully.
 * @retval false                     unsuccessfully.
 **/
bool libspdm_write_csr_to_file(const void * csr_pointer, size_t csr_len, uint32_t base_asym_algo)
{
    FILE *fp_out;
    char* file_name;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file_name = "rsa2048_csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file_name = "rsa3072_csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file_name = "rsa4096_csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file_name = "ecc256_csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file_name = "ecc384_csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file_name = "ecc521_csr";
        break;
    default:
        return false;
    }

    if ((fp_out = fopen(file_name, "w+b")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        return false;
    }

    if ((fwrite(csr_pointer, 1, csr_len, fp_out)) != csr_len) {
        printf("Write output file error %s\n", file_name);
        fclose(fp_out);
        return false;
    }

    fclose(fp_out);

    return true;
}


/**
 * Validate Crypto X509 certificate Verify
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_x509(char *Path, size_t len)
{
    bool status;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;
    uint8_t *test_cert;
    size_t test_cert_len;
    uint8_t *test_ca_cert;
    size_t test_ca_cert_len;
    uint8_t *test_bundle_cert;
    size_t test_bundle_cert_len;
    uint8_t *test_end_cert;
    size_t test_end_cert_len;
    size_t subject_size;
    uint8_t *subject;
    size_t common_name_size;
    char common_name[64];
    size_t cert_version;
    uint8_t asn1_buffer[1024];
    size_t asn1_buffer_len;
    uint8_t end_cert_from[64];
    size_t end_cert_from_len;
    uint8_t end_cert_to[64];
    size_t end_cert_to_len;
    uint8_t date_time1[64];
    uint8_t date_time2[64];
    char file_name_buffer[1024];

    test_cert = NULL;
    test_ca_cert = NULL;
    test_bundle_cert = NULL;
    test_end_cert = NULL;

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/inter.cert.der", sizeof("/inter.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_cert,
                                     &test_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/ca.cert.der", sizeof("/ca.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_ca_cert,
                                     &test_ca_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/bundle_requester.certchain.der", sizeof("/bundle_requester.certchain.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_bundle_cert,
                                     &test_bundle_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/end_requester.cert.der", sizeof("/end_requester.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_end_cert,
                                     &test_end_cert_len);
    if (!status) {
        goto cleanup;
    }


    /* X509 Certificate Verification.*/

    libspdm_my_print("\n- X509 Certificate Verification with Trusted CA ...");
    status = libspdm_x509_verify_cert(test_cert, test_cert_len, test_ca_cert,
                                      test_ca_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Certificate Chain Verification.*/

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "- X509 Certificate Chain Verification ... "));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_ca_cert, test_ca_cert_len,
                                            (const uint8_t *)test_bundle_cert,
                                            test_bundle_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Get leaf certificate from cert_chain Verificate*/

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate Chain get leaf certificate Verification ... "));
    status = libspdm_x509_get_cert_from_cert_chain(test_bundle_cert,
                                                   test_bundle_cert_len, -1,
                                                   &leaf_cert, &leaf_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_end_cert_len) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (libspdm_const_compare_mem(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Get leaf certificate from cert_chain Verificate*/

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate Chain get leaf certificate Verification ... "));
    status = libspdm_x509_get_cert_from_cert_chain(test_bundle_cert,
                                                   test_bundle_cert_len, 2,
                                                   &leaf_cert, &leaf_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_end_cert_len) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (libspdm_const_compare_mem(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Get root certificate from cert_chain Verificate*/

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate Chain get root certificate Verification ... "));
    status = libspdm_x509_get_cert_from_cert_chain(test_bundle_cert,
                                                   test_bundle_cert_len, 0,
                                                   &leaf_cert, &leaf_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_ca_cert_len) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (libspdm_const_compare_mem(leaf_cert, test_ca_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Certificate subject Retrieving.*/

    libspdm_my_print("- X509 Certificate subject Bytes Retrieving ... ");
    subject_size = 0;
    status = libspdm_x509_get_subject_name(test_cert, test_cert_len, NULL,
                                           &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = libspdm_x509_get_subject_name(test_cert, test_cert_len, subject,
                                           &subject_size);
    free_pool(subject);
    if (!status) {
        libspdm_my_print("[Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]");
    }

    libspdm_my_print("\n- X509 Certificate context Retrieving ... ");

    /* Get common_name from X509 Certificate subject*/

    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_common_name(test_cert, test_cert_len, common_name,
                                          &common_name_size);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Common name - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving Common name = \"%s\" (size = %d)",
                       common_name, common_name_size));
        libspdm_my_print(" - [PASS]");
    }


    /* Get Issuer OrganizationName from X509 Certificate subject*/

    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_organization_name(test_cert, test_cert_len, common_name,
                                                &common_name_size);
    if (status || common_name_size != 0) {
        libspdm_my_print("\n  - Retrieving Oraganization name - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Retrieving Oraganization name - [PASS]");
    }


    /* Get version from X509 Certificate*/

    cert_version = 0;
    status = libspdm_x509_get_version(test_cert, test_cert_len, &cert_version);
    if (!status) {
        libspdm_my_print("\n  - Retrieving version - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n  - Retrieving version = %d - ",
                       cert_version));
        libspdm_my_print("[Pass]");
    }


    /* Get Serial from X509 Certificate*/

    asn1_buffer_len = 1024;
    libspdm_zero_mem(asn1_buffer, asn1_buffer_len);
    status = libspdm_x509_get_serial_number(test_cert, test_cert_len, asn1_buffer,
                                            &asn1_buffer_len);
    if (!status) {
        libspdm_my_print("\n  - Retrieving serial_number - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n  - Retrieving serial_number = %d - ",
                       *((uint64_t *)asn1_buffer)));
        libspdm_my_print("[Pass]");
    }


    /* X509 Certificate subject Retrieving.*/

    libspdm_my_print("\n  - Retrieving issuer Bytes ... ");
    subject_size = 0;
    status = libspdm_x509_get_issuer_name(test_cert, test_cert_len, NULL,
                                          &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = libspdm_x509_get_issuer_name(test_cert, test_cert_len, subject,
                                          &subject_size);
    free_pool(subject);
    if (!status) {
        libspdm_my_print("[Fail]");
        goto cleanup;
    } else {
        libspdm_my_print(" - [Pass]");
    }


    /* Get Issuer common_name from X509 Certificate subject*/

    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_issuer_common_name(test_cert, test_cert_len, common_name,
                                                 &common_name_size);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Issuer Common name - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving Issuer Common name = \"%s\" (size = %d) - ",
                       common_name, common_name_size));
        libspdm_my_print("[Pass]");
    }


    /* Get Issuer OrganizationName from X509 Certificate subject*/

    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_issuer_orgnization_name(test_cert, test_cert_len,
                                                      common_name, &common_name_size);
    if (status || common_name_size != 0) {
        libspdm_my_print("\n  - Retrieving Issuer Oraganization name - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Retrieving Issuer Oraganization name - [Pass]");
    }


    /* Get X509GetSubjectAltName*/

    asn1_buffer_len = 1024;
    libspdm_zero_mem(asn1_buffer, asn1_buffer_len);
    status = libspdm_x509_get_extension_data(test_end_cert, test_end_cert_len,
                                             m_libspdm_oid_subject_alt_name,
                                             sizeof(m_libspdm_oid_subject_alt_name),
                                             asn1_buffer, &asn1_buffer_len);
    if (!status) {
        libspdm_my_print("\n  - Retrieving  SubjectAltName otherName - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving  SubjectAltName (size = %d) ",
                       asn1_buffer_len));
        libspdm_my_print("- [Pass]");
    }


    /* Get X509 Validity*/

    end_cert_from_len = 64;
    end_cert_to_len = 64;
    status = libspdm_x509_get_validity(test_end_cert, test_end_cert_len,
                                       end_cert_from, &end_cert_from_len,
                                       end_cert_to, &end_cert_to_len);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Validity - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Retrieving Validity - [Pass]");
    }

    asn1_buffer_len = 64;
    status = libspdm_x509_set_date_time("19700101000000Z", date_time1,
                                        &asn1_buffer_len);
    if (status && (asn1_buffer_len != 0)) {
        libspdm_my_print("\n  - Set date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    asn1_buffer_len = 64;
    status = libspdm_x509_set_date_time("19700201000000Z", date_time2,
                                        &asn1_buffer_len);
    if (status && (asn1_buffer_len != 0)) {
        libspdm_my_print("\n  - Set date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    if (libspdm_x509_compare_date_time(date_time1, date_time2) < 0) {
        libspdm_my_print("\n  - Compare date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Compare date_time- [Fail]");
        goto cleanup;
    }

    libspdm_my_print("\n");
    status = true;

cleanup:
    if (test_cert != NULL) {
        free(test_cert);
    }
    if (test_ca_cert != NULL) {
        free(test_ca_cert);
    }
    if (test_bundle_cert != NULL) {
        free(test_bundle_cert);
    }
    if (test_end_cert != NULL) {
        free(test_end_cert);
    }
    return status;
}

/**
 * Gen and verify CSR.
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen and verify RSA CSR.
 **/
bool libspdm_validate_crypt_x509_csr(void)
{
    bool ret;

    libspdm_my_print("\nGen CSR test:\n");
    /*read private key to gen RSA CSR*/
    uint8_t rsa_csr_pointer[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t rsa_csr_len;
    uint8_t *rsa_csr = rsa_csr_pointer;

    bool need_reset = false;

    libspdm_my_print("Gen and save RSA CSR!!!\n");
    ret = libspdm_gen_csr(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                          SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
                          &need_reset, &rsa_csr_len, &rsa_csr, LIBSPDM_MAX_CSR_SIZE,
                          NULL, 0);
    if (!ret) {
        libspdm_my_print("Gen RSA CSR fail !!!\n");
        return ret;
    }

    ret = libspdm_write_csr_to_file(rsa_csr, rsa_csr_len,
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072);
    if (!ret) {
        libspdm_my_print("Save RSA CSR fail !!!\n");
        return ret;
    }
    libspdm_my_print("Gen and save RSA CSR successful !!!\n");

    /*read private key to gen ECC CSR*/
    uint8_t ecc_csr_pointer[LIBSPDM_MAX_CSR_SIZE];
    size_t ecc_csr_len;
    uint8_t *ecc_csr = ecc_csr_pointer;

    libspdm_my_print("\nGen and save ECC CSR!!!\n");
    ret = libspdm_gen_csr(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                          SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
                          &need_reset, &ecc_csr_len, &ecc_csr, LIBSPDM_MAX_CSR_SIZE,
                          NULL, 0);
    if (!ret) {
        libspdm_my_print("Gen ECC CSR fail !!!\n");
        return ret;
    }

    ret = libspdm_write_csr_to_file(ecc_csr, ecc_csr_len,
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
    if (!ret) {
        libspdm_my_print("Save ECC CSR fail !!!\n");
        return ret;
    }
    libspdm_my_print("Gen and save ECC CSR successful !!!\n");

    /*read private key to gen ECC 256 CSR*/
    uint8_t ecc256_csr_pointer[LIBSPDM_MAX_CSR_SIZE];
    size_t ecc256_csr_len;
    uint8_t *ecc256_csr = ecc256_csr_pointer;

    libspdm_my_print("\nGen and save ECC_256 CSR with right_req_info!!!\n");
    ret = libspdm_gen_csr(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                          SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                          &need_reset, &ecc256_csr_len, &ecc256_csr, LIBSPDM_MAX_CSR_SIZE,
                          right_req_info, sizeof(right_req_info));
    if (!ret) {
        libspdm_my_print("Gen ECC_256 CSR with right_req_info fail !!!\n");
        return ret;
    }

    ret = libspdm_write_csr_to_file(ecc256_csr, ecc256_csr_len,
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256);
    if (!ret) {
        libspdm_my_print("Save ECC_256 CSR with right_req_info fail !!!\n");
        return ret;
    }
    libspdm_my_print("Gen and save ECC_256 CSR with right_req_info successful !!!\n");

    libspdm_my_print("\nTest req_info verify function!!!\n");
    ret = libspdm_verify_req_info(right_req_info, sizeof(right_req_info));
    if (ret) {
        libspdm_my_print("Test right req_info verify function  successful !!!\n");
    } else {
        return true;
    }

    ret = libspdm_verify_req_info(wrong_req_info, sizeof(wrong_req_info));
    if (!ret) {
        libspdm_my_print("Test wrong req_info verify function  successful !!!\n");
    } else {
        return false;
    }

    return ret;
}

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}
