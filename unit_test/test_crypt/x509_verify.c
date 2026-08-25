/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include <time.h>
#include "test_crypt.h"
#include "industry_standard/spdm.h"
#include "internal/libspdm_device_secret_lib.h"

static uint8_t m_libspdm_oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };

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
        file_name = "rsa2048.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file_name = "rsa3072.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file_name = "rsa4096.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file_name = "ecp256.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file_name = "ecp384.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file_name = "ecp521.csr";
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

size_t libspdm_get_aysm_nid_from_file_name(char *Path, size_t len)
{
    if (libspdm_consttime_is_mem_equal(Path, "ecp256", len - 1)) {
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
    } else if (libspdm_consttime_is_mem_equal(Path, "ecp384", len - 1)) {
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
    } else if (libspdm_consttime_is_mem_equal(Path, "rsa2048", len - 1)) {
        return LIBSPDM_CRYPTO_NID_RSASSA2048;
    } else if (libspdm_consttime_is_mem_equal(Path, "rsa3072", len - 1)) {
        return LIBSPDM_CRYPTO_NID_RSASSA3072;
    } else if (libspdm_consttime_is_mem_equal(Path, "sm2", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SM2_DSA_P256;
    } else if (libspdm_consttime_is_mem_equal(Path, "ed25519", len - 1)) {
        return LIBSPDM_CRYPTO_NID_EDDSA_ED25519;
    } else if (libspdm_consttime_is_mem_equal(Path, "ed448", len - 1)) {
        return LIBSPDM_CRYPTO_NID_EDDSA_ED448;
    } else if (libspdm_consttime_is_mem_equal(Path, "mldsa44", len - 1)) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_44;
    } else if (libspdm_consttime_is_mem_equal(Path, "mldsa65", len - 1)) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_65;
    } else if (libspdm_consttime_is_mem_equal(Path, "mldsa87", len - 1)) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_87;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-sha2-128s", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-sha2-128f", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-sha2-192s", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-sha2-192f", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-sha2-256s", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-sha2-256f", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-shake-128s", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-shake-128f", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-shake-192s", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-shake-192f", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-shake-256s", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S;
    } else if (libspdm_consttime_is_mem_equal(Path, "slh-dsa-shake-256f", len - 1)) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F;
    } else {
        return LIBSPDM_CRYPTO_NID_NULL;
    }
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
    uint8_t *test_private_key;
    size_t test_private_key_len;
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
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    size_t hash_nid;
    size_t asym_nid;
    uint8_t *csr;
    size_t csr_size;
    void *x509_ca_cert;
    void *context;
#endif

    test_cert = NULL;
    test_ca_cert = NULL;
    test_bundle_cert = NULL;
    test_end_cert = NULL;
    test_private_key = NULL;
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    x509_ca_cert = NULL;
    csr = NULL;
#endif

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/inter.cert.der", sizeof("/inter.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_cert, &test_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/ca.cert.der", sizeof("/ca.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_ca_cert, &test_ca_cert_len);
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
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_end_cert, &test_end_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/end_requester.key", sizeof("/end_requester.key"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_private_key,
                                     &test_private_key_len);
    if (!status) {
        goto cleanup;
    }

    /* X509 Certificate Verification.*/
    libspdm_my_print("\n- X509 Certificate Verification with Trusted CA ...");
    status = libspdm_x509_verify_cert(test_cert, test_cert_len, test_ca_cert, test_ca_cert_len);
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

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate CA cert verify itself Verification ... "));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_ca_cert, test_ca_cert_len,
                                            (const uint8_t *)test_ca_cert,
                                            test_ca_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate CA cert verify itself Verification with large cert len"));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_ca_cert, test_ca_cert_len,
                                            (const uint8_t *)test_ca_cert,
                                            test_ca_cert_len + 1);
    if (status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate end cert verify itself Verification ... "));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_end_cert, test_end_cert_len,
                                            (const uint8_t *)test_end_cert,
                                            test_end_cert_len);
    if (status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate end cert verify itself Verification with large cert len"));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_end_cert, test_end_cert_len,
                                            (const uint8_t *)test_end_cert,
                                            test_end_cert_len + 1);
    if (status) {
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
    if (memcmp(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
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
    if (memcmp(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
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
    if (memcmp(leaf_cert, test_ca_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    /* X509 Certificate subject Retrieving.*/
    libspdm_my_print("- X509 Certificate subject Bytes Retrieving ... ");
    subject_size = 0;
    status = libspdm_x509_get_subject_name(test_cert, test_cert_len, NULL, &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = libspdm_x509_get_subject_name(test_cert, test_cert_len, subject, &subject_size);
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
    status = libspdm_x509_get_common_name(test_cert, test_cert_len, common_name, &common_name_size);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Common name - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving Common name = \"%s\" (size = %zu)",
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
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n - Retrieving version = %zu - ", cert_version));
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
        size_t index;

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n  - Retrieving serial_number = "));
        for (index = 0; index < asn1_buffer_len; index++) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x", asn1_buffer[index]));
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, " - "));
        libspdm_my_print("[Pass]");
    }

    /* X509 Certificate subject Retrieving.*/
    libspdm_my_print("\n  - Retrieving issuer Bytes ... ");
    subject_size = 0;
    status = libspdm_x509_get_issuer_name(test_cert, test_cert_len, NULL, &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = libspdm_x509_get_issuer_name(test_cert, test_cert_len, subject, &subject_size);
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
                       "\n  - Retrieving Issuer Common name = \"%s\" (size = %zu) - ",
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
                       "\n  - Retrieving  SubjectAltName (size = %zu) ",
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
    status = libspdm_x509_set_date_time("19700101000000Z", date_time1, &asn1_buffer_len);
    if (status && (asn1_buffer_len != 0)) {
        libspdm_my_print("\n  - Set date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    asn1_buffer_len = 64;
    status = libspdm_x509_set_date_time("19700201000000Z", date_time2, &asn1_buffer_len);
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

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    /* X509 Gen CSR */
    char *subject_name = "C=NL,O=PolarSSL,CN=PolarSSL Server 1";

    libspdm_my_print("\n- X509 Gen CSR test ... ");
    status = libspdm_x509_construct_certificate(
        test_end_cert, test_end_cert_len, (uint8_t **)&x509_ca_cert);
    if ((x509_ca_cert == NULL) || (!status)) {
        libspdm_my_print("\n  - Construct Cert [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Construct Cert [Pass]");
    }
    hash_nid = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    asym_nid = libspdm_get_aysm_nid_from_file_name(Path, len);

    switch (asym_nid) {
    #if LIBSPDM_RSA_SSA_SUPPORT
    case LIBSPDM_CRYPTO_NID_RSASSA2048:
    case LIBSPDM_CRYPTO_NID_RSASSA3072:
        status = libspdm_rsa_get_private_key_from_pem(
            test_private_key, test_private_key_len, NULL, &context);
        break;
    #endif /* LIBSPDM_RSA_SSA_SUPPORT */
    #if LIBSPDM_ECDSA_SUPPORT
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384:
        status = libspdm_ec_get_private_key_from_pem(
            test_private_key, test_private_key_len, NULL, &context);
        break;
    #endif /* LIBSPDM_ECDSA_SUPPORT */
    #if LIBSPDM_SM2_DSA_SUPPORT
    case LIBSPDM_CRYPTO_NID_SM2_DSA_P256:
        status = libspdm_sm2_get_private_key_from_pem(
            test_private_key, test_private_key_len, NULL, &context);
        break;
    #endif /* LIBSPDM_SM2_DSA_SUPPORT */
    #if LIBSPDM_EDDSA_SUPPORT
    case LIBSPDM_CRYPTO_NID_EDDSA_ED25519:
    case LIBSPDM_CRYPTO_NID_EDDSA_ED448:
        status = libspdm_ecd_get_private_key_from_pem(
            test_private_key, test_private_key_len, NULL, &context);
        break;
    #endif /* LIBSPDM_EDDSA_SUPPORT */
    #if LIBSPDM_ML_DSA_SUPPORT
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        status = libspdm_mldsa_get_private_key_from_pem(
            test_private_key, test_private_key_len, NULL, &context);
        break;
    #endif /* LIBSPDM_ML_DSA_SUPPORT */
    #if LIBSPDM_SLH_DSA_SUPPORT
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        status = libspdm_slhdsa_get_private_key_from_pem(
            test_private_key, test_private_key_len, NULL, &context);
        break;
    #endif /* LIBSPDM_SLH_DSA_SUPPORT */
    default:
        libspdm_my_print("\n  - Get Private Key - [Fail]");
        status = false;
        goto cleanup;
    }

    if (!status) {
        libspdm_my_print("\n  - Get Private Key - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Get Private Key - [Pass]");
    }

    csr_size = 0x10000;
    csr = (uint8_t *)allocate_pool(csr_size);
    if (csr == NULL) {
        libspdm_my_print("\n  - Allocate CSR buffer - [Fail]");
        goto cleanup;
    }

    if ((asym_nid & 0x8000) != 0) {
        /* PQC algorithm: use pqc CSR API */
        status = libspdm_gen_x509_csr(
            hash_nid, 0, asym_nid, NULL, 0, true, context,
            subject_name, &csr_size, csr, NULL);
    } else {
        status = libspdm_gen_x509_csr(
            hash_nid, asym_nid, 0, NULL, 0, true, context,
            subject_name, &csr_size, csr, NULL);
    }
    if (!status) {
        libspdm_my_print("\n  - Gen CSR - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Gen CSR - [Pass]");
    }
#endif

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
    if (test_private_key != NULL) {
        free(test_private_key);
    }
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    if (csr != NULL) {
        free_pool(csr);
    }
    if (x509_ca_cert != NULL) {
        libspdm_x509_free(x509_ca_cert);
    }
#endif
    return status;
}

/* Security regression test for cert-chain validation.
 *
 * Chain: root (CA:TRUE, pathlen:0) -> inter (CA:TRUE) -> leaf (CA:FALSE).
 *
 * The root's basicConstraints set pathlen:0, meaning the root may issue
 * end-entity certificates but MUST NOT have any subordinate CA beneath it.
 * The chain above places a subordinate CA (inter) under that pathlen:0 root,
 * which violates RFC 5280 path validation and must be rejected. A pairwise
 * "each cert is the trust anchor for the next" walk cannot see this, because
 * the pathLenConstraint is a whole-path property. */
static const uint8_t m_pathlen_root_cert[] = {
    0x30, 0x82, 0x01, 0x76, 0x30, 0x82, 0x01, 0x1b, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x39, 0x4e, 0xfa, 0xcf, 0xe1, 0x8e, 0x2d, 0xe0, 0x27,
    0xd8, 0x95, 0x88, 0xa8, 0xff, 0xd9, 0xef, 0x2e, 0x97, 0x24, 0x89, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c,
    0x50, 0x61, 0x74, 0x68, 0x4c, 0x65, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74,
    0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x32, 0x31, 0x30, 0x37,
    0x35, 0x35, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x31,
    0x38, 0x30, 0x37, 0x35, 0x35, 0x30, 0x37, 0x5a, 0x30, 0x17, 0x31, 0x15,
    0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x50, 0x61, 0x74,
    0x68, 0x4c, 0x65, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    0x80, 0xba, 0x37, 0x60, 0xb1, 0xdb, 0xf0, 0xf6, 0x24, 0x8b, 0x3c, 0x55,
    0x60, 0x3f, 0xf6, 0xad, 0xac, 0x61, 0xa6, 0xd3, 0xaf, 0xeb, 0x94, 0x5b,
    0xb1, 0xed, 0x76, 0x07, 0x0c, 0x5d, 0x70, 0x96, 0xd8, 0xa4, 0x00, 0x0d,
    0x9d, 0xee, 0x8b, 0xac, 0xa9, 0x45, 0x16, 0xf4, 0x22, 0x7f, 0x97, 0x80,
    0xa9, 0xee, 0x8d, 0xd4, 0x5f, 0x43, 0xdc, 0x07, 0x06, 0x55, 0x15, 0xf4,
    0x11, 0xdc, 0x11, 0xb1, 0xa3, 0x45, 0x30, 0x43, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01,
    0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa4, 0x43, 0x88, 0xa0, 0x6e,
    0x79, 0xae, 0xa5, 0xd1, 0xd2, 0xf6, 0x67, 0x67, 0xc9, 0x80, 0x60, 0x2f,
    0xba, 0xc9, 0xa2, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xd8,
    0xc7, 0x1c, 0xa4, 0x87, 0x90, 0xb4, 0xec, 0xa0, 0x35, 0x5a, 0x56, 0xe4,
    0x43, 0x78, 0x11, 0xd9, 0xf6, 0x03, 0xc3, 0xc3, 0x98, 0x9b, 0xde, 0xe6,
    0xa8, 0x2d, 0x10, 0x82, 0x54, 0xfd, 0x9d, 0x02, 0x21, 0x00, 0xdb, 0x83,
    0x97, 0x7a, 0x5c, 0xc7, 0xc0, 0xa8, 0x48, 0x38, 0x29, 0x7f, 0xdc, 0x64,
    0xc7, 0xae, 0x75, 0x08, 0xa3, 0x4c, 0x66, 0xe1, 0xc8, 0x95, 0xee, 0xb2,
    0x6e, 0x84, 0x97, 0x2d, 0xc2, 0x39,
};

static const uint8_t m_pathlen_inter_cert[] = {
    0x30, 0x82, 0x01, 0x9e, 0x30, 0x82, 0x01, 0x44, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x42, 0x7a, 0x0c, 0x34, 0xc8, 0xc2, 0x3b, 0x88, 0xd1,
    0xf3, 0x78, 0xcb, 0xc1, 0x51, 0x7f, 0x96, 0x9b, 0xac, 0x3e, 0x2f, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c,
    0x50, 0x61, 0x74, 0x68, 0x4c, 0x65, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74,
    0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x32, 0x31, 0x30, 0x37,
    0x35, 0x35, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x31,
    0x38, 0x30, 0x37, 0x35, 0x35, 0x30, 0x37, 0x5a, 0x30, 0x22, 0x31, 0x20,
    0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x50, 0x61, 0x74,
    0x68, 0x4c, 0x65, 0x6e, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
    0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xd9,
    0x9d, 0xa2, 0x11, 0x6b, 0x9a, 0xe0, 0x3e, 0x22, 0xba, 0xee, 0xd6, 0x7a,
    0x51, 0xd4, 0xca, 0x70, 0xe1, 0xd2, 0xd1, 0x4a, 0x99, 0xc2, 0x6a, 0xb5,
    0x17, 0x12, 0x3a, 0x0b, 0x37, 0xb7, 0xb7, 0x6d, 0xd5, 0xcf, 0x81, 0xfc,
    0x8d, 0xd6, 0x19, 0x01, 0xe4, 0x68, 0x42, 0x41, 0xf2, 0xe4, 0x31, 0x31,
    0x12, 0xef, 0x4e, 0xb1, 0x9c, 0xda, 0xdb, 0x60, 0xc3, 0x46, 0x56, 0x79,
    0xbb, 0x5c, 0xab, 0xa3, 0x63, 0x30, 0x61, 0x30, 0x0f, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
    0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0x6d, 0xd7, 0x00, 0x0c, 0xab, 0xdf, 0x56, 0x5a, 0x21,
    0x5c, 0xed, 0xfc, 0x38, 0x94, 0x86, 0xa0, 0x24, 0x8b, 0x34, 0x65, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0xa4, 0x43, 0x88, 0xa0, 0x6e, 0x79, 0xae, 0xa5, 0xd1, 0xd2, 0xf6, 0x67,
    0x67, 0xc9, 0x80, 0x60, 0x2f, 0xba, 0xc9, 0xa2, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30,
    0x45, 0x02, 0x20, 0x02, 0x19, 0x4d, 0x7f, 0x1f, 0x06, 0xdf, 0x2b, 0x42,
    0x8b, 0x84, 0xc4, 0xde, 0x54, 0x25, 0xdf, 0x87, 0x81, 0x21, 0x05, 0x7c,
    0x0f, 0x45, 0x67, 0x31, 0x58, 0x33, 0x8d, 0xdb, 0x91, 0x6f, 0x83, 0x02,
    0x21, 0x00, 0xae, 0x09, 0x83, 0x34, 0x3f, 0x6a, 0x73, 0x15, 0xa5, 0x60,
    0x50, 0x48, 0xc2, 0x33, 0x78, 0xb6, 0xd0, 0xbd, 0x08, 0x76, 0x00, 0xc7,
    0x2e, 0x6d, 0xb3, 0xd0, 0xe8, 0x14, 0xa3, 0x94, 0x1e, 0x39,
};

static const uint8_t m_pathlen_leaf_cert[] = {
    0x30, 0x82, 0x01, 0x9c, 0x30, 0x82, 0x01, 0x41, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x10, 0x48, 0x66, 0xb1, 0x04, 0xe1, 0x45, 0x95, 0x64,
    0x25, 0x9c, 0x3f, 0x90, 0x08, 0x67, 0xeb, 0x6a, 0xfd, 0x1a, 0xe4, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17,
    0x50, 0x61, 0x74, 0x68, 0x4c, 0x65, 0x6e, 0x20, 0x49, 0x6e, 0x74, 0x65,
    0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x32, 0x31, 0x30, 0x37, 0x35,
    0x35, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x31, 0x38,
    0x30, 0x37, 0x35, 0x35, 0x30, 0x37, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30,
    0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x50, 0x61, 0x74, 0x68,
    0x4c, 0x65, 0x6e, 0x20, 0x4c, 0x65, 0x61, 0x66, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x85,
    0xeb, 0xcb, 0x5d, 0xf7, 0x24, 0x3f, 0x92, 0x9d, 0xc1, 0xf6, 0xce, 0x91,
    0xb8, 0x77, 0x19, 0x14, 0xf9, 0xb3, 0x84, 0xc5, 0xba, 0x44, 0x1b, 0x7f,
    0x74, 0x21, 0x67, 0x94, 0x07, 0xbf, 0x36, 0xdc, 0x8f, 0x82, 0xe4, 0xaa,
    0xb1, 0x71, 0x5e, 0xa8, 0x80, 0xe6, 0x95, 0x8f, 0x5a, 0x3b, 0x8d, 0xf3,
    0x02, 0xb2, 0xee, 0x0b, 0xbe, 0x25, 0xba, 0xcf, 0x0a, 0x4e, 0x2d, 0x37,
    0x9f, 0xbc, 0x96, 0xa3, 0x60, 0x30, 0x5e, 0x30, 0x0c, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07,
    0x80, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
    0xf3, 0xf2, 0x9f, 0x21, 0xb3, 0x69, 0x17, 0x66, 0xb6, 0x91, 0xbb, 0x5e,
    0xd8, 0x75, 0x19, 0x75, 0x84, 0x48, 0x1c, 0x72, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6d, 0xd7, 0x00,
    0x0c, 0xab, 0xdf, 0x56, 0x5a, 0x21, 0x5c, 0xed, 0xfc, 0x38, 0x94, 0x86,
    0xa0, 0x24, 0x8b, 0x34, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,
    0x00, 0x93, 0x9f, 0x32, 0xa6, 0x90, 0xe9, 0xa7, 0xe5, 0x74, 0xe7, 0x24,
    0x04, 0x7e, 0x75, 0xe0, 0xe8, 0x10, 0xe8, 0x84, 0xc8, 0xad, 0xdf, 0xb5,
    0x00, 0xce, 0x18, 0xa3, 0xe3, 0xe4, 0x36, 0x77, 0x92, 0x02, 0x21, 0x00,
    0x95, 0xac, 0x42, 0x9e, 0x41, 0x3b, 0x53, 0x1d, 0x43, 0xe4, 0x6e, 0x35,
    0xb8, 0xba, 0x54, 0xc9, 0xc2, 0x25, 0x79, 0x06, 0xe8, 0x15, 0xdf, 0xa2,
    0x92, 0xeb, 0x36, 0x5f, 0xc7, 0x5b, 0x21, 0xb5,
};

/**
 * Validate that libspdm_x509_verify_cert_chain() rejects a chain that violates
 * the root's pathLenConstraint.
 *
 * @retval  true  Validation succeeded (malicious chain rejected).
 * @retval  false  Validation failed (malicious chain accepted).
 **/
bool libspdm_validate_crypt_x509_verify_cert_chain_pathlen_constraints(void)
{
    bool status;
    uint8_t bad_chain[sizeof(m_pathlen_inter_cert) + sizeof(m_pathlen_leaf_cert)];

    libspdm_my_print("\nCrypto X509 verify_cert_chain pathLenConstraint Testing:\n");

    /* Sanity: inter is legitimately signed by the root. */
    libspdm_my_print("- inter signed by root ... ");
    status = libspdm_x509_verify_cert(m_pathlen_inter_cert, sizeof(m_pathlen_inter_cert),
                                      m_pathlen_root_cert, sizeof(m_pathlen_root_cert));
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return false;
    }
    libspdm_my_print("[Pass]\n");

    /* Sanity: leaf is legitimately signed by inter. */
    libspdm_my_print("- leaf signed by inter ... ");
    status = libspdm_x509_verify_cert(m_pathlen_leaf_cert, sizeof(m_pathlen_leaf_cert),
                                      m_pathlen_inter_cert, sizeof(m_pathlen_inter_cert));
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return false;
    }
    libspdm_my_print("[Pass]\n");

    /* The chain root -> inter -> leaf must be rejected: the root's pathlen:0
     * forbids any subordinate CA (inter) beneath it. */
    libspdm_copy_mem(bad_chain, sizeof(bad_chain),
                     m_pathlen_inter_cert, sizeof(m_pathlen_inter_cert));
    libspdm_copy_mem(bad_chain + sizeof(m_pathlen_inter_cert),
                     sizeof(bad_chain) - sizeof(m_pathlen_inter_cert),
                     m_pathlen_leaf_cert, sizeof(m_pathlen_leaf_cert));

    libspdm_my_print("- reject chain violating pathLenConstraint ... ");
    status = libspdm_x509_verify_cert_chain(m_pathlen_root_cert, sizeof(m_pathlen_root_cert),
                                            bad_chain, sizeof(bad_chain));
    if (status) {
        libspdm_my_print("[Fail] (pathlen:0 root accepted a subordinate CA)\n");
        return false;
    }
    libspdm_my_print("[Pass]\n");

    return true;
}

/* Security regression test for cert-chain validation.
 *
 * Chain: root (nameConstraints permitted DNS:example.com) -> inter (CA) -> leaf.
 *
 * The leaf carries a subjectAltName dNSName of host.evil.org, which is outside
 * the root's permitted subtree. RFC 5280 name constraints apply to every
 * certificate below the constraining CA, so this chain must be rejected. A
 * pairwise walk cannot see it, because the root's constraint is never evaluated
 * against the non-adjacent leaf. */
static const uint8_t m_nc_root_cert[] = {
    0x30, 0x82, 0x01, 0x84, 0x30, 0x82, 0x01, 0x2a, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x28, 0x06, 0x34, 0xae, 0x2d, 0xdd, 0xb5, 0xd3, 0x2f,
    0x0c, 0x11, 0x66, 0x6d, 0x39, 0xa0, 0xc2, 0xd2, 0x4d, 0x81, 0x60, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07,
    0x4e, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x38, 0x32, 0x31, 0x31, 0x34, 0x31, 0x37, 0x32, 0x38, 0x5a,
    0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x31, 0x38, 0x31, 0x34, 0x31, 0x37,
    0x32, 0x38, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x07, 0x4e, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x9f, 0x6e, 0xcf, 0xc1, 0x82, 0x44, 0x69, 0x8c, 0x5e, 0xb6,
    0x09, 0xe5, 0x16, 0x0c, 0x75, 0x16, 0x3f, 0x68, 0xa3, 0xb2, 0x33, 0x0d,
    0x93, 0xc6, 0xe4, 0xb1, 0xbf, 0xce, 0x07, 0x51, 0x70, 0x73, 0xed, 0xaf,
    0x26, 0xdf, 0xa6, 0xcc, 0x35, 0x13, 0x67, 0x96, 0x9f, 0xb2, 0x6a, 0x96,
    0x64, 0x86, 0x8a, 0x11, 0xb7, 0xe3, 0xb2, 0x41, 0xcb, 0xcf, 0x4a, 0x29,
    0x81, 0x54, 0x4c, 0xd4, 0xb1, 0x97, 0xa3, 0x5e, 0x30, 0x5c, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
    0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1a, 0x06, 0x03, 0x55,
    0x1d, 0x1e, 0x04, 0x13, 0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0x82, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xaa, 0x54,
    0xb3, 0x14, 0x24, 0x3e, 0xf0, 0xf5, 0xf5, 0x47, 0x65, 0xc9, 0x42, 0x1f,
    0x13, 0xef, 0xea, 0x4b, 0x34, 0x56, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
    0x20, 0x3c, 0xb1, 0xfb, 0xf1, 0x8e, 0x90, 0x36, 0x0c, 0x9b, 0x52, 0xe1,
    0x6c, 0x7b, 0x04, 0xe2, 0xff, 0x43, 0xaf, 0xf4, 0xf9, 0x92, 0xac, 0x5c,
    0x9a, 0xb7, 0x79, 0x97, 0xdb, 0x06, 0xb0, 0x60, 0x2d, 0x02, 0x21, 0x00,
    0x8e, 0x58, 0xeb, 0xc2, 0xdb, 0xcc, 0x92, 0xc2, 0x6b, 0x38, 0x42, 0xf8,
    0x78, 0x15, 0x33, 0x92, 0xc3, 0xce, 0xf2, 0xa7, 0x35, 0xa9, 0x21, 0x97,
    0xf8, 0xc9, 0xcd, 0x62, 0x55, 0x34, 0xd1, 0xee,
};

static const uint8_t m_nc_inter_cert[] = {
    0x30, 0x82, 0x01, 0x92, 0x30, 0x82, 0x01, 0x3a, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x6d, 0xeb, 0xa8, 0x7b, 0x4a, 0x2b, 0xc3, 0x7c, 0x88,
    0xdb, 0xb0, 0x06, 0xa5, 0x75, 0xb4, 0xc5, 0x02, 0xe7, 0xb1, 0x85, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07,
    0x4e, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x38, 0x32, 0x31, 0x31, 0x34, 0x31, 0x37, 0x32, 0x39, 0x5a,
    0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x31, 0x38, 0x31, 0x34, 0x31, 0x37,
    0x32, 0x39, 0x5a, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x12, 0x4e, 0x43, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72,
    0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59,
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0x34, 0xc3, 0x6f, 0x1a, 0x9b, 0xfd, 0xd7, 0x96, 0x21, 0xb4, 0xb7,
    0x0d, 0xff, 0xaa, 0x38, 0x6c, 0x86, 0xe8, 0x33, 0xb1, 0xf5, 0xb4, 0xa2,
    0x05, 0xb3, 0x82, 0x30, 0xbd, 0xaf, 0x0f, 0xb8, 0xba, 0x8d, 0xe4, 0x89,
    0x64, 0xca, 0x45, 0xfc, 0x9a, 0x4c, 0x6a, 0x4c, 0x91, 0x37, 0x10, 0x64,
    0x00, 0x49, 0x7f, 0xfc, 0xce, 0xee, 0x29, 0xfb, 0x09, 0x96, 0x4c, 0x62,
    0x2b, 0x97, 0xa1, 0x6c, 0x7f, 0xa3, 0x63, 0x30, 0x61, 0x30, 0x0f, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
    0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0xd8, 0x21, 0x32, 0xbe, 0xd3, 0x9a, 0x08,
    0xa3, 0x9d, 0xf3, 0x38, 0x68, 0x3a, 0x25, 0x66, 0x20, 0xb6, 0xe3, 0xbf,
    0xcf, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0xaa, 0x54, 0xb3, 0x14, 0x24, 0x3e, 0xf0, 0xf5, 0xf5, 0x47,
    0x65, 0xc9, 0x42, 0x1f, 0x13, 0xef, 0xea, 0x4b, 0x34, 0x56, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x46,
    0x00, 0x30, 0x43, 0x02, 0x20, 0x7d, 0x41, 0xd3, 0x8d, 0x39, 0xc4, 0x02,
    0x82, 0x2f, 0xec, 0x30, 0x58, 0x30, 0x8c, 0x7e, 0xf3, 0xbf, 0x3f, 0x75,
    0x4c, 0xb7, 0x4c, 0xdd, 0x25, 0xf9, 0x75, 0xe9, 0x84, 0xad, 0x14, 0xef,
    0x21, 0x02, 0x1f, 0x04, 0x36, 0x07, 0x26, 0x45, 0x70, 0x43, 0x29, 0x5c,
    0xd4, 0x52, 0xf7, 0x66, 0x06, 0x56, 0x50, 0xd0, 0xb9, 0x60, 0x62, 0x46,
    0xd1, 0xc2, 0x77, 0xd6, 0xa6, 0xc2, 0xcb, 0x50, 0x8a, 0xed,
};

static const uint8_t m_nc_leaf_cert[] = {
    0x30, 0x82, 0x01, 0xaa, 0x30, 0x82, 0x01, 0x51, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x5a, 0x0a, 0x9f, 0xc4, 0xe8, 0x9c, 0xa3, 0xba, 0x53,
    0xd2, 0xfa, 0x2d, 0xb1, 0x8f, 0x88, 0x4a, 0x3a, 0xf2, 0xda, 0xab, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
    0x4e, 0x43, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69,
    0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36,
    0x30, 0x38, 0x32, 0x31, 0x31, 0x34, 0x31, 0x37, 0x32, 0x39, 0x5a, 0x17,
    0x0d, 0x33, 0x36, 0x30, 0x38, 0x31, 0x38, 0x31, 0x34, 0x31, 0x37, 0x32,
    0x39, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x07, 0x4e, 0x43, 0x20, 0x4c, 0x65, 0x61, 0x66, 0x30, 0x59,
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0xc4, 0x3e, 0x98, 0xca, 0x83, 0x93, 0xee, 0x24, 0xb7, 0x81, 0x62,
    0x9b, 0xa5, 0xa7, 0x68, 0xf2, 0xf6, 0xc0, 0x95, 0xd9, 0xaa, 0xff, 0x3e,
    0xb2, 0x54, 0x69, 0x24, 0xb8, 0xa7, 0xdf, 0x1b, 0x5f, 0x35, 0x9f, 0x29,
    0x45, 0x21, 0x65, 0xa5, 0x4f, 0x10, 0xf4, 0xfb, 0x0f, 0xc2, 0x3b, 0xe2,
    0x87, 0xd3, 0x46, 0xf9, 0xb6, 0x38, 0x70, 0xde, 0xa9, 0x8a, 0xb7, 0x42,
    0xf1, 0x3a, 0x41, 0x7c, 0xda, 0xa3, 0x7a, 0x30, 0x78, 0x30, 0x0c, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30,
    0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x07, 0x80, 0x30, 0x18, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x11,
    0x30, 0x0f, 0x82, 0x0d, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x65, 0x76, 0x69,
    0x6c, 0x2e, 0x6f, 0x72, 0x67, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0x65, 0xd3, 0x1b, 0x7d, 0x83, 0x9d, 0x7a, 0x7c,
    0x7c, 0xcb, 0x66, 0xc5, 0x14, 0x2f, 0x9e, 0x22, 0x9f, 0x0f, 0xe9, 0xa3,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
    0x14, 0xd8, 0x21, 0x32, 0xbe, 0xd3, 0x9a, 0x08, 0xa3, 0x9d, 0xf3, 0x38,
    0x68, 0x3a, 0x25, 0x66, 0x20, 0xb6, 0xe3, 0xbf, 0xcf, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00,
    0x30, 0x44, 0x02, 0x20, 0x64, 0x0d, 0xdb, 0x8a, 0x0b, 0x65, 0xa2, 0x65,
    0x04, 0x6a, 0xee, 0x04, 0x36, 0x7a, 0xc1, 0xef, 0x30, 0x0f, 0x80, 0x30,
    0x4f, 0xef, 0x30, 0x45, 0xb0, 0x08, 0x18, 0xec, 0xd1, 0xa6, 0xd5, 0xb3,
    0x02, 0x20, 0x1a, 0x58, 0xe6, 0x81, 0xae, 0xbc, 0x29, 0x71, 0x65, 0xf5,
    0xdc, 0x2a, 0xe3, 0x21, 0x32, 0xed, 0x9c, 0x78, 0xe2, 0xce, 0x2f, 0x84,
    0x4b, 0xf5, 0x56, 0x62, 0xa0, 0x7a, 0x0f, 0x2c, 0x75, 0xaa,
};

/**
 * Validate that libspdm_x509_verify_cert_chain() rejects a chain that violates
 * the root's dNSName nameConstraints.
 *
 * @retval  true  Validation succeeded (malicious chain rejected).
 * @retval  false  Validation failed (malicious chain accepted).
 **/
bool libspdm_validate_crypt_x509_verify_cert_chain_name_constraints(void)
{
    bool status;
    uint8_t bad_chain[sizeof(m_nc_inter_cert) + sizeof(m_nc_leaf_cert)];

    libspdm_my_print("\nCrypto X509 verify_cert_chain nameConstraints Testing:\n");

    /* Sanity: inter is legitimately signed by the root. */
    libspdm_my_print("- inter signed by root ... ");
    status = libspdm_x509_verify_cert(m_nc_inter_cert, sizeof(m_nc_inter_cert),
                                      m_nc_root_cert, sizeof(m_nc_root_cert));
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return false;
    }
    libspdm_my_print("[Pass]\n");

    /* Sanity: leaf is legitimately signed by inter. */
    libspdm_my_print("- leaf signed by inter ... ");
    status = libspdm_x509_verify_cert(m_nc_leaf_cert, sizeof(m_nc_leaf_cert),
                                      m_nc_inter_cert, sizeof(m_nc_inter_cert));
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return false;
    }
    libspdm_my_print("[Pass]\n");

    /* The chain root -> inter -> leaf must be rejected: the leaf's dNSName
    * host.evil.org is outside the root's permitted subtree example.com. */
    libspdm_copy_mem(bad_chain, sizeof(bad_chain),
                     m_nc_inter_cert, sizeof(m_nc_inter_cert));
    libspdm_copy_mem(bad_chain + sizeof(m_nc_inter_cert),
                     sizeof(bad_chain) - sizeof(m_nc_inter_cert),
                     m_nc_leaf_cert, sizeof(m_nc_leaf_cert));

    libspdm_my_print("- reject chain violating nameConstraints ... ");
    status = libspdm_x509_verify_cert_chain(m_nc_root_cert, sizeof(m_nc_root_cert),
                                            bad_chain, sizeof(bad_chain));
    if (status) {
        libspdm_my_print("[Fail] (leaf dNSName outside permitted subtree accepted)\n");
        return false;
    }
    libspdm_my_print("[Pass]\n");

    return true;
}

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}

/**
 * The certificates in rsa3072_Expiration are generated with a one day validity period, so
 * whether they are currently expired depends on when they were generated rather than on
 * anything fixed. Derive the expected result from the certificate instead of assuming it
 * has expired.
 **/
bool libspdm_validate_crypt_x509_expiration(void)
{
    bool status;
    bool expected;
    bool result;
    bool in_validity_period;
    uint8_t *ca_cert;
    size_t ca_cert_len;
    uint8_t *inter_cert;
    size_t inter_cert_len;
    uint8_t cert_from[64];
    size_t cert_from_len;
    uint8_t cert_to[64];
    size_t cert_to_len;
    uint8_t now[64];
    size_t now_len;
    char now_str[16];
    time_t now_time;
    struct tm *now_tm;

    ca_cert = NULL;
    inter_cert = NULL;
    result = false;

    libspdm_my_print("\n- X509 Expired Certificate Verification ... ");

    status = libspdm_read_input_file("rsa3072_Expiration/ca.cert.der",
                                     (void **)&ca_cert, &ca_cert_len);
    if (!status) {
        goto cleanup;
    }

    status = libspdm_read_input_file("rsa3072_Expiration/inter.cert.der",
                                     (void **)&inter_cert, &inter_cert_len);
    if (!status) {
        goto cleanup;
    }

    cert_from_len = sizeof(cert_from);
    cert_to_len = sizeof(cert_to);
    status = libspdm_x509_get_validity(inter_cert, inter_cert_len, cert_from, &cert_from_len,
                                       cert_to, &cert_to_len);
    if (!status) {
        goto cleanup;
    }

    now_time = time(NULL);
    now_tm = gmtime(&now_time);
    if (now_tm == NULL) {
        goto cleanup;
    }
    if (strftime(now_str, sizeof(now_str), "%Y%m%d%H%M%SZ", now_tm) == 0) {
        goto cleanup;
    }

    now_len = sizeof(now);
    status = libspdm_x509_set_date_time(now_str, now, &now_len);
    if (!status) {
        goto cleanup;
    }

    in_validity_period = (libspdm_x509_compare_date_time(now, cert_from) >= 0) &&
                         (libspdm_x509_compare_date_time(now, cert_to) <= 0);

#if defined(OPENSSL_IGNORE_TIME) || defined(LIBSPDM_MBEDTLS_X509_IGNORE_TIME)
    /* The build opted out of checking validity periods. */
    expected = true;
#else
    expected = in_validity_period;
#endif

    status = libspdm_x509_verify_cert(inter_cert, inter_cert_len, ca_cert, ca_cert_len);
    if (status != expected) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }

    if (in_validity_period) {
        libspdm_my_print("[Pass - certificate has not expired, nothing distinguished]\n");
    } else {
        libspdm_my_print("[Pass]\n");
    }
    result = true;

cleanup:
    if (ca_cert != NULL) {
        free(ca_cert);
    }
    if (inter_cert != NULL) {
        free(inter_cert);
    }

    return result;
}
