/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/
#include "test_crypt.h"

static const uint8_t m_oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };

/**
  Validate Crypto X509 certificate Verify

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status validate_crypt_x509(char8 *Path, uintn len)
{
    boolean status;
    uint8_t *leaf_cert;
    uintn leaf_cert_len;
    uint8_t *test_cert;
    uintn test_cert_len;
    uint8_t *test_ca_cert;
    uintn test_ca_cert_len;
    uint8_t *test_bundle_cert;
    uintn test_bundle_cert_len;
    uint8_t *test_end_cert;
    uintn test_end_cert_len;
    uintn subject_size;
    uint8_t *subject;
    uintn common_name_size;
    char8 common_name[64];
    return_status ret;
    uintn cert_version;
    uint8_t asn1_buffer[1024];
    uintn asn1_buffer_len;
    uint8_t end_cert_from[64];
    uintn end_cert_from_len;
    uint8_t end_cert_to[64];
    uintn end_cert_to_len;
    uint8_t date_time1[64];
    uint8_t date_time2[64];
    return_status ret_status;
    char8 file_name_buffer[1024];

    ret_status = RETURN_ABORTED;
    test_cert = NULL;
    test_ca_cert = NULL;
    test_bundle_cert = NULL;
    test_end_cert = NULL;

    zero_mem(file_name_buffer, 1024);
    copy_mem(file_name_buffer, Path, len);
    copy_mem(file_name_buffer + len - 1, "/inter.cert.der",
         sizeof("/inter.cert.der"));
    status = read_input_file(file_name_buffer, (void **)&test_cert,
                 &test_cert_len);
    if (!status) {
        goto cleanup;
    }

    zero_mem(file_name_buffer, 1024);
    copy_mem(file_name_buffer, Path, len);
    copy_mem(file_name_buffer + len - 1, "/ca.cert.der",
         sizeof("/ca.cert.der"));
    status = read_input_file(file_name_buffer, (void **)&test_ca_cert,
                 &test_ca_cert_len);
    if (!status) {
        goto cleanup;
    }

    zero_mem(file_name_buffer, 1024);
    copy_mem(file_name_buffer, Path, len);
    copy_mem(file_name_buffer + len - 1, "/bundle_requester.certchain.der",
         sizeof("/bundle_requester.certchain.der"));
    status = read_input_file(file_name_buffer, (void **)&test_bundle_cert,
                 &test_bundle_cert_len);
    if (!status) {
        goto cleanup;
    }

    zero_mem(file_name_buffer, 1024);
    copy_mem(file_name_buffer, Path, len);
    copy_mem(file_name_buffer + len - 1, "/end_requester.cert.der",
         sizeof("/end_requester.cert.der"));
    status = read_input_file(file_name_buffer, (void **)&test_end_cert,
                 &test_end_cert_len);
    if (!status) {
        goto cleanup;
    }

    //
    // X509 Certificate Verification.
    //
    my_print("\n- X509 Certificate Verification with Trusted CA ...");
    status = x509_verify_cert(test_cert, test_cert_len, test_ca_cert,
                  test_ca_cert_len);
    if (!status) {
        my_print("[Fail]\n");
        goto cleanup;
    } else {
        my_print("[Pass]\n");
    }

    //
    // X509 Certificate Chain Verification.
    //
    DEBUG((DEBUG_INFO, "- X509 Certificate Chain Verification ... "));
    status = x509_verify_cert_chain((uint8_t *)test_ca_cert, test_ca_cert_len,
                    (uint8_t *)test_bundle_cert,
                    test_bundle_cert_len);
    if (!status) {
        my_print("[Fail]\n");
        goto cleanup;
    } else {
        my_print("[Pass]\n");
    }

    //
    // X509 Get leaf certificate from cert_chain Verificate
    //
    DEBUG((DEBUG_INFO,
           "- X509 Certificate Chain get leaf certificate Verification ... "));
    status = x509_get_cert_from_cert_chain(test_bundle_cert,
                           test_bundle_cert_len, -1,
                           &leaf_cert, &leaf_cert_len);
    if (!status) {
        my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_end_cert_len) {
        my_print("[Fail]\n");
        goto cleanup;
    }
    if (const_compare_mem(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
        my_print("[Fail]\n");
        goto cleanup;
    } else {
        my_print("[Pass]\n");
    }

    //
    // X509 Get leaf certificate from cert_chain Verificate
    //
    DEBUG((DEBUG_INFO,
           "- X509 Certificate Chain get leaf certificate Verification ... "));
    status = x509_get_cert_from_cert_chain(test_bundle_cert,
                           test_bundle_cert_len, 2,
                           &leaf_cert, &leaf_cert_len);
    if (!status) {
        my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_end_cert_len) {
        my_print("[Fail]\n");
        goto cleanup;
    }
    if (const_compare_mem(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
        my_print("[Fail]\n");
        goto cleanup;
    } else {
        my_print("[Pass]\n");
    }

    //
    // X509 Get root certificate from cert_chain Verificate
    //
    DEBUG((DEBUG_INFO,
           "- X509 Certificate Chain get root certificate Verification ... "));
    status = x509_get_cert_from_cert_chain(test_bundle_cert,
                           test_bundle_cert_len, 0,
                           &leaf_cert, &leaf_cert_len);
    if (!status) {
        my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_ca_cert_len) {
        my_print("[Fail]\n");
        goto cleanup;
    }
    if (const_compare_mem(leaf_cert, test_ca_cert, leaf_cert_len) != 0) {
        my_print("[Fail]\n");
        goto cleanup;
    } else {
        my_print("[Pass]\n");
    }

    //
    // X509 Certificate subject Retrieving.
    //
    my_print("- X509 Certificate subject Bytes Retrieving ... ");
    subject_size = 0;
    status = x509_get_subject_name(test_cert, test_cert_len, NULL,
                       &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = x509_get_subject_name(test_cert, test_cert_len, subject,
                       &subject_size);
    free_pool(subject);
    if (!status) {
        my_print("[Fail]");
        goto cleanup;
    } else {
        my_print("[Pass]");
    }

    my_print("\n- X509 Certificate context Retrieving ... ");
    //
    // Get common_name from X509 Certificate subject
    //
    common_name_size = 64;
    zero_mem(common_name, common_name_size);
    ret = x509_get_common_name(test_cert, test_cert_len, common_name,
                   &common_name_size);
    if (RETURN_ERROR(ret)) {
        my_print("\n  - Retrieving Common name - [Fail]");
        goto cleanup;
    } else {
        DEBUG((DEBUG_INFO,
               "\n  - Retrieving Common name = \"%s\" (size = %d)",
               common_name, common_name_size));
        my_print(" - [PASS]");
    }

    //
    // Get Issuer OrganizationName from X509 Certificate subject
    //
    common_name_size = 64;
    zero_mem(common_name, common_name_size);
    ret = x509_get_organization_name(test_cert, test_cert_len, common_name,
                     &common_name_size);
    if (ret != RETURN_NOT_FOUND) {
        my_print("\n  - Retrieving Oraganization name - [Fail]");
        goto cleanup;
    } else {
        my_print("\n  - Retrieving Oraganization name - [PASS]");
    }

    //
    // Get version from X509 Certificate
    //
    cert_version = 0;
    ret = x509_get_version(test_cert, test_cert_len, &cert_version);
    if (RETURN_ERROR(ret)) {
        my_print("\n  - Retrieving version - [Fail]");
        goto cleanup;
    } else {
        DEBUG((DEBUG_INFO, "\n  - Retrieving version = %d - ",
               cert_version));
        my_print("[Pass]");
    }

    //
    // Get Serial from X509 Certificate
    //
    asn1_buffer_len = 1024;
    zero_mem(asn1_buffer, asn1_buffer_len);
    ret = x509_get_serial_number(test_cert, test_cert_len, asn1_buffer,
                     &asn1_buffer_len);
    if (RETURN_ERROR(ret)) {
        my_print("\n  - Retrieving serial_number - [Fail]");
        goto cleanup;
    } else {
        DEBUG((DEBUG_INFO, "\n  - Retrieving serial_number = %d - ",
               *((uint64_t *)asn1_buffer)));
        my_print("[Pass]");
    }

    //
    // X509 Certificate subject Retrieving.
    //
    my_print("\n  - Retrieving issuer Bytes ... ");
    subject_size = 0;
    status = x509_get_issuer_name(test_cert, test_cert_len, NULL,
                      &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = x509_get_issuer_name(test_cert, test_cert_len, subject,
                      &subject_size);
    free_pool(subject);
    if (!status) {
        my_print("[Fail]");
        goto cleanup;
    } else {
        my_print(" - [Pass]");
    }

    //
    // Get Issuer common_name from X509 Certificate subject
    //
    common_name_size = 64;
    zero_mem(common_name, common_name_size);
    ret = x509_get_issuer_common_name(test_cert, test_cert_len, common_name,
                      &common_name_size);
    if (RETURN_ERROR(ret)) {
        my_print("\n  - Retrieving Issuer Common name - [Fail]");
        goto cleanup;
    } else {
        DEBUG((DEBUG_INFO,
               "\n  - Retrieving Issuer Common name = \"%s\" (size = %d) - ",
               common_name, common_name_size));
        my_print("[Pass]");
    }

    //
    // Get Issuer OrganizationName from X509 Certificate subject
    //
    common_name_size = 64;
    zero_mem(common_name, common_name_size);
    ret = x509_get_issuer_orgnization_name(test_cert, test_cert_len,
                           common_name, &common_name_size);
    if (ret != RETURN_NOT_FOUND) {
        my_print("\n  - Retrieving Issuer Oraganization name - [Fail]");
        goto cleanup;
    } else {
        my_print("\n  - Retrieving Issuer Oraganization name - [Pass]");
    }

    //
    // Get X509GetSubjectAltName
    //
    asn1_buffer_len = 1024;
    zero_mem(asn1_buffer, asn1_buffer_len);
    ret = x509_get_extension_data(test_end_cert, test_end_cert_len,
                      (uint8_t *)m_oid_subject_alt_name,
                      sizeof(m_oid_subject_alt_name),
                      asn1_buffer, &asn1_buffer_len);
    if (RETURN_ERROR(ret)) {
        my_print("\n  - Retrieving  SubjectAltName otherName - [Fail]");
        goto cleanup;
    } else {
        DEBUG((DEBUG_INFO,
               "\n  - Retrieving  SubjectAltName (size = %d) ",
               asn1_buffer_len));
        my_print("- [Pass]");
    }

    //
    // Get X509 Validity
    //
    end_cert_from_len = 64;
    end_cert_to_len = 64;
    status = x509_get_validity(test_end_cert, test_end_cert_len,
                   end_cert_from, &end_cert_from_len,
                   end_cert_to, &end_cert_to_len);
    if (!status) {
        my_print("\n  - Retrieving Validity - [Fail]");
        goto cleanup;
    } else {
        my_print("\n  - Retrieving Validity - [Pass]");
    }

    asn1_buffer_len = 64;
    ret = x509_set_date_time("19700101000000Z", date_time1,
                 &asn1_buffer_len);
    if ((ret == RETURN_SUCCESS) && (asn1_buffer_len != 0)) {
        my_print("\n  - Set date_time - [Pass]");
    } else {
        my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    asn1_buffer_len = 64;
    ret = x509_set_date_time("19700201000000Z", date_time2,
                 &asn1_buffer_len);
    if ((ret == RETURN_SUCCESS) && (asn1_buffer_len != 0)) {
        my_print("\n  - Set date_time - [Pass]");
    } else {
        my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    if (x509_compare_date_time(date_time1, date_time2) < 0) {
        my_print("\n  - Compare date_time - [Pass]");
    } else {
        my_print("\n  - Compare date_time- [Fail]");
        goto cleanup;
    }

    my_print("\n");
    ret_status = RETURN_SUCCESS;

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
    return ret_status;
}
