/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_pqccrypt_lib.h"

#if LIBSPDM_CERT_PARSE_SUPPORT
/**
 * Construct a X509 object from DER-encoded certificate data.
 *
 * If cert is NULL, then return false.
 * If single_x509_cert is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  cert              Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size         The size of certificate data in bytes.
 * @param[out] single_x509_cert  The generated X509 object.
 *
 * @retval  true   The X509 object generation succeeded.
 * @retval  false  The operation failed.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_pqc_x509_construct_certificate(const uint8_t *cert, size_t cert_size,
                                            uint8_t **single_x509_cert)
{
    // TBD 1.4 - Need cert chain parsing for PQC.
    return false;
}

/**
 * Generate a CSR.
 *
 * @param[in]      hash_nid              hash algo for sign
 * @param[in]      pqc_asym_nid          pqc_asym algo for sign
 *
 * @param[in]      requester_info        requester info to gen CSR
 * @param[in]      requester_info_length The len of requester info
 *
 * @param[in]       is_ca                if true, set basic_constraints: CA:true; Otherwise, set to false.
 *
 * @param[in]      context               Pointer to asymmetric context
 * @param[in]      subject_name          Subject name: should be break with ',' in the middle
 *                                       example: "C=AA,CN=BB"
 *
 * Subject names should contain a comma-separated list of OID types and values:
 * The valid OID type name is in:
 * {"CN", "commonName", "C", "countryName", "O", "organizationName","L",
 * "OU", "organizationalUnitName", "ST", "stateOrProvinceName", "emailAddress",
 * "serialNumber", "postalAddress", "postalCode", "dnQualifier", "title",
 * "SN","givenName","GN", "initials", "pseudonym", "generationQualifier", "domainComponent", "DC"}.
 * Note: The object of C and countryName should be CSR Supported Country Codes
 *
 * @param[in, out]      csr_len               For input, csr_len is the size of store CSR buffer.
 *                                            For output, csr_len is CSR len for DER format
 * @param[in, out]      csr_pointer           For input, csr_pointer is buffer address to store CSR.
 *                                            For output, csr_pointer is address for stored CSR.
 *                                            The csr_pointer address will be changed.
 * @param[in]           base_cert             An optional leaf certificate whose
 *                                            extensions should be copied to the CSR
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen CSR.
 **/
bool libspdm_gen_pqc_x509_csr(size_t hash_nid, size_t pqc_asym_nid,
                              uint8_t *requester_info, size_t requester_info_length,
                              bool is_ca,
                              void *context, char *subject_name,
                              size_t *csr_len, uint8_t *csr_pointer,
                              void *base_cert)
{
    // TBD 1.4 - Need cert chain parsing for PQC.
    return false;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
