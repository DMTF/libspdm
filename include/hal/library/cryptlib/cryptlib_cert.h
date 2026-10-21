/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_CERT_H
#define CRYPTLIB_CERT_H

#if LIBSPDM_CERT_PARSE_SUPPORT

/**
 * Retrieve the tag and length of the tag.
 *
 * tag is the whole identifier octet, which combines the class, the constructed bit and the tag
 * number, such as LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED. On success,
 * *ptr points to the contents of the element, *length is their size, and the contents end at or
 * before end. On failure, *ptr and *length are unspecified, so the caller must not use them.
 *
 * @param ptr      On input, the position of the element in the ASN.1 data.
 *                 On output, the position of its contents.
 * @param end      End of data.
 * @param length   The variable that will receive the length of the contents.
 * @param tag      The expected identifier octet.
 *
 * @retval  true   Get tag successful.
 * @retval  false  Failed to get tag or tag not match.
 **/
extern bool libspdm_asn1_get_tag(uint8_t **ptr, const uint8_t *end, size_t *length, uint32_t tag);

/**
 * Retrieve the subject bytes from one X.509 certificate.
 *
 * The subject bytes are the DER encoding of the subject Name, including its SEQUENCE header. If
 * subject_size is too small then false is returned and subject_size is set to the size needed. To
 * get the size, pass a NULL cert_subject and a subject_size of 0. Otherwise cert_subject must not
 * be NULL.
 *
 * If cert is NULL, then return false.
 * If subject_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert          Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     Size of the X509 certificate in bytes.
 * @param[out]     cert_subject  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] subject_size  The size in bytes of the cert_subject buffer on input,
 *                               and the size of buffer returned cert_subject on output.
 *
 * @retval  true   The certificate subject was retrieved successfully.
 * @retval  false  If subject_size is not 0 on output, it was too small and is now the size needed.
 * @retval  false  If subject_size is 0 on output, the certificate is invalid.
 **/
extern bool libspdm_x509_get_subject_name(const uint8_t *cert, size_t cert_size,
                                          uint8_t *cert_subject,
                                          size_t *subject_size);

/**
 * Retrieve the version from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert       Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size  Size of the X509 certificate in bytes.
 * @param[out]     version    Pointer to the retrieved version, which is zero-based (2 for v3).
 *
 * @retval  true   The version was retrieved successfully.
 * @retval  false  The version could not be retrieved.
 **/
extern bool libspdm_x509_get_version(const uint8_t *cert, size_t cert_size, size_t *version);

/**
 * Retrieve the serialNumber from one X.509 certificate.
 *
 * If serial_number_size is too small then false is returned and serial_number_size is set to the
 * size needed. To get the size, pass a NULL serial_number and a serial_number_size of 0.
 * Otherwise serial_number must not be NULL.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert                Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size           Size of the X509 certificate in bytes.
 * @param[out]     serial_number       Pointer to the retrieved certificate serial_number bytes.
 * @param[in, out] serial_number_size  The size in bytes of the serial_number buffer on input,
 *                                     and the size of buffer returned serial_number on output.
 *
 * @retval  true   The serial number was retrieved successfully.
 * @retval  false  The certificate is invalid, or serial_number_size is too small.
 **/
extern bool libspdm_x509_get_serial_number(const uint8_t *cert, size_t cert_size,
                                           uint8_t *serial_number,
                                           size_t *serial_number_size);

/**
 * Retrieve the signature algorithm from one X.509 certificate.
 *
 * If oid_size is too small then false is returned and oid_size is set to the size needed. To get
 * the size, pass a NULL oid and an oid_size of 0. Otherwise oid must not be NULL.
 *
 * @param[in]      cert       Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size  Size of the X509 certificate in bytes.
 * @param[out]     oid        Signature algorithm Object identifier buffer.
 * @param[in,out]  oid_size   Signature algorithm Object identifier buffer size.
 *
 * @retval  true    If oid_size is not 0 on output, the signature algorithm was retrieved
 *                  successfully.
 * @retval  true    If oid_size is 0 on output, the certificate was parsed, but its signature
 *                  algorithm is not recognized.
 * @retval  false   If oid_size is not 0 on output, it was too small and is now the size needed.
 * @retval  false   If oid_size is 0 on output, the certificate is invalid.
 **/
extern bool libspdm_x509_get_signature_algorithm(const uint8_t *cert,
                                                 size_t cert_size, uint8_t *oid,
                                                 size_t *oid_size);

/**
 * Retrieve the issuer bytes from one X.509 certificate.
 *
 * The issuer bytes are the DER encoding of the issuer Name, including its SEQUENCE header. If
 * issuer_size is too small then false is returned and issuer_size is set to the size needed. To get
 * the size, pass a NULL cert_issuer and an issuer_size of 0. Otherwise cert_issuer must not be
 * NULL.
 *
 * If cert is NULL, then return false.
 * If issuer_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size    Size of the X509 certificate in bytes.
 * @param[out]     cert_issuer  Pointer to the retrieved certificate issuer bytes.
 * @param[in, out] issuer_size  The size in bytes of the cert_issuer buffer on input,
 *                              and the size of buffer returned cert_issuer on output.
 *
 * @retval  true   The certificate issuer was retrieved successfully.
 * @retval  false  If issuer_size is not 0 on output, it was too small and is now the size needed.
 * @retval  false  If issuer_size is 0 on output, the certificate is invalid.
 **/
extern bool libspdm_x509_get_issuer_name(const uint8_t *cert, size_t cert_size,
                                         uint8_t *cert_issuer,
                                         size_t *issuer_size);

/**
 * Retrieve Extension data from one X.509 certificate.
 *
 * oid is the content octets of the extension's OBJECT IDENTIFIER, without its tag and length. The
 * extension data is the contents of the extension's extnValue OCTET STRING, without its tag and
 * length.
 *
 * @param[in]      cert                 Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size            Size of the X509 certificate in bytes.
 * @param[in]      oid                  Object identifier buffer
 * @param[in]      oid_size             Object identifier buffer size
 * @param[out]     extension_data       Extension bytes.
 * @param[in, out] extension_data_size  Extension bytes size.
 *
 * @retval true   If the returned extension_data_size == 0, it means that cert and oid are valid, but the oid extension is not found;
 *                If the returned extension_data_size != 0, it means that cert and oid are valid, and the oid extension is found;
 * @retval false  If the returned extension_data_size == 0, it means that cert or oid are invalid;
 *                If the returned extension_data_size != 0, it means that cert and oid are valid, and the oid extension is found,
 *                                                          but the store buffer is too small.
 **/
extern bool libspdm_x509_get_extension_data(const uint8_t *cert, size_t cert_size,
                                            const uint8_t *oid, size_t oid_size,
                                            uint8_t *extension_data,
                                            size_t *extension_data_size);

/**
 * Retrieve the Validity from one X.509 certificate
 *
 * from and to receive date_time objects for notBefore and notAfter. A date_time object is opaque to
 * libspdm, which only passes it to libspdm_x509_compare_date_time(). libspdm provides 64-byte
 * buffers, so a date_time object must fit in 64 bytes. If a buffer is too small then false is
 * returned and the size of that buffer is set to the size needed.
 *
 * If cert is NULL, then return false.
 * If from_size or to_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert       Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size  Size of the X509 certificate in bytes.
 * @param[out]     from       notBefore Pointer to date_time object.
 * @param[in,out]  from_size  notBefore date_time object size.
 * @param[out]     to         notAfter Pointer to date_time object.
 * @param[in,out]  to_size    notAfter date_time object size.
 *
 * Note: libspdm_x509_compare_date_time to compare date_time object
 *       libspdm_x509_set_date_time to get a date_time object from a date_time_str
 *
 * @retval  true   The certificate Validity was retrieved successfully.
 * @retval  false  If from_size or to_size is not 0 on output, a buffer was too small.
 * @retval  false  If from_size and to_size are 0 on output, the certificate is invalid.
 **/
extern bool libspdm_x509_get_validity(const uint8_t *cert, size_t cert_size,
                                      uint8_t *from, size_t *from_size, uint8_t *to,
                                      size_t *to_size);

/**
 * Convert a date and time string into a date_time object.
 *
 * date_time_str has the form YYYYMMDDhhmmssZ, where Z stands for UTC. The date_time object has the
 * format of libspdm_x509_get_validity(). If date_time_size is too small then false is returned and
 * date_time_size is set to the size needed.
 *
 * date_time_str and date_time_size must not be NULL.
 * If this interface is not supported, then return false.
 *
 * @param[in]      date_time_str   date_time string like YYYYMMDDhhmmssZ.
 * @param[out]     date_time       Pointer to a date_time object.
 * @param[in,out]  date_time_size  date_time object buffer size.
 *
 * @retval  true   The date_time object was set.
 * @retval  false  date_time_str is invalid, or date_time_size is too small.
 **/
extern bool libspdm_x509_set_date_time(const char *date_time_str, void *date_time,
                                       size_t *date_time_size);

/**
 * Compare date_time1 object and date_time2 object.
 *
 * If date_time1 is NULL, then return -2.
 * If date_time2 is NULL, then return -2.
 * If date_time1 == date_time2, then return 0
 * If date_time1 > date_time2, then return 1
 * If date_time1 < date_time2, then return -1
 *
 * @param[in]      date_time1  Pointer to a date_time Object
 * @param[in]      date_time2  Pointer to a date_time Object
 *
 * @retval   0  If date_time1 == date_time2
 * @retval   1  If date_time1 > date_time2
 * @retval  -1  If date_time1 < date_time2
 * @retval  -2  If date_time1 or date_time2 is NULL, or if they cannot be compared.
 **/
extern int32_t libspdm_x509_compare_date_time(const void *date_time1, const void *date_time2);

/**
 * Retrieve the key usage from one X.509 certificate.
 *
 * @param[in]      cert       Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size  Size of the X509 certificate in bytes.
 * @param[out]     usage      Key usage (LIBSPDM_CRYPTO_X509_KU_*)
 *
 * @retval  true   if the usage is not equal to 0. The certificate key usage retrieved successfully.
 * @retval  true   if the usage is equal 0. The certificate parse successfully, but the cert doesn't have key usage.
 * @retval  false  Invalid certificate, or usage is NULL.
 **/
extern bool libspdm_x509_get_key_usage(const uint8_t *cert, size_t cert_size, size_t *usage);

/**
 * Retrieve the Extended key usage from one X.509 certificate.
 *
 * The usage bytes are the contents of the extension's extnValue OCTET STRING, which is the DER
 * encoding of the ExtKeyUsageSyntax SEQUENCE.
 *
 * @param[in]      cert        Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size   Size of the X509 certificate in bytes.
 * @param[out]     usage       Key usage bytes.
 * @param[in, out] usage_size  Key usage buffer size in bytes.
 *
 * @retval true   If the returned usage_size == 0, it means that cert is valid, but the Extended key usage is not found;
 *                If the returned usage_size != 0, it means that cert is valid, and the Extended key usage is found;
 * @retval false  If the returned usage_size == 0, it means that cert is invalid;
 *                If the returned usage_size != 0, it means that cert is valid, and the Extended key usage is found,
 *                                                 but the store buffer is too small.
 **/
extern bool libspdm_x509_get_extended_key_usage(const uint8_t *cert,
                                                size_t cert_size, uint8_t *usage,
                                                size_t *usage_size);

/**
 * Retrieve the basic constraints from one X.509 certificate.
 *
 * The basic constraints bytes are the contents of the extension's extnValue OCTET STRING, which is
 * the DER encoding of the BasicConstraints SEQUENCE.
 *
 * @param[in]      cert                     Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size                Size of the X509 certificate in bytes.
 * @param[out]     basic_constraints        Basic constraints bytes.
 * @param[in, out] basic_constraints_size   Basic constraints buffer size in bytes.
 *
 * @retval true   If the returned basic_constraints_size == 0, it means that cert is valid, but the basic_constraints is not found;
 *                If the returned basic_constraints_size != 0, it means that cert is valid, and the basic_constraints is found;
 * @retval false  If the returned basic_constraints_size == 0, it means that cert is invalid;
 *                If the returned basic_constraints_size != 0, it means that cert is valid, and the basic_constraints is found,
 *                                                             but the store buffer is too small.
 **/
extern bool libspdm_x509_get_extended_basic_constraints(const uint8_t *cert,
                                                        size_t cert_size,
                                                        uint8_t *basic_constraints,
                                                        size_t *basic_constraints_size);

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * Besides the signature, this function should check the validity period of each certificate against
 * the current time, that the issuing certificate is a CA, and that no certificate has an
 * unrecognized critical extension, because libspdm does not check these itself.
 *
 * If cert is self-issued and is the same certificate as ca_cert, then it is accepted as its own
 * trust anchor, and its signature is not checked.
 *
 * If cert is NULL, then return false.
 * If ca_cert is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert          Pointer to the DER-encoded X509 certificate to be verified.
 * @param[in]      cert_size     Size of the X509 certificate in bytes.
 * @param[in]      ca_cert       Pointer to the DER-encoded trusted CA certificate.
 * @param[in]      ca_cert_size  Size of the CA Certificate in bytes.
 *
 * @retval  true   The certificate was issued by the trusted CA.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                 trusted CA.
 * @retval  false  This interface is not supported.
 *
 **/
extern bool libspdm_x509_verify_cert(const uint8_t *cert, size_t cert_size,
                                     const uint8_t *ca_cert, size_t ca_cert_size);

/**
 * Verify a certificate chain against a trusted root certificate.
 *
 * root_cert is the trust anchor, which is typically self-signed. The last certificate in cert_chain
 * is the leaf certificate, and the certificates before it are intermediate certificates. If the
 * first certificate in cert_chain is identical to root_cert, then root_cert must be a self-signed
 * root certificate. This function applies the checks of libspdm_x509_verify_cert() to every
 * certificate in the path.
 *
 * @param[in]      root_cert          Pointer to the DER-encoded trust anchor certificate.
 * @param[in]      root_cert_length   Size of the trust anchor certificate in bytes.
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                    where the first certificate is signed by root_cert
 *                                    or is root_cert itself, and each subsequent certificate
 *                                    is signed by the preceding certificate.
 * @param[in]      cert_chain_length  Total length of the certificate chain, in bytes.
 *
 * @retval  true   The last certificate in cert_chain chains to root_cert.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                 trusted CA.
 **/
extern bool libspdm_x509_verify_cert_chain(const uint8_t *root_cert, size_t root_cert_length,
                                           const uint8_t *cert_chain,
                                           size_t cert_chain_length);

/**
 * Get one X509 certificate from cert_chain.
 *
 * The function only walks the DER SEQUENCE headers of the certificates. It does not verify the
 * chain, and the caller can use it on a chain that has not been verified yet.
 *
 * @param[in]      cert_chain         One or more concatenated ASN.1 DER-encoded X.509
 *                                    certificates.
 * @param[in]      cert_chain_length  Total length of the certificate chain, in bytes.
 *
 * @param[in]      cert_index         Index of certificate. If index is -1 indicates the
 *                                    last certificate in cert_chain.
 *
 * @param[out]     cert              The certificate at the index of cert_chain.
 * @param[out]     cert_length       The length certificate at the index of cert_chain.
 *
 * @retval  true   Success.
 * @retval  false  Failed to get certificate from certificate chain.
 **/
extern bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                                  size_t cert_chain_length,
                                                  const int32_t cert_index, const uint8_t **cert,
                                                  size_t *cert_length);

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA public key from one DER-encoded X509 certificate.
 *
 * cert and rsa_context must not be NULL.
 * If this interface is not supported, then return false.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] rsa_context  Pointer to newly generated RSA context which contain the retrieved
 *                          RSA public key component. Use libspdm_rsa_free() function to free the
 *                          resource.
 *
 * @retval  true   RSA public key was retrieved successfully.
 * @retval  false  Fail to retrieve RSA public key from X509 certificate.
 * @retval  false  This interface is not supported.
 **/
extern bool libspdm_rsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                 void **rsa_context);
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
/**
 * Retrieve the EC public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert        Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size   Size of the X509 certificate in bytes.
 * @param[out] ec_context  Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * cert and ec_context must not be NULL.
 *
 * @retval  true   EC public key was retrieved successfully.
 * @retval  false  Fail to retrieve EC public key from X509 certificate.
 *
 **/
extern bool libspdm_ec_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                void **ec_context);
#endif /* LIBSPDM_ECDSA_SUPPORT */

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
/**
 * Retrieve the Ed public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] ecd_context  Pointer to newly generated Ed DSA context which contain the retrieved
 *                          Ed public key component. Use libspdm_ecd_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed public key was retrieved successfully.
 * @retval  false  Fail to retrieve Ed public key from X509 certificate.
 *
 **/
extern bool libspdm_ecd_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                 void **ecd_context);
#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */

#if LIBSPDM_SM2_DSA_SUPPORT
/**
 * Retrieve the sm2 public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] sm2_context  Pointer to newly generated sm2 context which contain the retrieved
 *                          sm2 public key component. Use libspdm_sm2_dsa_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 public key was retrieved successfully.
 * @retval  false  Fail to retrieve sm2 public key from X509 certificate.
 *
 **/
extern bool libspdm_sm2_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                 void **sm2_context);
#endif /* LIBSPDM_SM2_DSA_SUPPORT */

#if LIBSPDM_ML_DSA_SUPPORT
/**
 * Retrieve the mldsa public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated mldsa context which contain the retrieved
 *                          mldsa public key component. Use libspdm_mldsa_free() function to free the
 *                          resource.
 *
 * cert and dsa_context must not be NULL.
 *
 * @retval  true   mldsa public key was retrieved successfully.
 * @retval  false  Fail to retrieve mldsa public key from X509 certificate.
 *
 **/
extern bool libspdm_mldsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                   void **dsa_context);
#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT
/**
 * Retrieve the slhdsa public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated slhdsa context which contain the retrieved
 *                          slhdsa public key component. Use libspdm_slhdsa_free() function to free the
 *                          resource.
 *
 * cert and dsa_context must not be NULL.
 *
 * @retval  true   slhdsa public key was retrieved successfully.
 * @retval  false  Fail to retrieve slhdsa public key from X509 certificate.
 *
 **/
extern bool libspdm_slhdsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                    void **dsa_context);
#endif /* LIBSPDM_SLH_DSA_SUPPORT */

#endif /* LIBSPDM_CERT_PARSE_SUPPORT */

#endif /* CRYPTLIB_CERT_H */
