/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_EXT_H
#define CRYPTLIB_EXT_H

#include "hal/base.h"

/**
 * Retrieve the common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert              Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         Size of the X509 certificate in bytes.
 * @param[out]     common_name       Buffer to contain the retrieved certificate common
 *                                   name string (UTF8). At most common_name_size bytes will be
 *                                   written and the string will be null terminated. May be
 *                                   NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size  The size in bytes of the common_name buffer on input,
 *                                   and the size of buffer returned common_name on output.
 *                                   If common_name is NULL then the amount of space needed
 *                                   in buffer (including the final null) is returned.
 *
 * @retval  true
 * @retval  false
 **/
extern bool libspdm_x509_get_common_name(const uint8_t *cert, size_t cert_size,
                                         char *common_name,
                                         size_t *common_name_size);

/**
 * Retrieve the organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert              Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         Size of the X509 certificate in bytes.
 * @param[out]     name_buffer       Buffer to contain the retrieved certificate organization
 *                                   name string. At most name_buffer_size bytes will be
 *                                   written and the string will be null terminated. May be
 *                                   NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size  The size in bytes of the name buffer on input,
 *                                   and the size of buffer returned name on output.
 *                                   If name_buffer is NULL then the amount of space needed
 *                                   in buffer (including the final null) is returned.
 *
 * @retval  true
 * @retval  false
 **/
extern bool libspdm_x509_get_organization_name(const uint8_t *cert, size_t cert_size,
                                               char *name_buffer,
                                               size_t *name_buffer_size);

/**
 * Retrieve the issuer common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert              Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         Size of the X509 certificate in bytes.
 * @param[out]     common_name       Buffer to contain the retrieved certificate issuer common
 *                                   name string. At most common_name_size bytes will be
 *                                   written and the string will be null terminated. May be
 *                                   NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size  The size in bytes of the common_name buffer on input,
 *                                   and the size of buffer returned common_name on output.
 *                                   If common_name is NULL then the amount of space needed
 *                                   in buffer (including the final null) is returned.
 *
 * @retval  true
 * @retval  false
 **/
extern bool libspdm_x509_get_issuer_common_name(const uint8_t *cert, size_t cert_size,
                                                char *common_name,
                                                size_t *common_name_size);

/**
 * Retrieve the issuer organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert              Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         Size of the X509 certificate in bytes.
 * @param[out]     name_buffer       Buffer to contain the retrieved certificate issuer organization
 *                                   name string. At most name_buffer_size bytes will be
 *                                   written and the string will be null terminated. May be
 *                                   NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size  The size in bytes of the name buffer on input,
 *                                   and the size of buffer returned name on output.
 *                                   If name_buffer is NULL then the amount of space needed
 *                                   in buffer (including the final null) is returned.
 *
 * @retval  true
 * @retval  false
 **/
extern bool libspdm_x509_get_issuer_orgnization_name(const uint8_t *cert, size_t cert_size,
                                                     char *name_buffer,
                                                     size_t *name_buffer_size);

/**
 * Retrieve the signature algorithm from one X.509 certificate.
 *
 * @param[in]      cert       Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size  Size of the X509 certificate in bytes.
 * @param[out]     oid        Signature algorithm Object identifier buffer.
 * @param[in,out]  oid_size   Signature algorithm Object identifier buffer size.
 *
 * @retval  true
 * @retval  false
 **/
extern bool libspdm_x509_get_signature_algorithm(const uint8_t *cert,
                                                 size_t cert_size, uint8_t *oid,
                                                 size_t *oid_size);

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
extern bool libspdm_x509_construct_certificate(const uint8_t *cert, size_t cert_size,
                                               uint8_t **single_x509_cert);

/**
 * Construct a X509 stack object from a list of DER-encoded certificate data.
 *
 * If x509_stack is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
 *                              On output, pointer to the X509 stack object with new
 *                              inserted X509 certificate.
 * @param           ...         A list of DER-encoded single certificate data followed
 *                              by certificate size. A NULL terminates the list. The
 *                              pairs are the arguments to libspdm_x509_construct_certificate().
 *
 * @retval  true   The X509 stack construction succeeded.
 * @retval  false  The construction operation failed.
 * @retval  false  This interface is not supported.
 **/
extern bool libspdm_x509_construct_certificate_stack(uint8_t **x509_stack, ...);

/**
 * Release the specified X509 object.
 *
 * If the interface is not supported, then ASSERT().
 *
 * @param[in]  x509_cert  Pointer to the X509 object to be released.
 **/
extern void libspdm_x509_free(void *x509_cert);

/**
 * Release the specified X509 stack object.
 *
 * If the interface is not supported, then ASSERT().
 *
 * @param[in]  x509_stack  Pointer to the X509 stack object to be released.
 **/
extern void libspdm_x509_stack_free(void *x509_stack);

/**
 * Retrieve the TBSCertificate from one given X.509 certificate.
 *
 * @param[in]      cert         Pointer to the given DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     tbs_cert      DER-Encoded to-Be-Signed certificate.
 * @param[out]     tbs_cert_size  size of the TBS certificate in bytes.
 *
 * If cert is NULL, then return false.
 * If tbs_cert is NULL, then return false.
 * If tbs_cert_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @retval  true   The TBSCertificate was retrieved successfully.
 * @retval  false  Invalid X.509 certificate.
 **/
extern bool libspdm_x509_get_tbs_cert(const uint8_t *cert, size_t cert_size,
                                      uint8_t **tbs_cert, size_t *tbs_cert_size);

/**
 * Retrieve the RSA Private key from the password-protected PEM key data.
 *
 * If pem_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  pem_data     Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size     Size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] rsa_context  Pointer to new-generated RSA context which contain the retrieved
 *                          RSA private key component. Use libspdm_rsa_free() function to free the
 *                          resource.
 *
 * @retval  true   RSA Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 * @retval  false  This interface is not supported.
 **/
extern bool libspdm_rsa_get_private_key_from_pem(const uint8_t *pem_data,
                                                 size_t pem_size,
                                                 const char *password,
                                                 void **rsa_context);

/**
 * Retrieve the EC Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data    Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size    Size of the PEM key data in bytes.
 * @param[in]  password    NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ec_context  Pointer to new-generated EC DSA context which contain the retrieved
 *                         EC private key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
extern bool libspdm_ec_get_private_key_from_pem(const uint8_t *pem_data, size_t pem_size,
                                                const char *password,
                                                void **ec_context);

/**
 * Retrieve the Ed Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data     Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size     Size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ecd_context  Pointer to new-generated Ed DSA context which contain the retrieved
 *                          Ed private key component. Use libspdm_ecd_free() function to free the
 *                          resource.
 *
 * If pem_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
extern bool libspdm_ecd_get_private_key_from_pem(const uint8_t *pem_data,
                                                 size_t pem_size,
                                                 const char *password,
                                                 void **ecd_context);

/**
 * Retrieve the sm2 Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data     Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size     Size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] sm2_context  Pointer to new-generated sm2 context which contain the retrieved
 *                          sm2 private key component. Use sm2_free() function to free the
 *                          resource.
 *
 * If pem_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
extern bool libspdm_sm2_get_private_key_from_pem(const uint8_t *pem_data,
                                                 size_t pem_size,
                                                 const char *password,
                                                 void **sm2_context);
#endif /* CRYPTLIB_EXT_H */
