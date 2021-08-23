/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  X.509 Certificate Handler Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>

///
/// OID
///
static const uint8 m_oid_common_name[] = { 0x55, 0x04, 0x03 };
static const uint8 m_oid_organization_name[] = { 0x55, 0x04, 0x0A };
static const uint8 m_oid_ext_key_usage[] = { 0x55, 0x1D, 0x25 };

/**
  Construct a X509 object from DER-encoded certificate data.

  If cert is NULL, then return FALSE.
  If single_x509_cert is NULL, then return FALSE.

  @param[in]  cert            Pointer to the DER-encoded certificate data.
  @param[in]  cert_size        The size of certificate data in bytes.
  @param[out] single_x509_cert  The generated X509 object.

  @retval     TRUE            The X509 object generation succeeded.
  @retval     FALSE           The operation failed.

**/
boolean x509_construct_certificate(IN const uint8 *cert, IN uintn cert_size,
				   OUT uint8 **single_x509_cert)
{
	mbedtls_x509_crt *mbedtls_cert;
	int32 ret;

	if (cert == NULL || single_x509_cert == NULL || cert_size == 0) {
		return FALSE;
	}

	mbedtls_cert = allocate_pool(sizeof(mbedtls_x509_crt));
	if (mbedtls_cert == NULL) {
		return FALSE;
	}

	mbedtls_x509_crt_init(mbedtls_cert);

	*single_x509_cert = (uint8 *)(void *)mbedtls_cert;
	ret = mbedtls_x509_crt_parse_der(mbedtls_cert, cert, cert_size);

	return ret == 0;
}

static boolean X509ConstructCertificateStackV(IN OUT uint8 **x509_stack,
					      IN VA_LIST args)
{
	uint8 *cert;
	uintn cert_size;
	int32 index;
	int32 ret;

	if (x509_stack == NULL) {
		return FALSE;
	}

	ret = 0;
	mbedtls_x509_crt *crt = (mbedtls_x509_crt *)*x509_stack;
	if (crt == NULL) {
		crt = allocate_pool(sizeof(mbedtls_x509_crt));
		if (crt == NULL) {
			return FALSE;
		}
		mbedtls_x509_crt_init(crt);
		*x509_stack = (uint8 *)crt;
	}

	for (index = 0;; index++) {
		//
		// If cert is NULL, then it is the end of the list.
		//
		cert = VA_ARG(args, uint8 *);
		if (cert == NULL) {
			break;
		}

		cert_size = VA_ARG(args, uintn);
		if (cert_size == 0) {
			break;
		}

		ret = mbedtls_x509_crt_parse_der(crt, cert, cert_size);

		if (ret != 0) {
			break;
		}
	}
	return ret == 0;
}

/**
  Construct a X509 stack object from a list of DER-encoded certificate data.

  If x509_stack is NULL, then return FALSE.

  @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
                              On output, pointer to the X509 stack object with new
                              inserted X509 certificate.
  @param           ...        A list of DER-encoded single certificate data followed
                              by certificate size. A NULL terminates the list. The
                              pairs are the arguments to x509_construct_certificate().

  @retval     TRUE            The X509 stack construction succeeded.
  @retval     FALSE           The construction operation failed.

**/
boolean x509_construct_certificate_stack(IN OUT uint8 **x509_stack, ...)
{
	VA_LIST args;
	boolean result;

	VA_START(args, x509_stack);
	result = X509ConstructCertificateStackV(x509_stack, args);
	VA_END(args);
	return result;
}

/**
  Release the specified X509 object.

  If x509_cert is NULL, then return FALSE.

  @param[in]  x509_cert  Pointer to the X509 object to be released.

**/
void x509_free(IN void *x509_cert)
{
	if (x509_cert) {
		mbedtls_x509_crt_free(x509_cert);
		free_pool(x509_cert);
	}
}

/**
  Release the specified X509 stack object.

  If x509_stack is NULL, then return FALSE.

  @param[in]  x509_stack  Pointer to the X509 stack object to be released.

**/
void x509_stack_free(IN void *x509_stack)
{
	if (x509_stack == NULL) {
		return;
	}

	mbedtls_x509_crt_free(x509_stack);
}

/**
  Retrieve the tag and length of the tag.

  @param ptr      The position in the ASN.1 data
  @param end      end of data
  @param length   The variable that will receive the length
  @param tag      The expected tag

  @retval      TRUE   Get tag successful
  @retval      FALSe  Failed to get tag or tag not match
**/
boolean asn1_get_tag(IN OUT uint8 **ptr, IN uint8 *end, OUT uintn *length,
		     IN uint32 tag)
{
	if (mbedtls_asn1_get_tag(ptr, end, length, (int32)tag) == 0) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
  Retrieve the subject bytes from one X.509 certificate.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     cert_subject  Pointer to the retrieved certificate subject bytes.
  @param[in, out] subject_size  The size in bytes of the cert_subject buffer on input,
                               and the size of buffer returned cert_subject on output.

  If cert is NULL, then return FALSE.
  If subject_size is NULL, then return FALSE.

  @retval  TRUE   The certificate subject retrieved successfully.
  @retval  FALSE  Invalid certificate, or the subject_size is too small for the result.
                  The subject_size will be updated with the required size.

**/
boolean x509_get_subject_name(IN const uint8 *cert, IN uintn cert_size,
			      OUT uint8 *cert_subject,
			      IN OUT uintn *subject_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	boolean status;

	if (cert == NULL) {
		return FALSE;
	}

	status = FALSE;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		if (*subject_size < crt.subject_raw.len) {
			*subject_size = crt.subject_raw.len;
			status = FALSE;
			goto cleanup;
		}
		if (cert_subject != NULL) {
			copy_mem(cert_subject, crt.subject_raw.p, crt.subject_raw.len);
		}
		*subject_size = crt.subject_raw.len;
		status = TRUE;
	}

cleanup:
	mbedtls_x509_crt_free(&crt);

	return status;
}

return_status
internal_x509_get_nid_name(IN mbedtls_x509_name *name, IN uint8 *oid,
			   IN uintn oid_size, IN OUT char8 *common_name,
			   OPTIONAL IN OUT uintn *common_name_size)
{
	mbedtls_asn1_named_data *data;

	data = mbedtls_asn1_find_named_data(name, oid, oid_size);
	if (data != NULL) {
		if (*common_name_size <= data->val.len) {
			*common_name_size = data->val.len + 1;
			return RETURN_BUFFER_TOO_SMALL;
		}
		if (common_name != NULL) {
			copy_mem(common_name, data->val.p, data->val.len);
			common_name[data->val.len] = '\0';
		}
		*common_name_size = data->val.len + 1;
		return RETURN_SUCCESS;
	} else {
		return RETURN_NOT_FOUND;
	}
}

return_status
internal_x509_get_subject_nid_name(IN const uint8 *cert, IN uintn cert_size,
				   IN uint8 *oid, IN uintn oid_size,
				   OUT char8 *common_name,
				   OPTIONAL IN OUT uintn *common_name_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	mbedtls_x509_name *name;
	return_status status;

	if (cert == NULL) {
		return FALSE;
	}

	status = RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		name = &(crt.subject);
		status = internal_x509_get_nid_name(
			name, oid, oid_size, common_name, common_name_size);
	}

	mbedtls_x509_crt_free(&crt);

	return status;
}

return_status
internal_x509_get_issuer_nid_name(IN const uint8 *cert, IN uintn cert_size,
				  IN uint8 *oid, IN uintn oid_size,
				  OUT char8 *common_name,
				  OPTIONAL IN OUT uintn *common_name_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	mbedtls_x509_name *name;
	return_status status;

	if (cert == NULL) {
		return FALSE;
	}

	status = RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		name = &(crt.issuer);
		status = internal_x509_get_nid_name(
			name, oid, oid_size, common_name, common_name_size);
	}

	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the common name (CN) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     common_name       buffer to contain the retrieved certificate common
                                   name string. At most common_name_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
                                   and the size of buffer returned common_name on output.
                                   If common_name is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate common_name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If common_name_size is NULL.
                                   If common_name is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no common_name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status x509_get_common_name(IN const uint8 *cert, IN uintn cert_size,
				   OUT char8 *common_name,
				   OPTIONAL IN OUT uintn *common_name_size)
{
	return internal_x509_get_subject_nid_name(
		cert, cert_size, (uint8 *)m_oid_common_name,
		sizeof(m_oid_common_name), common_name, common_name_size);
}

/**
  Retrieve the organization name (O) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate organization
                                   name string. At most name_buffer_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Organization name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status
x509_get_organization_name(IN const uint8 *cert, IN uintn cert_size,
			   OUT char8 *name_buffer,
			   OPTIONAL IN OUT uintn *name_buffer_size)
{
	return internal_x509_get_subject_nid_name(
		cert, cert_size, (uint8 *)m_oid_organization_name,
		sizeof(m_oid_organization_name), name_buffer, name_buffer_size);
}

/**
  Retrieve the RSA public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
                           RSA public key component. Use rsa_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If rsa_context is NULL, then return FALSE.

  @retval  TRUE   RSA public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve RSA public key from X509 certificate.

**/
boolean rsa_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				     OUT void **rsa_context)
{
	mbedtls_x509_crt crt;
	mbedtls_rsa_context *rsa;
	int32 ret;

	mbedtls_x509_crt_init(&crt);

	if (mbedtls_x509_crt_parse_der(&crt, cert, cert_size) != 0) {
		return FALSE;
	}

	if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_RSA) {
		mbedtls_x509_crt_free(&crt);
		return FALSE;
	}

	rsa = rsa_new();
	if (rsa == NULL) {
		mbedtls_x509_crt_free(&crt);
		return FALSE;
	}
	ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(crt.pk));
	if (ret != 0) {
		rsa_free(rsa);
		mbedtls_x509_crt_free(&crt);
		return FALSE;
	}
	mbedtls_x509_crt_free(&crt);

	*rsa_context = rsa;
	return TRUE;
}

/**
  Retrieve the EC public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
                           EC public key component. Use ec_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If ec_context is NULL, then return FALSE.

  @retval  TRUE   EC public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve EC public key from X509 certificate.

**/
boolean ec_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				    OUT void **ec_context)
{
	mbedtls_x509_crt crt;
	mbedtls_ecdh_context *ecdh;
	int32 ret;

	mbedtls_x509_crt_init(&crt);

	if (mbedtls_x509_crt_parse_der(&crt, cert, cert_size) != 0) {
		return FALSE;
	}

	if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_ECKEY) {
		mbedtls_x509_crt_free(&crt);
		return FALSE;
	}

	ecdh = allocate_zero_pool(sizeof(mbedtls_ecdh_context));
	if (ecdh == NULL) {
		mbedtls_x509_crt_free(&crt);
		return FALSE;
	}
	mbedtls_ecdh_init(ecdh);

	ret = mbedtls_ecdh_get_params(ecdh, mbedtls_pk_ec(crt.pk),
				      MBEDTLS_ECDH_OURS);
	if (ret != 0) {
		mbedtls_ecdh_free(ecdh);
		free_pool(ecdh);
		mbedtls_x509_crt_free(&crt);
		return FALSE;
	}
	mbedtls_x509_crt_free(&crt);

	*ec_context = ecdh;
	return TRUE;
}

/**
  Retrieve the Ed public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
                           Ed public key component. Use ecd_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If ecd_context is NULL, then return FALSE.

  @retval  TRUE   Ed public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve Ed public key from X509 certificate.

**/
boolean ed_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				    OUT void **ecd_context)
{
	return FALSE;
}

/**
  Retrieve the sm2 public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
                           sm2 public key component. Use sm2_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If ecd_context is NULL, then return FALSE.

  @retval  TRUE   sm2 public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve sm2 public key from X509 certificate.

**/
boolean sm2_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				     OUT void **sm2_context)
{
	return FALSE;
}

/**
  Verify one X509 certificate was issued by the trusted CA.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate to be verified.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[in]      ca_cert       Pointer to the DER-encoded trusted CA certificate.
  @param[in]      ca_cert_size   size of the CA Certificate in bytes.

  If cert is NULL, then return FALSE.
  If ca_cert is NULL, then return FALSE.

  @retval  TRUE   The certificate was issued by the trusted CA.
  @retval  FALSE  Invalid certificate or the certificate was not issued by the given
                  trusted CA.

**/
boolean x509_verify_cert(IN const uint8 *cert, IN uintn cert_size,
			 IN const uint8 *ca_cert, IN uintn ca_cert_size)
{
	int32 ret;
	mbedtls_x509_crt ca, end;
	uint32 v_flag = 0;
	mbedtls_x509_crt_profile profile = { 0 };

	if (cert == NULL || ca_cert == NULL) {
		return FALSE;
	}

	copy_mem(&profile, &mbedtls_x509_crt_profile_default,
		 sizeof(mbedtls_x509_crt_profile));

	mbedtls_x509_crt_init(&ca);
	mbedtls_x509_crt_init(&end);

	ret = mbedtls_x509_crt_parse_der(&ca, ca_cert, ca_cert_size);

	if (ret == 0) {
		ret = mbedtls_x509_crt_parse_der(&end, cert, cert_size);
	}

	if (ret == 0) {
		ret = mbedtls_x509_crt_verify_with_profile(
			&end, &ca, NULL, &profile, NULL, &v_flag, NULL, NULL);
	}

	mbedtls_x509_crt_free(&ca);
	mbedtls_x509_crt_free(&end);

	return ret == 0;
}

/**
  Verify one X509 certificate was issued by the trusted CA.

  @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
                                    where the first certificate is signed by the Root
                                    Certificate or is the Root Cerificate itself. and
                                    subsequent cerificate is signed by the preceding
                                    cerificate.
  @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.

  @param[in]      root_cert          Trusted Root Certificate buffer

  @param[in]      root_cert_length    Trusted Root Certificate buffer length

  @retval  TRUE   All cerificates was issued by the first certificate in X509Certchain.
  @retval  FALSE  Invalid certificate or the certificate was not issued by the given
                  trusted CA.
**/
boolean x509_verify_cert_chain(IN uint8 *root_cert, IN uintn root_cert_length,
			       IN uint8 *cert_chain, IN uintn cert_chain_length)
{
	uintn asn1_len;
	uintn preceding_cert_len;
	uint8 *preceding_cert;
	uintn current_cert_len;
	uint8 *current_cert;
	uint8 *tmp_ptr;
	uint32 ret;
	boolean verify_flag;

	verify_flag = FALSE;
	preceding_cert = root_cert;
	preceding_cert_len = root_cert_length;

	current_cert = cert_chain;

	//
	// Get Current certificate from certificates buffer and Verify with preciding cert
	//
	do {
		tmp_ptr = current_cert;
		ret = mbedtls_asn1_get_tag(
			&tmp_ptr, cert_chain + cert_chain_length, &asn1_len,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		if (ret != 0) {
			break;
		}

		current_cert_len = asn1_len + (tmp_ptr - current_cert);

		if (x509_verify_cert(current_cert, current_cert_len,
				     preceding_cert,
				     preceding_cert_len) == FALSE) {
			verify_flag = FALSE;
			break;
		} else {
			verify_flag = TRUE;
		}

		//
		// Save preceding certificate
		//
		preceding_cert = current_cert;
		preceding_cert_len = current_cert_len;

		//
		// Move current certificate to next;
		//
		current_cert = current_cert + current_cert_len;
	} while (TRUE);

	return verify_flag;
}

/**
  Get one X509 certificate from cert_chain.

  @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
                                    where the first certificate is signed by the Root
                                    Certificate or is the Root Cerificate itself. and
                                    subsequent cerificate is signed by the preceding
                                    cerificate.
  @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.

  @param[in]      cert_index         index of certificate.

  @param[out]     cert              The certificate at the index of cert_chain.
  @param[out]     cert_length        The length certificate at the index of cert_chain.

  @retval  TRUE   Success.
  @retval  FALSE  Failed to get certificate from certificate chain.
**/
boolean x509_get_cert_from_cert_chain(IN uint8 *cert_chain,
				      IN uintn cert_chain_length,
				      IN int32 cert_index, OUT uint8 **cert,
				      OUT uintn *cert_length)
{
	uintn asn1_len;
	int32 current_index;
	uintn current_cert_len;
	uint8 *current_cert;
	uint8 *tmp_ptr;
	int32 ret;

	//
	// Check input parameters.
	//
	if ((cert_chain == NULL) || (cert == NULL) || (cert_index < -1) ||
	    (cert_length == NULL)) {
		return FALSE;
	}

	current_cert = cert_chain;
	current_index = -1;

	//
	// Traverse the certificate chain
	//
	while (TRUE) {
		//
		// Get asn1 tag len
		//
		tmp_ptr = current_cert;
		ret = mbedtls_asn1_get_tag(
			&tmp_ptr, cert_chain + cert_chain_length, &asn1_len,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		if (ret != 0) {
			break;
		}

		current_cert_len = asn1_len + (tmp_ptr - current_cert);
		current_index++;

		if (current_index == cert_index) {
			*cert = current_cert;
			*cert_length = current_cert_len;
			return TRUE;
		}

		//
		// Move to next
		//
		current_cert = current_cert + current_cert_len;
	}

	//
	// If cert_index is -1, Return the last certificate
	//
	if (cert_index == -1 && current_index >= 0) {
		*cert = current_cert - current_cert_len;
		*cert_length = current_cert_len;
		return TRUE;
	}

	return FALSE;
}

/**
  Retrieve the TBSCertificate from one given X.509 certificate.

  @param[in]      cert         Pointer to the given DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     tbs_cert      DER-Encoded to-Be-Signed certificate.
  @param[out]     tbs_cert_size  size of the TBS certificate in bytes.

  If cert is NULL, then return FALSE.
  If tbs_cert is NULL, then return FALSE.
  If tbs_cert_size is NULL, then return FALSE.

  @retval  TRUE   The TBSCertificate was retrieved successfully.
  @retval  FALSE  Invalid X.509 certificate.

**/
boolean x509_get_tbs_cert(IN const uint8 *cert, IN uintn cert_size,
			  OUT uint8 **tbs_cert, OUT uintn *tbs_cert_size)
{
	return FALSE;
}

/**
  Retrieve the version from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If cert_size is 0, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     version      Pointer to the retrieved version integer.

  @retval RETURN_SUCCESS           The certificate version retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If  cert is NULL or cert_size is Zero.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status x509_get_version(IN const uint8 *cert, IN uintn cert_size,
			       OUT uintn *version)
{
	mbedtls_x509_crt crt;
	int32 ret;
	return_status status;

	if (cert == NULL) {
		return RETURN_INVALID_PARAMETER;
	}

	status = RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		*version = crt.version - 1;
		status = RETURN_SUCCESS;
	}

	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the serialNumber from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If cert_size is 0, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     serial_number  Pointer to the retrieved certificate serial_number bytes.
  @param[in, out] serial_number_size  The size in bytes of the serial_number buffer on input,
                               and the size of buffer returned serial_number on output.

  @retval RETURN_SUCCESS           The certificate serialNumber retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL or cert_size is Zero.
                                   If serial_number_size is NULL.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no serial_number exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the serial_number is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   serial_number_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_serial_number(IN const uint8 *cert, IN uintn cert_size,
				     OUT uint8 *serial_number,
				     OPTIONAL IN OUT uintn *serial_number_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	return_status status;

	if (cert == NULL) {
		return RETURN_INVALID_PARAMETER;
	}

	status = RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		if (*serial_number_size <= crt.serial.len) {
			*serial_number_size = crt.serial.len + 1;
			status = RETURN_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		if (serial_number != NULL) {
			copy_mem(serial_number, crt.serial.p, crt.serial.len);
			serial_number[crt.serial.len] = '\0';
		}
		*serial_number_size = crt.serial.len + 1;
		status = RETURN_SUCCESS;
	}
cleanup:
	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the issuer bytes from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If issuer_size is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     cert_issuer  Pointer to the retrieved certificate subject bytes.
  @param[in, out] issuer_size  The size in bytes of the cert_issuer buffer on input,
                               and the size of buffer returned cert_issuer on output.

  @retval  TRUE   The certificate issuer retrieved successfully.
  @retval  FALSE  Invalid certificate, or the issuer_size is too small for the result.
                  The issuer_size will be updated with the required size.
  @retval  FALSE  This interface is not supported.

**/
boolean x509_get_issuer_name(IN const uint8 *cert, IN uintn cert_size,
			     OUT uint8 *cert_issuer,
			     IN OUT uintn *issuer_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	boolean status;

	if (cert == NULL) {
		return FALSE;
	}

	status = FALSE;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		if (*issuer_size < crt.issuer_raw.len) {
			*issuer_size = crt.issuer_raw.len;
			status = FALSE;
			goto cleanup;
		}
		if (cert_issuer != NULL) {
			copy_mem(cert_issuer, crt.issuer_raw.p, crt.issuer_raw.len);
		}
		*issuer_size = crt.issuer_raw.len;
		status = TRUE;
	}

cleanup:
	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the issuer common name (CN) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     common_name       buffer to contain the retrieved certificate issuer common
                                   name string. At most common_name_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
                                   and the size of buffer returned common_name on output.
                                   If common_name is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate Issuer common_name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If common_name_size is NULL.
                                   If common_name is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no common_name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status
x509_get_issuer_common_name(IN const uint8 *cert, IN uintn cert_size,
			    OUT char8 *common_name,
			    OPTIONAL IN OUT uintn *common_name_size)
{
	return internal_x509_get_issuer_nid_name(cert, cert_size,
						 (uint8 *)m_oid_common_name,
						 sizeof(m_oid_common_name),
						 common_name, common_name_size);
}

/**
  Retrieve the issuer organization name (O) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate issuer organization
                                   name string. At most name_buffer_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate issuer Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Organization name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status
x509_get_issuer_orgnization_name(IN const uint8 *cert, IN uintn cert_size,
				 OUT char8 *name_buffer,
				 OPTIONAL IN OUT uintn *name_buffer_size)
{
	return internal_x509_get_issuer_nid_name(
		cert, cert_size, (uint8 *)m_oid_organization_name,
		sizeof(m_oid_organization_name), name_buffer, name_buffer_size);
}

/**
  Retrieve the signature algorithm from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     oid              signature algorithm Object identifier buffer.
  @param[in,out]  oid_size          signature algorithm Object identifier buffer size

  @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If oid_size is NULL.
                                   If oid is not NULL and *oid_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SignatureType.
  @retval RETURN_BUFFER_TOO_SMALL  If the oid is NULL. The required buffer size
                                   is returned in the oid_size.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_signature_algorithm(IN const uint8 *cert,
					   IN uintn cert_size, OUT uint8 *oid,
					   OPTIONAL IN OUT uintn *oid_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	return_status status;

	if (cert == NULL || cert_size == 0 || oid_size == NULL) {
		return RETURN_INVALID_PARAMETER;
	}

	status = RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		if (*oid_size < crt.sig_oid.len) {
			*oid_size = crt.serial.len;
			status = RETURN_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		if (oid != NULL) {
			copy_mem(oid, crt.sig_oid.p, crt.sig_oid.len);
		}
		*oid_size = crt.sig_oid.len;
		status = RETURN_SUCCESS;
	}

cleanup:
	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
 Find first Extension data match with given OID

  @param[in]      start             Pointer to the DER-encoded extensions data
  @param[in]      end               extensions data size in bytes
  @param[in ]     oid               OID for match
  @param[in ]     oid_size           OID size in bytes
  @param[out]     find_extension_data output matched extension data.
  @param[out]     find_extension_data_len matched extension data size.

 **/
static return_status
internal_x509_find_extension_data(uint8 *start, uint8 *end, uint8 *oid,
				  uintn oid_size, uint8 **find_extension_data,
				  uintn *find_extension_data_len)
{
	uint8 *ptr;
	uint8 *extension_ptr;
	size_t obj_len;
	int32 ret;
	return_status status;
	size_t find_extension_len;
	size_t header_len;

	status = RETURN_INVALID_PARAMETER;
	ptr = start;

	ret = 0;

	while (TRUE) {
		/*
    * Extension  ::=  SEQUENCE  {
    *      extnID      OBJECT IDENTIFIER,
    *      critical    boolean DEFAULT FALSE,
    *      extnValue   OCTET STRING  }
    */
		extension_ptr = ptr;
		ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
					   MBEDTLS_ASN1_CONSTRUCTED |
						   MBEDTLS_ASN1_SEQUENCE);
		if (ret == 0) {
			header_len = (size_t)(ptr - extension_ptr);
			find_extension_len = obj_len;
			// Get Object Identifier
			ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
						   MBEDTLS_ASN1_OID);
		} else {
			break;
		}

		if (ret == 0 && const_compare_mem(ptr, oid, oid_size) == 0) {
			ptr += obj_len;

			ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
						   MBEDTLS_ASN1_BOOLEAN);
			if (ret == 0) {
				ptr += obj_len;
			}

			ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
						   MBEDTLS_ASN1_OCTET_STRING);
		} else {
			ret = 1;
		}

		if (ret == 0) {
			*find_extension_data = ptr;
			*find_extension_data_len = obj_len;
			status = RETURN_SUCCESS;
			break;
		}

		// move to next
		ptr = extension_ptr + header_len + find_extension_len;
		ret = 0;
	}

	return status;
}

/**
  Retrieve Extension data from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[in]      oid              Object identifier buffer
  @param[in]      oid_size          Object identifier buffer size
  @param[out]     extension_data    Extension bytes.
  @param[in, out] extension_data_size Extension bytes size.

  @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If extension_data_size is NULL.
                                   If extension_data is not NULL and *extension_data_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Extension entry match oid.
  @retval RETURN_BUFFER_TOO_SMALL  If the extension_data is NULL. The required buffer size
                                   is returned in the extension_data_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_extension_data(IN const uint8 *cert, IN uintn cert_size,
				      IN uint8 *oid, IN uintn oid_size,
				      OUT uint8 *extension_data,
				      IN OUT uintn *extension_data_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	return_status status;
	uint8 *ptr;
	uint8 *end;
	size_t obj_len;

	if (cert == NULL || cert_size == 0 || oid == NULL || oid_size == 0 ||
	    extension_data_size == NULL) {
		return RETURN_INVALID_PARAMETER;
	}

	status = RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		ptr = crt.v3_ext.p;
		end = crt.v3_ext.p + crt.v3_ext.len;
		ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
					   MBEDTLS_ASN1_CONSTRUCTED |
						   MBEDTLS_ASN1_SEQUENCE);
	}

	if (ret == 0) {
		status = internal_x509_find_extension_data(
			ptr, end, oid, oid_size, &ptr, &obj_len);
	}

	if (status == RETURN_SUCCESS) {
		if (*extension_data_size < obj_len) {
			*extension_data_size = obj_len;
			status = RETURN_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		if (oid != NULL) {
			copy_mem(extension_data, ptr, obj_len);
		}
		*extension_data_size = obj_len;
		status = RETURN_SUCCESS;
	}

cleanup:
	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the Validity from one X.509 certificate

  If cert is NULL, then return FALSE.
  If CertIssuerSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     from         notBefore Pointer to date_time object.
  @param[in,out]  from_size     notBefore date_time object size.
  @param[out]     to           notAfter Pointer to date_time object.
  @param[in,out]  to_size       notAfter date_time object size.

  Note: x509_compare_date_time to compare date_time oject
        x509SetDateTime to get a date_time object from a date_time_str

  @retval  TRUE   The certificate Validity retrieved successfully.
  @retval  FALSE  Invalid certificate, or Validity retrieve failed.
  @retval  FALSE  This interface is not supported.
**/
boolean x509_get_validity(IN const uint8 *cert, IN uintn cert_size,
			  IN uint8 *from, IN OUT uintn *from_size, IN uint8 *to,
			  IN OUT uintn *to_size)
{
	mbedtls_x509_crt crt;
	int32 ret;
	boolean status;
	uintn t_size;
	uintn f_size;

	if (cert == NULL) {
		return FALSE;
	}

	status = FALSE;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		f_size = sizeof(mbedtls_x509_time);
		if (*from_size < f_size) {
			*from_size = f_size;
			goto done;
		}
		*from_size = f_size;
		if (from != NULL) {
			copy_mem(from, &(crt.valid_from), f_size);
		}

		t_size = sizeof(mbedtls_x509_time);
		if (*to_size < t_size) {
			*to_size = t_size;
			goto done;
		}
		*to_size = t_size;
		if (to != NULL) {
			copy_mem(to, &(crt.valid_to),
				 sizeof(mbedtls_x509_time));
		}
		status = TRUE;
	}

done:
	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the key usage from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     usage            key usage (CRYPTO_X509_KU_*)

  @retval  TRUE   The certificate key usage retrieved successfully.
  @retval  FALSE  Invalid certificate, or usage is NULL
  @retval  FALSE  This interface is not supported.
**/
boolean x509_get_key_usage(IN const uint8 *cert, IN uintn cert_size,
			   OUT uintn *usage)
{
	mbedtls_x509_crt crt;
	int32 ret;
	boolean status;

	if (cert == NULL) {
		return FALSE;
	}

	status = FALSE;

	mbedtls_x509_crt_init(&crt);

	ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

	if (ret == 0) {
		*usage = crt.key_usage;
		status = TRUE;
	}
	mbedtls_x509_crt_free(&crt);

	return status;
}

/**
  Retrieve the Extended key usage from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     usage            key usage bytes.
  @param[in, out] usage_size        key usage buffer sizs in bytes.

  @retval RETURN_SUCCESS           The usage bytes retrieve successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If cert_size is NULL.
                                   If usage is not NULL and *usage_size is 0.
                                   If cert is invalid.
  @retval RETURN_BUFFER_TOO_SMALL  If the usage is NULL. The required buffer size
                                   is returned in the usage_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_extended_key_usage(IN const uint8 *cert,
					  IN uintn cert_size, OUT uint8 *usage,
					  IN OUT uintn *usage_size)
{
	return_status status;

	if (cert == NULL || cert_size == 0 || usage_size == NULL) {
		return RETURN_INVALID_PARAMETER;
	}

	status = x509_get_extension_data((uint8 *)cert, cert_size,
					 (uint8 *)m_oid_ext_key_usage,
					 sizeof(m_oid_ext_key_usage), usage,
					 usage_size);

	return status;
}

/**
  Return 0 if before <= after, 1 otherwise
**/
static intn internal_x509_check_time(const mbedtls_x509_time *before,
				     const mbedtls_x509_time *after)
{
	if (before->year > after->year)
		return (1);

	if (before->year == after->year && before->mon > after->mon)
		return (1);

	if (before->year == after->year && before->mon == after->mon &&
	    before->day > after->day)
		return (1);

	if (before->year == after->year && before->mon == after->mon &&
	    before->day == after->day && before->hour > after->hour)
		return (1);

	if (before->year == after->year && before->mon == after->mon &&
	    before->day == after->day && before->hour == after->hour &&
	    before->min > after->min)
		return (1);

	if (before->year == after->year && before->mon == after->mon &&
	    before->day == after->day && before->hour == after->hour &&
	    before->min == after->min && before->sec > after->sec)
		return (1);

	return (0);
}

static int32 internal_atoi(char8 *p_start, char8 *p_end)
{
	char8 *p = p_start;
	int32 k = 0;
	while (p < p_end) {
		///
		/// k = k * 2³ + k * 2¹ = k * 8 + k * 2 = k * 10
		///
		k = (k << 3) + (k << 1) + (*p) - '0';
		p++;
	}
	return k;
}

/**
  format a date_time object into DataTime buffer

  If date_time_str is NULL, then return FALSE.
  If date_time_size is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      date_time_str      date_time string like YYYYMMDDhhmmssZ
                                   Ref: https://www.w3.org/TR/NOTE-datetime
                                   Z stand for UTC time
  @param[out]     date_time         Pointer to a date_time object.
  @param[in,out]  date_time_size     date_time object buffer size.

  @retval RETURN_SUCCESS           The date_time object create successfully.
  @retval RETURN_INVALID_PARAMETER If date_time_str is NULL.
                                   If date_time_size is NULL.
                                   If date_time is not NULL and *date_time_size is 0.
                                   If year month day hour minute second combination is invalid datetime.
  @retval RETURN_BUFFER_TOO_SMALL  If the date_time is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   date_time_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_set_date_time(char8 *date_time_str, IN OUT void *date_time,
				 IN OUT uintn *date_time_size)
{
	mbedtls_x509_time dt;

	int32 year;
	int32 month;
	int32 day;
	int32 hour;
	int32 minute;
	int32 second;
	return_status status;
	char8 *p;

	p = date_time_str;

	year = internal_atoi(p, p + 4);
	p += 4;
	month = internal_atoi(p, p + 2);
	p += 2;
	day = internal_atoi(p, p + 2);
	p += 2;
	hour = internal_atoi(p, p + 2);
	p += 2;
	minute = internal_atoi(p, p + 2);
	p += 2;
	second = internal_atoi(p, p + 2);
	p += 2;
	dt.year = (int)year;
	dt.mon = (int)month;
	dt.day = (int)day;
	dt.hour = (int)hour;
	dt.min = (int)minute;
	dt.sec = (int)second;

	if (*date_time_size < sizeof(mbedtls_x509_time)) {
		*date_time_size = sizeof(mbedtls_x509_time);
		status = RETURN_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	if (date_time != NULL) {
		copy_mem(date_time, &dt, sizeof(mbedtls_x509_time));
	}
	*date_time_size = sizeof(mbedtls_x509_time);
	status = RETURN_SUCCESS;
cleanup:
	return status;
}

/**
  Compare date_time1 object and date_time2 object.

  If date_time1 is NULL, then return -2.
  If date_time2 is NULL, then return -2.
  If date_time1 == date_time2, then return 0
  If date_time1 > date_time2, then return 1
  If date_time1 < date_time2, then return -1

  @param[in]      date_time1         Pointer to a date_time Ojbect
  @param[in]      date_time2         Pointer to a date_time Object

  @retval  0      If date_time1 == date_time2
  @retval  1      If date_time1 > date_time2
  @retval  -1     If date_time1 < date_time2
**/
intn x509_compare_date_time(IN void *date_time1, IN void *date_time2)
{
	if (date_time1 == NULL || date_time2 == NULL) {
		return -2;
	}
	if (const_compare_mem(date_time2, date_time1, sizeof(mbedtls_x509_time)) ==
	    0) {
		return 0;
	}
	if (internal_x509_check_time((mbedtls_x509_time *)date_time1,
				     (mbedtls_x509_time *)date_time2) == 0) {
		return -1;
	} else {
		return 1;
	}
}
