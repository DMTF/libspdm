/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  X.509 Certificate Handler Wrapper Implementation.
**/

#include "internal_crypt_lib.h"

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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
}

/**
  Release the specified X509 object.

  If x509_cert is NULL, then return FALSE.

  @param[in]  x509_cert  Pointer to the X509 object to be released.

**/
void x509_free(IN void *x509_cert)
{
	ASSERT(FALSE);
}

/**
  Release the specified X509 stack object.

  If x509_stack is NULL, then return FALSE.

  @param[in]  x509_stack  Pointer to the X509 stack object to be released.

**/
void x509_stack_free(IN void *x509_stack)
{
	ASSERT(FALSE);
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
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
	ASSERT(FALSE);
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
}

/**
  Retrieve the issuer bytes from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If CertIssuerSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     CertIssuer  Pointer to the retrieved certificate subject bytes.
  @param[in, out] CertIssuerSize  The size in bytes of the CertIssuer buffer on input,
                               and the size of buffer returned cert_subject on output.

  @retval  TRUE   The certificate issuer retrieved successfully.
  @retval  FALSE  Invalid certificate, or the CertIssuerSize is too small for the result.
                  The CertIssuerSize will be updated with the required size.
  @retval  FALSE  This interface is not supported.

**/
boolean x509_get_issuer_name(IN const uint8 *cert, IN uintn cert_size,
			     OUT uint8 *CertIssuer,
			     IN OUT uintn *CertIssuerSize)
{
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return RETURN_UNSUPPORTED;
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
	ASSERT(FALSE);
	return -3;
}
