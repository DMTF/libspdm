/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  X.509 Certificate Handler Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>

///
/// OID
///
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
	X509 *x509_cert;
	const uint8 *temp;

	//
	// Check input parameters.
	//
	if (cert == NULL || single_x509_cert == NULL || cert_size > INT_MAX) {
		return FALSE;
	}

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	temp = cert;
	x509_cert = d2i_X509(NULL, &temp, (long)cert_size);
	if (x509_cert == NULL) {
		return FALSE;
	}

	*single_x509_cert = (uint8 *)x509_cert;

	return TRUE;
}

/**
  Construct a X509 stack object from a list of DER-encoded certificate data.

  If x509_stack is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
                              On output, pointer to the X509 stack object with new
                              inserted X509 certificate.
  @param[in]       args       VA_LIST marker for the variable argument list.
                              A list of DER-encoded single certificate data followed
                              by certificate size. A NULL terminates the list. The
                              pairs are the arguments to x509_construct_certificate().

  @retval     TRUE            The X509 stack construction succeeded.
  @retval     FALSE           The construction operation failed.
  @retval     FALSE           This interface is not supported.

**/
boolean X509ConstructCertificateStackV(IN OUT uint8 **x509_stack,
				       IN VA_LIST args)
{
	uint8 *cert;
	uintn cert_size;
	X509 *x509_cert;
	STACK_OF(X509) * cert_stack;
	boolean res;
	uintn index;

	//
	// Check input parameters.
	//
	if (x509_stack == NULL) {
		return FALSE;
	}

	res = FALSE;

	//
	// Initialize X509 stack object.
	//
	cert_stack = (STACK_OF(X509) *)(*x509_stack);
	if (cert_stack == NULL) {
		cert_stack = sk_X509_new_null();
		if (cert_stack == NULL) {
			return res;
		}
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

		//
		// Construct X509 Object from the given DER-encoded certificate data.
		//
		x509_cert = NULL;
		res = x509_construct_certificate((const uint8 *)cert, cert_size,
						 (uint8 **)&x509_cert);
		if (!res) {
			if (x509_cert != NULL) {
				X509_free(x509_cert);
			}
			break;
		}

		//
		// Insert the new X509 object into X509 stack object.
		//
		sk_X509_push(cert_stack, x509_cert);
	}

	if (!res) {
		sk_X509_pop_free(cert_stack, X509_free);
	} else {
		*x509_stack = (uint8 *)cert_stack;
	}

	return res;
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
	//
	// Check input parameters.
	//
	if (x509_cert == NULL) {
		return;
	}

	//
	// Free OpenSSL X509 object.
	//
	X509_free((X509 *)x509_cert);
}

/**
  Release the specified X509 stack object.

  If x509_stack is NULL, then return FALSE.

  @param[in]  x509_stack  Pointer to the X509 stack object to be released.

**/
void x509_stack_free(IN void *x509_stack)
{
	//
	// Check input parameters.
	//
	if (x509_stack == NULL) {
		return;
	}

	//
	// Free OpenSSL X509 stack object.
	//
	sk_X509_pop_free((STACK_OF(X509) *)x509_stack, X509_free);
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
	uint8 *ptr_old;
	int32 obj_tag;
	int32 obj_class;
	long obj_length;

	//
	// Save ptr position
	//
	ptr_old = *ptr;

	ASN1_get_object((const uint8 **)ptr, &obj_length, &obj_tag, &obj_class,
			(int32)(end - (*ptr)));
	if (obj_tag == (int32)(tag & CRYPTO_ASN1_TAG_VALUE_MASK) &&
	    obj_class == (int32)(tag & CRYPTO_ASN1_TAG_CLASS_MASK)) {
		*length = (uintn)obj_length;
		return TRUE;
	} else {
		//
		// if doesn't match tag, restore ptr to origin ptr
		//
		*ptr = ptr_old;
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
	boolean res;
	X509 *x509_cert;
	X509_NAME *x509_name;
	uintn x509_name_size;

	//
	// Check input parameters.
	//
	if (cert == NULL || subject_size == NULL) {
		return FALSE;
	}

	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Retrieve subject name from certificate object.
	//
	x509_name = X509_get_subject_name(x509_cert);
	if (x509_name == NULL) {
		goto done;
	}

	x509_name_size = i2d_X509_NAME(x509_name, NULL);
	if (*subject_size < x509_name_size) {
		*subject_size = x509_name_size;
		goto done;
	}
	*subject_size = x509_name_size;
	if (cert_subject != NULL) {
		i2d_X509_NAME(x509_name, &cert_subject);
		res = TRUE;
	}

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	return res;
}

/**
  Retrieve a string from one X.509 certificate base on the request_nid.

  @param[in]      x509_name         X509 name
  @param[in]      request_nid      NID of string to obtain
  @param[out]     common_name       buffer to contain the retrieved certificate common
                                   name string (UTF8). At most common_name_size bytes will be
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
  @retval RETURN_NOT_FOUND         If no NID name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
static return_status
internal_x509_get_nid_name(IN X509_NAME *x509_name, IN int32 request_nid,
			   OUT char8 *common_name,
			   OPTIONAL IN OUT uintn *common_name_size)
{
	return_status status;
	int32 index;
	intn length;
	X509_NAME_ENTRY *entry;
	ASN1_STRING *entry_data;
	uint8 *utf8_name;

	status = RETURN_INVALID_PARAMETER;
	utf8_name = NULL;

	//
	// Check input parameters.
	//
	if (x509_name == NULL || (common_name_size == NULL)) {
		return status;
	}
	if ((common_name != NULL) && (*common_name_size == 0)) {
		return status;
	}

	//
	// Retrive the string from X.509 Subject base on the request_nid
	//
	index = X509_NAME_get_index_by_NID(x509_name, request_nid, -1);
	if (index < 0) {
		//
		// No request_nid name entry exists in X509_NAME object
		//
		*common_name_size = 0;
		status = RETURN_NOT_FOUND;
		goto done;
	}

	entry = X509_NAME_get_entry(x509_name, index);
	if (entry == NULL) {
		//
		// Fail to retrieve name entry data
		//
		*common_name_size = 0;
		status = RETURN_NOT_FOUND;
		goto done;
	}

	entry_data = X509_NAME_ENTRY_get_data(entry);

	length = ASN1_STRING_to_UTF8(&utf8_name, entry_data);
	if (length < 0) {
		//
		// Fail to convert the name string
		//
		*common_name_size = 0;
		status = RETURN_INVALID_PARAMETER;
		goto done;
	}

	if (common_name == NULL) {
		*common_name_size = length + 1;
		status = RETURN_BUFFER_TOO_SMALL;
	} else {
		*common_name_size =
			MIN((uintn)length, *common_name_size - 1) + 1;
		copy_mem(common_name, utf8_name, *common_name_size - 1);
		common_name[*common_name_size - 1] = '\0';
		status = RETURN_SUCCESS;
	}

done:
	//
	// Release Resources.
	//
	if (utf8_name != NULL) {
		OPENSSL_free(utf8_name);
	}

	return status;
}

/**
  Retrieve a string from one X.509 certificate base on the request_nid.

  @param[in]      x509_name         x509_name Struct
  @param[in]      request_nid      NID of string to obtain
  @param[out]     common_name       buffer to contain the retrieved certificate common
                                   name string (UTF8). At most common_name_size bytes will be
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
  @retval RETURN_NOT_FOUND         If no NID name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
static return_status
internal_x509_get_subject_nid_name(IN const uint8 *cert, IN uintn cert_size,
				   IN int32 request_nid, OUT char8 *common_name,
				   OPTIONAL IN OUT uintn *common_name_size)
{
	return_status status;
	boolean res;
	X509 *x509_cert;
	X509_NAME *x509_name;

	status = RETURN_INVALID_PARAMETER;
	x509_cert = NULL;

	if (cert == NULL || cert_size == 0) {
		goto done;
	}

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		//
		// Invalid X.509 Certificate
		//
		goto done;
	}

	res = FALSE;

	//
	// Retrieve subject name from certificate object.
	//
	x509_name = X509_get_subject_name(x509_cert);
	if (x509_name == NULL) {
		//
		// Fail to retrieve subject name content
		//
		goto done;
	}

	status = internal_x509_get_nid_name(x509_name, request_nid, common_name,
					    common_name_size);

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}
	return status;
}

/**
  Retrieve a string from one X.509 certificate base on the request_nid.

  @param[in]      x509_name         X509 Struct
  @param[in]      request_nid      NID of string to obtain
  @param[out]     common_name       buffer to contain the retrieved certificate common
                                   name string (UTF8). At most common_name_size bytes will be
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
  @retval RETURN_NOT_FOUND         If no NID name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
static return_status
internal_x509_get_issuer_nid_name(IN const uint8 *cert, IN uintn cert_size,
				  IN int32 request_nid, OUT char8 *common_name,
				  OPTIONAL IN OUT uintn *common_name_size)
{
	return_status status;
	boolean res;
	X509 *x509_cert;
	X509_NAME *x509_name;

	status = RETURN_INVALID_PARAMETER;
	x509_cert = NULL;

	if (cert == NULL || cert_size == 0) {
		goto done;
	}

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		//
		// Invalid X.509 Certificate
		//
		goto done;
	}

	res = FALSE;

	//
	// Retrieve subject name from certificate object.
	//
	x509_name = X509_get_issuer_name(x509_cert);
	if (x509_name == NULL) {
		//
		// Fail to retrieve subject name content
		//
		goto done;
	}

	status = internal_x509_get_nid_name(x509_name, request_nid, common_name,
					    common_name_size);

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}
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
		cert, cert_size, NID_commonName, common_name, common_name_size);
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
	return internal_x509_get_subject_nid_name(cert, cert_size,
						  NID_organizationName,
						  name_buffer,
						  name_buffer_size);
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
	return_status status;
	boolean res;
	X509 *x509_cert;

	x509_cert = NULL;
	status = RETURN_SUCCESS;
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		//
		// Invalid X.509 Certificate
		//
		status = RETURN_INVALID_PARAMETER;
	}

	if (!RETURN_ERROR(status)) {
		*version = X509_get_version(x509_cert);
	}

	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}
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
	boolean res;
	X509 *x509_cert;
	ASN1_INTEGER *asn1_integer;
	return_status status;

	status = RETURN_INVALID_PARAMETER;

	//
	// Check input parameters.
	//
	if (cert == NULL || serial_number_size == NULL) {
		return status;
	}

	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		goto done;
	}

	//
	// Retrieve subject name from certificate object.
	//
	asn1_integer = X509_get_serialNumber(x509_cert);
	if (asn1_integer == NULL) {
		status = RETURN_NOT_FOUND;
		goto done;
	}

	if (*serial_number_size < (uintn)asn1_integer->length) {
		*serial_number_size = (uintn)asn1_integer->length;
		status = RETURN_BUFFER_TOO_SMALL;
		goto done;
	}
	*serial_number_size = (uintn)asn1_integer->length;
	if (serial_number != NULL) {
		copy_mem(serial_number, asn1_integer->data,
			 *serial_number_size);
		status = RETURN_SUCCESS;
	}

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

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
	boolean res;
	X509 *x509_cert;
	X509_NAME *x509_name;
	uintn x509_name_size;

	//
	// Check input parameters.
	//
	if (cert == NULL || issuer_size == NULL) {
		return FALSE;
	}

	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Retrieve issuer name from certificate object.
	//
	x509_name = X509_get_issuer_name(x509_cert);
	if (x509_name == NULL) {
		goto done;
	}

	x509_name_size = i2d_X509_NAME(x509_name, NULL);
	if (*issuer_size < x509_name_size) {
		*issuer_size = x509_name_size;
		goto done;
	}
	*issuer_size = x509_name_size;
	if (cert_issuer != NULL) {
		i2d_X509_NAME(x509_name, &cert_issuer);
		res = TRUE;
	}

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	return res;
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
	return internal_x509_get_issuer_nid_name(
		cert, cert_size, NID_commonName, common_name, common_name_size);
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
	return internal_x509_get_issuer_nid_name(cert, cert_size,
						 NID_organizationName,
						 name_buffer, name_buffer_size);
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
	boolean res;
	return_status status;
	X509 *x509_cert;
	int nid;
	ASN1_OBJECT *asn1_obj;
	uintn obj_length;

	//
	// Check input parameters.
	//
	if (cert == NULL || oid_size == NULL || cert_size == 0) {
		return RETURN_INVALID_PARAMETER;
	}

	x509_cert = NULL;
	status = RETURN_INVALID_PARAMETER;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		status = RETURN_INVALID_PARAMETER;
		goto done;
	}

	//
	// Retrieve subject name from certificate object.
	//
	nid = X509_get_signature_nid(x509_cert);
	if (nid == NID_undef) {
		status = RETURN_NOT_FOUND;
		goto done;
	}
	asn1_obj = OBJ_nid2obj(nid);
	if (asn1_obj == NULL) {
		status = RETURN_NOT_FOUND;
		goto done;
	}

	obj_length = OBJ_length(asn1_obj);
	if (*oid_size < obj_length) {
		*oid_size = obj_length;
		status = RETURN_BUFFER_TOO_SMALL;
		goto done;
	}
	if (oid != NULL) {
		copy_mem(oid, OBJ_get0_data(asn1_obj), obj_length);
	}
	*oid_size = obj_length;
	status = RETURN_SUCCESS;

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

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
	boolean res;
	X509 *x509_cert;
	const ASN1_TIME *f_time;
	const ASN1_TIME *t_time;
	uintn t_size;
	uintn f_size;

	//
	// Check input parameters.
	//
	if (cert == NULL || from_size == NULL || to_size == NULL ||
	    cert_size == 0) {
		return FALSE;
	}

	x509_cert = NULL;
	res = FALSE;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		goto done;
	}

	//
	// Retrieve Validity from/to from certificate object.
	//
	f_time = X509_get0_notBefore(x509_cert);
	t_time = X509_get0_notAfter(x509_cert);

	if (f_time == NULL || t_time == NULL) {
		goto done;
	}

	f_size = sizeof(ASN1_TIME) + f_time->length;
	if (*from_size < f_size) {
		*from_size = f_size;
		goto done;
	}
	*from_size = f_size;
	if (from != NULL) {
		copy_mem(from, f_time, sizeof(ASN1_TIME));
		((ASN1_TIME *)from)->data = from + sizeof(ASN1_TIME);
		copy_mem(from + sizeof(ASN1_TIME), f_time->data,
			 f_time->length);
	}

	t_size = sizeof(ASN1_TIME) + t_time->length;
	if (*to_size < t_size) {
		*to_size = t_size;
		goto done;
	}
	*to_size = t_size;
	if (to != NULL) {
		copy_mem(to, t_time, sizeof(ASN1_TIME));
		((ASN1_TIME *)to)->data = to + sizeof(ASN1_TIME);
		copy_mem(to + sizeof(ASN1_TIME), t_time->data, t_time->length);
	}

	res = TRUE;

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	return res;
}

/**
  format a date_time object into DataTime buffer

  If date_time_str is NULL, then return FALSE.
  If date_time_size is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      date_time_str      date_time string like YYYYMMDDhhmmssZ
                                   Ref: https://www.w3.org/TR/NOTE-datetime
                                   Z stand for UTC time
  @param[in,out]  date_time         Pointer to a date_time object.
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
return_status x509_set_date_time(IN char8 *date_time_str, OUT void *date_time,
				 IN OUT uintn *date_time_size)
{
	return_status status;
	int32 ret;
	ASN1_TIME *dt;
	uintn d_size;

	dt = NULL;
	status = RETURN_INVALID_PARAMETER;

	dt = ASN1_TIME_new();
	if (dt == NULL) {
		status = RETURN_OUT_OF_RESOURCES;
		goto cleanup;
	}

	ret = ASN1_TIME_set_string_X509(dt, date_time_str);
	if (ret != 1) {
		status = RETURN_INVALID_PARAMETER;
		goto cleanup;
	}

	d_size = sizeof(ASN1_TIME) + dt->length;
	if (*date_time_size < d_size) {
		*date_time_size = d_size;
		status = RETURN_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	*date_time_size = d_size;
	if (date_time != NULL) {
		copy_mem(date_time, dt, sizeof(ASN1_TIME));
		((ASN1_TIME *)date_time)->data =
			(uint8 *)date_time + sizeof(ASN1_TIME);
		copy_mem((uint8 *)date_time + sizeof(ASN1_TIME), dt->data,
			 dt->length);
	}
	status = RETURN_SUCCESS;

cleanup:
	if (dt != NULL) {
		ASN1_TIME_free(dt);
	}
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
	return (intn)ASN1_TIME_compare(date_time1, date_time2);
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
	boolean res;
	X509 *x509_cert;

	//
	// Check input parameters.
	//
	if (cert == NULL || usage == NULL) {
		return FALSE;
	}

	x509_cert = NULL;
	res = FALSE;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		goto done;
	}

	//
	// Retrieve subject name from certificate object.
	//
	*usage = X509_get_key_usage(x509_cert);
	if (*usage == NID_undef) {
		goto done;
	}
	res = TRUE;

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	return res;
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
	return_status status;
	intn i;
	boolean res;
	X509 *x509_cert;
	const STACK_OF(X509_EXTENSION) * extensions;
	ASN1_OBJECT *asn1_obj;
	ASN1_OCTET_STRING *asn1_oct;
	X509_EXTENSION *ext;
	uintn obj_length;
	uintn oct_length;

	status = RETURN_INVALID_PARAMETER;

	//
	// Check input parameters.
	//
	if (cert == NULL || cert_size == 0 || oid == NULL || oid_size == 0 ||
	    extension_data_size == NULL) {
		return status;
	}

	x509_cert = NULL;
	res = FALSE;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		goto cleanup;
	}

	//
	// Retrieve extensions from certificate object.
	//
	status = RETURN_NOT_FOUND;
	extensions = X509_get0_extensions(x509_cert);
	if (sk_X509_EXTENSION_num(extensions) <= 0) {
		goto cleanup;
	}

	//
	// Traverse extensions
	//
	for (i = 0; i < sk_X509_EXTENSION_num(extensions); i++) {
		ext = sk_X509_EXTENSION_value(extensions, (int)i);
		if (ext == NULL) {
			continue;
		}
		asn1_obj = X509_EXTENSION_get_object(ext);
		if (asn1_obj == NULL) {
			continue;
		}
		asn1_oct = X509_EXTENSION_get_data(ext);
		if (asn1_oct == NULL) {
			continue;
		}

		obj_length = OBJ_length(asn1_obj);
		oct_length = ASN1_STRING_length(asn1_oct);

		if (oid_size == obj_length &&
		    const_compare_mem(OBJ_get0_data(asn1_obj), oid, oid_size) == 0) {
			//
			// Extension Found
			//
			status = RETURN_SUCCESS;
			break;
		}
	}
	if (status == RETURN_SUCCESS) {
		if (*extension_data_size < oct_length) {
			*extension_data_size = oct_length;
			status = RETURN_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		if (oid != NULL) {
			copy_mem(extension_data, ASN1_STRING_get0_data(asn1_oct),
				 asn1_oct->length);
		}
		*extension_data_size = oct_length;
		status = RETURN_SUCCESS;
	}

cleanup:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

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
	status = x509_get_extension_data(cert, cert_size,
					 (uint8 *)m_oid_ext_key_usage,
					 sizeof(m_oid_ext_key_usage), usage,
					 usage_size);
	return status;
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
	boolean res;
	EVP_PKEY *pkey;
	X509 *x509_cert;

	//
	// Check input parameters.
	//
	if (cert == NULL || rsa_context == NULL) {
		return FALSE;
	}

	pkey = NULL;
	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Retrieve and check EVP_PKEY data from X509 Certificate.
	//
	pkey = X509_get_pubkey(x509_cert);
	if ((pkey == NULL) || (EVP_PKEY_id(pkey) != EVP_PKEY_RSA)) {
		goto done;
	}

	//
	// Duplicate RSA context from the retrieved EVP_PKEY.
	//
	if ((*rsa_context = RSAPublicKey_dup(EVP_PKEY_get0_RSA(pkey))) !=
	    NULL) {
		res = TRUE;
	}

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}

	return res;
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
	boolean res;
	EVP_PKEY *pkey;
	X509 *x509_cert;

	//
	// Check input parameters.
	//
	if (cert == NULL || ec_context == NULL) {
		return FALSE;
	}

	pkey = NULL;
	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Retrieve and check EVP_PKEY data from X509 Certificate.
	//
	pkey = X509_get_pubkey(x509_cert);
	if ((pkey == NULL) || (EVP_PKEY_id(pkey) != EVP_PKEY_EC)) {
		goto done;
	}

	//
	// Duplicate EC context from the retrieved EVP_PKEY.
	//
	if ((*ec_context = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(pkey))) != NULL) {
		res = TRUE;
	}

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}

	return res;
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
	boolean res;
	EVP_PKEY *pkey;
	X509 *x509_cert;
	int32 type;

	//
	// Check input parameters.
	//
	if (cert == NULL || ecd_context == NULL) {
		return FALSE;
	}

	pkey = NULL;
	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Retrieve and check EVP_PKEY data from X509 Certificate.
	//
	pkey = X509_get_pubkey(x509_cert);
	if (pkey == NULL) {
		goto done;
	}
	type = EVP_PKEY_id(pkey);
	if ((type != EVP_PKEY_ED25519) && (type != EVP_PKEY_ED448)) {
		goto done;
	}

	*ecd_context = pkey;
	res = TRUE;

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	return res;
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
	boolean res;
	EVP_PKEY *pkey;
	X509 *x509_cert;
	int32 result;
	EC_KEY *ec_key;
	int32 openssl_nid;

	//
	// Check input parameters.
	//
	if (cert == NULL || sm2_context == NULL) {
		return FALSE;
	}

	pkey = NULL;
	x509_cert = NULL;

	//
	// Read DER-encoded X509 Certificate and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Retrieve and check EVP_PKEY data from X509 Certificate.
	//
	pkey = X509_get_pubkey(x509_cert);
	if (pkey == NULL) {
		goto done;
	}
	ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
	if (openssl_nid != NID_sm2) {
		goto done;
	}
	result = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	if (result == 0) {
		goto done;
	}

	*sm2_context = pkey;
	res = TRUE;

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	return res;
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
	boolean res;
	X509 *x509_cert;
	X509 *x509_ca_cert;
	X509_STORE *cert_store;
	X509_STORE_CTX *cert_ctx;

	//
	// Check input parameters.
	//
	if (cert == NULL || ca_cert == NULL) {
		return FALSE;
	}

	res = FALSE;
	x509_cert = NULL;
	x509_ca_cert = NULL;
	cert_store = NULL;
	cert_ctx = NULL;

	//
	// Register & Initialize necessary digest algorithms for certificate verification.
	//
	if (EVP_add_digest(EVP_sha256()) == 0) {
		goto done;
	}
	if (EVP_add_digest(EVP_sha384()) == 0) {
		goto done;
	}
	if (EVP_add_digest(EVP_sha512()) == 0) {
		goto done;
	}

	//
	// Read DER-encoded certificate to be verified and Construct X509 object.
	//
	res = x509_construct_certificate(cert, cert_size, (uint8 **)&x509_cert);
	if ((x509_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	//
	// Read DER-encoded root certificate and Construct X509 object.
	//
	res = x509_construct_certificate(ca_cert, ca_cert_size,
					 (uint8 **)&x509_ca_cert);
	if ((x509_ca_cert == NULL) || (!res)) {
		res = FALSE;
		goto done;
	}

	res = FALSE;

	//
	// Set up X509 Store for trusted certificate.
	//
	cert_store = X509_STORE_new();
	if (cert_store == NULL) {
		goto done;
	}
	if (!(X509_STORE_add_cert(cert_store, x509_ca_cert))) {
		goto done;
	}

	//
	// Allow partial certificate chains, terminated by a non-self-signed but
	// still trusted intermediate certificate. Also disable time checks.
	//
	X509_STORE_set_flags(cert_store, X509_V_FLAG_PARTIAL_CHAIN |
						 X509_V_FLAG_NO_CHECK_TIME);

	//
	// Set up X509_STORE_CTX for the subsequent verification operation.
	//
	cert_ctx = X509_STORE_CTX_new();
	if (cert_ctx == NULL) {
		goto done;
	}
	if (!X509_STORE_CTX_init(cert_ctx, cert_store, x509_cert, NULL)) {
		goto done;
	}

	//
	// X509 Certificate Verification.
	//
	res = (boolean)X509_verify_cert(cert_ctx);
	X509_STORE_CTX_cleanup(cert_ctx);

done:
	//
	// Release Resources.
	//
	if (x509_cert != NULL) {
		X509_free(x509_cert);
	}

	if (x509_ca_cert != NULL) {
		X509_free(x509_ca_cert);
	}

	if (cert_store != NULL) {
		X509_STORE_free(cert_store);
	}

	X509_STORE_CTX_free(cert_ctx);

	return res;
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
	const uint8 *temp;
	uint32 asn1_tag;
	uint32 obj_class;
	uintn length;

	//
	// Check input parameters.
	//
	if ((cert == NULL) || (tbs_cert == NULL) || (tbs_cert_size == NULL) ||
	    (cert_size > INT_MAX)) {
		return FALSE;
	}

	//
	// An X.509 Certificate is: (defined in RFC3280)
	//   Certificate  ::=  SEQUENCE  {
	//     tbsCertificate       TBSCertificate,
	//     signatureAlgorithm   AlgorithmIdentifier,
	//     signature            BIT STRING }
	//
	// and
	//
	//  TBSCertificate  ::=  SEQUENCE  {
	//    version         [0]  version DEFAULT v1,
	//    ...
	//    }
	//
	// So we can just ASN1-parse the x.509 DER-encoded data. If we strip
	// the first SEQUENCE, the second SEQUENCE is the TBSCertificate.
	//
	temp = cert;
	length = 0;
	ASN1_get_object(&temp, (long *)&length, (int *)&asn1_tag,
			(int *)&obj_class, (long)cert_size);

	if (asn1_tag != V_ASN1_SEQUENCE) {
		return FALSE;
	}

	*tbs_cert = (uint8 *)temp;

	ASN1_get_object(&temp, (long *)&length, (int *)&asn1_tag,
			(int *)&obj_class, (long)length);
	//
	// Verify the parsed TBSCertificate is one correct SEQUENCE data.
	//
	if (asn1_tag != V_ASN1_SEQUENCE) {
		return FALSE;
	}

	*tbs_cert_size = length + (temp - *tbs_cert);

	return TRUE;
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
	uint8 *tmp_ptr;
	uintn length;
	uint32 asn1_tag;
	uint32 obj_class;
	uint8 *current_cert;
	uintn current_cert_len;
	uint8 *preceding_cert;
	uintn preceding_cert_len;
	boolean verify_flag;
	int32 ret;

	preceding_cert = root_cert;
	preceding_cert_len = root_cert_length;

	current_cert = cert_chain;
	length = 0;
	current_cert_len = 0;

	verify_flag = FALSE;
	while (TRUE) {
		tmp_ptr = current_cert;
		ret = ASN1_get_object(
			(const uint8 **)&tmp_ptr, (long *)&length,
			(int *)&asn1_tag, (int *)&obj_class,
			(long)(cert_chain_length + cert_chain - tmp_ptr));
		if (asn1_tag != V_ASN1_SEQUENCE || ret == 0x80) {
			break;
		}

		//
		// Calculate current_cert length;
		//
		current_cert_len = tmp_ptr - current_cert + length;

		//
		// Verify current_cert with preceding cert;
		//
		verify_flag =
			x509_verify_cert(current_cert, current_cert_len,
					 preceding_cert, preceding_cert_len);
		if (verify_flag == FALSE) {
			break;
		}

		//
		// move Current cert to Preceding cert
		//
		preceding_cert_len = current_cert_len;
		preceding_cert = current_cert;

		//
		// Move to next
		//
		current_cert = current_cert + current_cert_len;
	}

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
	uint32 asn1_tag;
	uint32 obj_class;

	//
	// Check input parameters.
	//
	if ((cert_chain == NULL) || (cert == NULL) || (cert_index < -1) ||
	    (cert_length == NULL)) {
		return FALSE;
	}

	asn1_len = 0;
	current_cert_len = 0;
	current_cert = cert_chain;
	current_index = -1;

	//
	// Traverse the certificate chain
	//
	while (TRUE) {
		tmp_ptr = current_cert;

		// Get asn1 object and taglen
		ret = ASN1_get_object(
			(const uint8 **)&tmp_ptr, (long *)&asn1_len,
			(int *)&asn1_tag, (int *)&obj_class,
			(long)(cert_chain_length + cert_chain - tmp_ptr));
		if (asn1_tag != V_ASN1_SEQUENCE || ret == 0x80) {
			break;
		}
		//
		// Calculate current_cert length;
		//
		current_cert_len = tmp_ptr - current_cert + asn1_len;
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
