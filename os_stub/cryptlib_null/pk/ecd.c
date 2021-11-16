/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Edwards-Curve Wrapper Implementation.

  RFC 8032 - Edwards-Curve Digital signature algorithm (EdDSA)
  FIPS 186-4 - Digital signature Standard (DSS)
**/

#include "internal_crypt_lib.h"

/**
  Allocates and Initializes one Edwards-Curve context for subsequent use
  with the NID.

  The key is generated before the function returns.

  @param nid cipher NID

  @return  Pointer to the Edwards-Curve context that has been initialized.
           If the allocations fails, ecd_new_by_nid() returns NULL.

**/
void *ecd_new_by_nid(IN uintn nid)
{
	return NULL;
}

/**
  Release the specified Ed context.

  @param[in]  ecd_context  Pointer to the Ed context to be released.

**/
void ecd_free(IN void *ecd_context)
{
}

/**
  Sets the public key component into the established Ed context.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  @param[in, out]  ecd_context      Pointer to Ed context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   Ed public key component was set successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ecd_set_pub_key(IN OUT void *ecd_context, IN uint8_t *public_key,
			IN uintn public_key_size)
{
	return FALSE;
}

/**
  Gets the public key component from the established Ed context.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  @param[in, out]  ecd_context      Pointer to Ed context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   Ed key component was retrieved successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ecd_get_pub_key(IN OUT void *ecd_context, OUT uint8_t *public_key,
			IN OUT uintn *public_key_size)
{
	return FALSE;
}

/**
  Validates key components of Ed context.
  NOTE: This function performs integrity checks on all the Ed key material, so
        the Ed key structure must contain all the private key data.

  If ecd_context is NULL, then return FALSE.

  @param[in]  ecd_context  Pointer to Ed context to check.

  @retval  TRUE   Ed key components are valid.
  @retval  FALSE  Ed key components are not valid.

**/
boolean ecd_check_key(IN void *ecd_context)
{
	return FALSE;
}

/**
  Generates Ed key and returns Ed public key.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  If ecd_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ecd_context      Pointer to the Ed context.
  @param[out]      public         Pointer to the buffer to receive generated public key.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   Ed public key generation succeeded.
  @retval FALSE  Ed public key generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ecd_generate_key(IN OUT void *ecd_context, OUT uint8_t *public_key,
			 IN OUT uintn *public_key_size)
{
	return FALSE;
}

/**
  Carries out the Ed-DSA signature.

  This function carries out the Ed-DSA signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If ecd_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  hash_nid must be NULL.
  If sig_size is large enough but signature is NULL, then return FALSE.

  For ed25519, context must be NULL and context_size must be 0.
  For ed448, context must be maximum of 255 octets.

  For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.

  @param[in]       ecd_context    Pointer to Ed context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       context      the EDDSA signing context.
  @param[in]       context_size size of EDDSA signing context.
  @param[in]       message      Pointer to octet message to be signed (before hash).
  @param[in]       size         size of the message in bytes.
  @param[out]      signature    Pointer to buffer to receive Ed-DSA signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in Ed-DSA.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean eddsa_sign(IN void *ecd_context, IN uintn hash_nid,
		   IN const uint8_t *context, IN uintn context_size,
		   IN const uint8_t *message, IN uintn size, OUT uint8_t *signature,
		   IN OUT uintn *sig_size)
{
	return FALSE;
}

/**
  Verifies the Ed-DSA signature.

  If ecd_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  hash_nid must be NULL.

  For ed25519, context must be NULL and context_size must be 0.
  For ed448, context must be maximum of 255 octets.

  For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.

  @param[in]  ecd_context    Pointer to Ed context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  context      the EDDSA signing context.
  @param[in]  context_size size of EDDSA signing context.
  @param[in]  message      Pointer to octet message to be checked (before hash).
  @param[in]  size         size of the message in bytes.
  @param[in]  signature    Pointer to Ed-DSA signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in Ed-DSA.
  @retval  FALSE  Invalid signature or invalid Ed context.

**/
boolean eddsa_verify(IN void *ecd_context, IN uintn hash_nid,
		     IN const uint8_t *context, IN uintn context_size,
		     IN const uint8_t *message, IN uintn size,
		     IN const uint8_t *signature, IN uintn sig_size)
{
	return FALSE;
}
