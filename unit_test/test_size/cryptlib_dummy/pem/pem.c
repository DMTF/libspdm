/** @file
  PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation over OpenSSL.

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "internal_crypt_lib.h"

/**
  Retrieve the RSA Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
                           RSA private key component. Use rsa_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If rsa_context is NULL, then return FALSE.

  @retval  TRUE   RSA Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean rsa_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **rsa_context)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Retrieve the EC Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
                           EC private key component. Use ec_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If ec_context is NULL, then return FALSE.

  @retval  TRUE   EC Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean ec_get_private_key_from_pem(IN const uint8 *pem_data, IN uintn pem_size,
				    IN const char8 *password,
				    OUT void **ec_context)
{
	ASSERT(FALSE);
	return FALSE;
}
