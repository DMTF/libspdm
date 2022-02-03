/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

/**
 * Retrieve the RSA Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
 *                         RSA private key component. Use rsa_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool rsa_get_private_key_from_pem(IN const uint8_t *pem_data,
                                  IN uintn pem_size,
                                  IN const char *password,
                                  OUT void **rsa_context)
{
    ASSERT(false);
    return false;
}

/**
 * Retrieve the EC Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
 *                         EC private key component. Use ec_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool ec_get_private_key_from_pem(IN const uint8_t *pem_data, IN uintn pem_size,
                                 IN const char *password,
                                 OUT void **ec_context)
{
    ASSERT(false);
    return false;
}

/**
 * Retrieve the Ed Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
 *                         Ed private key component. Use ecd_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool ecd_get_private_key_from_pem(IN const uint8_t *pem_data,
                                  IN uintn pem_size,
                                  IN const char *password,
                                  OUT void **ecd_context)
{
    ASSERT(false);
    return false;
}

/**
 * Retrieve the sm2 Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
 *                         sm2 private key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool sm2_get_private_key_from_pem(IN const uint8_t *pem_data,
                                  IN uintn pem_size,
                                  IN const char *password,
                                  OUT void **sm2_context)
{
    ASSERT(false);
    return false;
}
