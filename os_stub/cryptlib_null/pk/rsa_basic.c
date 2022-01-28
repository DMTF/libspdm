/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  RSA Asymmetric Cipher Wrapper Implementation.

  This file implements following APIs which provide basic capabilities for RSA:
  1) rsa_new
  2) rsa_free
  3) rsa_set_key
  4) rsa_pkcs1_verify

  RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
**/

#include "internal_crypt_lib.h"

/**
  Allocates and initializes one RSA context for subsequent use.

  @return  Pointer to the RSA context that has been initialized.
           If the allocations fails, rsa_new() returns NULL.

**/
void *rsa_new(void)
{
    ASSERT(FALSE);
    return NULL;
}

/**
  Release the specified RSA context.

  @param[in]  rsa_context  Pointer to the RSA context to be released.

**/
void rsa_free(IN void *rsa_context)
{
    ASSERT(FALSE);
}

/**
  Sets the tag-designated key component into the established RSA context.

  This function sets the tag-designated RSA key component into the established
  RSA context from the user-specified non-negative integer (octet string format
  represented in RSA PKCS#1).
  If big_number is NULL, then the specified key component in RSA context is cleared.

  If rsa_context is NULL, then return FALSE.

  @param[in, out]  rsa_context  Pointer to RSA context being set.
  @param[in]       key_tag      tag of RSA key component being set.
  @param[in]       big_number   Pointer to octet integer buffer.
                               If NULL, then the specified key component in RSA
                               context is cleared.
  @param[in]       bn_size      size of big number buffer in bytes.
                               If big_number is NULL, then it is ignored.

  @retval  TRUE   RSA key component was set successfully.
  @retval  FALSE  Invalid RSA key component tag.

**/
boolean rsa_set_key(IN OUT void *rsa_context, IN rsa_key_tag_t key_tag,
            IN const uint8_t *big_number, IN uintn bn_size)
{
    ASSERT(FALSE);
    return FALSE;
}

/**
  Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
  RSA PKCS#1.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.

  @param[in]  rsa_context   Pointer to RSA context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message_hash  Pointer to octet message hash to be checked.
  @param[in]  hash_size     size of the message hash in bytes.
  @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in PKCS1-v1_5.
  @retval  FALSE  Invalid signature or invalid RSA context.

**/
boolean rsa_pkcs1_verify_with_nid(IN void *rsa_context, IN uintn hash_nid,
                  IN const uint8_t *message_hash,
                  IN uintn hash_size, IN const uint8_t *signature,
                  IN uintn sig_size)
{
    ASSERT(FALSE);
    return FALSE;
}

/**
  Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
  RSA PKCS#1 v2.2.

  The salt length is same as digest length.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.

  @param[in]  rsa_context   Pointer to RSA context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message_hash  Pointer to octet message hash to be checked.
  @param[in]  hash_size     size of the message hash in bytes.
  @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in RSA-SSA PSS.
  @retval  FALSE  Invalid signature or invalid RSA context.

**/
boolean rsa_pss_verify(IN void *rsa_context, IN uintn hash_nid,
               IN const uint8_t *message_hash, IN uintn hash_size,
               IN const uint8_t *signature, IN uintn sig_size)
{
    ASSERT(FALSE);
    return FALSE;
}
