/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  HMAC-SHA3_256/384/512 KDF Wrapper Implementation.

  RFC 5869: HMAC-based Extract-and-Expand key Derivation Function (HKDF)
**/

#include "internal_crypt_lib.h"

/**
  Derive SHA3_256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_256_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}

/**
  Derive SHA3_256 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_256_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
	return FALSE;
}

/**
  Derive SHA3_256 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_256_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}

/**
  Derive SHA3_384 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_384_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}

/**
  Derive SHA3_384 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_384_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
	return FALSE;
}

/**
  Derive SHA3_384 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_384_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}

/**
  Derive SHA3_512 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_512_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}

/**
  Derive SHA3_512 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_512_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
	return FALSE;
}

/**
  Derive SHA3_512 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha3_512_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}
