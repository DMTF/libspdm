/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  HMAC-SHA256 KDF Wrapper Implementation.

  RFC 5869: HMAC-based Extract-and-Expand key Derivation Function (HKDF)
**/

#include "internal_crypt_lib.h"
#include <mbedtls/hkdf.h>

/**
  Derive HMAC-based Extract-and-Expand key Derivation Function (HKDF).

  @param[in]   md_type           message digest Type.
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
boolean hkdf_md_extract_and_expand(IN mbedtls_md_type_t md_type,
				   IN const uint8 *key, IN uintn key_size,
				   IN const uint8 *salt, IN uintn salt_size,
				   IN const uint8 *info, IN uintn info_size,
				   OUT uint8 *out, IN uintn out_size)
{
	const mbedtls_md_info_t *md;
	int32 ret;

	if (key == NULL || salt == NULL || info == NULL || out == NULL ||
	    key_size > INT_MAX || salt_size > INT_MAX || info_size > INT_MAX ||
	    out_size > INT_MAX) {
		return FALSE;
	}

	md = mbedtls_md_info_from_type(md_type);
	ASSERT(md != NULL);

	ret = mbedtls_hkdf(md, salt, (uint32)salt_size, key, (uint32)key_size,
			   info, (uint32)info_size, out, (uint32)out_size);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Derive HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   md_type           message digest Type.
  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_md_extract(IN mbedtls_md_type_t md_type, IN const uint8 *key,
			IN uintn key_size, IN const uint8 *salt,
			IN uintn salt_size, OUT uint8 *prk_out,
			IN uintn prk_out_size)
{
	const mbedtls_md_info_t *md;
	int32 ret;
	uintn md_size;

	if (key == NULL || salt == NULL || prk_out == NULL ||
	    key_size > INT_MAX || salt_size > INT_MAX ||
	    prk_out_size > INT_MAX) {
		return FALSE;
	}

	md_size = 0;
	switch (md_type) {
	case MBEDTLS_MD_SHA256:
		md_size = SHA256_DIGEST_SIZE;
		break;
	case MBEDTLS_MD_SHA384:
		md_size = SHA384_DIGEST_SIZE;
		break;
	case MBEDTLS_MD_SHA512:
		md_size = SHA512_DIGEST_SIZE;
		break;
	default:
		return FALSE;
	}
	if (prk_out_size != md_size) {
		return FALSE;
	}

	md = mbedtls_md_info_from_type(md_type);
	ASSERT(md != NULL);

	ret = mbedtls_hkdf_extract(md, salt, (uint32)salt_size, key,
				   (uint32)key_size, prk_out);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Derive HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   md_type           message digest Type.
  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_md_expand(IN mbedtls_md_type_t md_type, IN const uint8 *prk,
		       IN uintn prk_size, IN const uint8 *info,
		       IN uintn info_size, OUT uint8 *out, IN uintn out_size)
{
	const mbedtls_md_info_t *md;
	int32 ret;
	uintn md_size;

	if (prk == NULL || info == NULL || out == NULL || prk_size > INT_MAX ||
	    info_size > INT_MAX || out_size > INT_MAX) {
		return FALSE;
	}

	switch (md_type) {
	case MBEDTLS_MD_SHA256:
		md_size = SHA256_DIGEST_SIZE;
		break;
	case MBEDTLS_MD_SHA384:
		md_size = SHA384_DIGEST_SIZE;
		break;
	case MBEDTLS_MD_SHA512:
		md_size = SHA512_DIGEST_SIZE;
		break;
	}
	if (prk_size != md_size) {
		return FALSE;
	}

	md = mbedtls_md_info_from_type(md_type);
	ASSERT(md != NULL);

	ret = mbedtls_hkdf_expand(md, prk, (uint32)prk_size, info,
				  (uint32)info_size, out, (uint32)out_size);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Derive SHA256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

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
boolean hkdf_sha256_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
	return hkdf_md_extract_and_expand(MBEDTLS_MD_SHA256, key, key_size,
					  salt, salt_size, info, info_size, out,
					  out_size);
}

/**
  Derive SHA256 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha256_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
	return hkdf_md_extract(MBEDTLS_MD_SHA256, key, key_size, salt,
			       salt_size, prk_out, prk_out_size);
}

/**
  Derive SHA256 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha256_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
	return hkdf_md_expand(MBEDTLS_MD_SHA256, prk, prk_size, info, info_size,
			      out, out_size);
}

/**
  Derive SHA384 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

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
boolean hkdf_sha384_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
	return hkdf_md_extract_and_expand(MBEDTLS_MD_SHA384, key, key_size,
					  salt, salt_size, info, info_size, out,
					  out_size);
}

/**
  Derive SHA384 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha384_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
	return hkdf_md_extract(MBEDTLS_MD_SHA384, key, key_size, salt,
			       salt_size, prk_out, prk_out_size);
}

/**
  Derive SHA384 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha384_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
	return hkdf_md_expand(MBEDTLS_MD_SHA384, prk, prk_size, info, info_size,
			      out, out_size);
}

/**
  Derive SHA512 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

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
boolean hkdf_sha512_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
	return hkdf_md_extract_and_expand(MBEDTLS_MD_SHA512, key, key_size,
					  salt, salt_size, info, info_size, out,
					  out_size);
}

/**
  Derive SHA512 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha512_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
	return hkdf_md_extract(MBEDTLS_MD_SHA512, key, key_size, salt,
			       salt_size, prk_out, prk_out_size);
}

/**
  Derive SHA512 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha512_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
	return hkdf_md_expand(MBEDTLS_MD_SHA512, prk, prk_size, info, info_size,
			      out, out_size);
}
