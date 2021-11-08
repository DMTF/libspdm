/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Diffie-Hellman Wrapper Implementation over.

  RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
**/

#include "internal_crypt_lib.h"

/**
  Allocates and Initializes one Diffie-Hellman context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Diffie-Hellman context that has been initialized.
           If the allocations fails, dh_new() returns NULL.

**/
void *dh_new_by_nid(IN uintn nid)
{
	ASSERT(FALSE);
	return NULL;
}

/**
  Release the specified DH context.

  If dh_context is NULL, then return FALSE.

  @param[in]  dh_context  Pointer to the DH context to be released.

**/
void dh_free(IN void *dh_context)
{
	ASSERT(FALSE);
}

/**
  Generates DH parameter.

  Given generator g, and length of prime number p in bits, this function generates p,
  and sets DH context according to value of g and p.

  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by random_seed().

  If dh_context is NULL, then return FALSE.
  If prime is NULL, then return FALSE.

  @param[in, out]  dh_context    Pointer to the DH context.
  @param[in]       generator    value of generator.
  @param[in]       prime_length  length in bits of prime to be generated.
  @param[out]      prime        Pointer to the buffer to receive the generated prime number.

  @retval TRUE   DH parameter generation succeeded.
  @retval FALSE  value of generator is not supported.
  @retval FALSE  PRNG fails to generate random prime number with prime_length.

**/
boolean dh_generate_parameter(IN OUT void *dh_context, IN uintn generator,
			      IN uintn prime_length, OUT uint8 *prime)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Sets generator and prime parameters for DH.

  Given generator g, and prime number p, this function and sets DH
  context accordingly.

  If dh_context is NULL, then return FALSE.
  If prime is NULL, then return FALSE.

  @param[in, out]  dh_context    Pointer to the DH context.
  @param[in]       generator    value of generator.
  @param[in]       prime_length  length in bits of prime to be generated.
  @param[in]       prime        Pointer to the prime number.

  @retval TRUE   DH parameter setting succeeded.
  @retval FALSE  value of generator is not supported.
  @retval FALSE  value of generator is not suitable for the prime.
  @retval FALSE  value of prime is not a prime number.
  @retval FALSE  value of prime is not a safe prime number.

**/
boolean dh_set_parameter(IN OUT void *dh_context, IN uintn generator,
			 IN uintn prime_length, IN const uint8 *prime)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Generates DH public key.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  If dh_context is NULL, then return FALSE.
  If public_key_size is NULL, then return FALSE.
  If public_key_size is large enough but public_key is NULL, then return FALSE.

  @param[in, out]  dh_context      Pointer to the DH context.
  @param[out]      public_key      Pointer to the buffer to receive generated public key.
  @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
                                  On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DH public key generation succeeded.
  @retval FALSE  DH public key generation failed.
  @retval FALSE  public_key_size is not large enough.

**/
boolean dh_generate_key(IN OUT void *dh_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  If dh_context is NULL, then return FALSE.
  If peer_public_key is NULL, then return FALSE.
  If key_size is NULL, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  @param[in, out]  dh_context          Pointer to the DH context.
  @param[in]       peer_public_key      Pointer to the peer's public key.
  @param[in]       peer_public_key_size  size of peer's public key in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   DH exchanged key generation succeeded.
  @retval FALSE  DH exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean dh_compute_key(IN OUT void *dh_context, IN const uint8 *peer_public_key,
		       IN uintn peer_public_key_size, OUT uint8 *key,
		       IN OUT uintn *key_size)
{
	ASSERT(FALSE);
	return FALSE;
}
