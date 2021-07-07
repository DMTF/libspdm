/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_CRYPTO_LIB_H__
#define __SPDM_CRYPTO_LIB_H__

#include "spdm_lib_config.h"

#include <base.h>
#include <industry_standard/spdm.h>
#include <library/debuglib.h>
#include <library/memlib.h>
#include <library/cryptlib.h>

#define MAX_DHE_KEY_SIZE 512
#define MAX_ASYM_KEY_SIZE 512
#define MAX_HASH_SIZE 64
#define MAX_AEAD_KEY_SIZE 32
#define MAX_AEAD_IV_SIZE 12

/**
  Computes the hash of a input data buffer.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  data                         Pointer to the buffer containing the data to be hashed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the hash value.

  @retval TRUE   hash computation succeeded.
  @retval FALSE  hash computation failed.
**/
typedef boolean (*hash_all_func)(IN const void *data, IN uintn data_size,
				 OUT uint8 *hash_value);

/**
  Computes the HMAC of a input data buffer.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  data                         Pointer to the buffer containing the data to be HMACed.
  @param  data_size                     size of data buffer in bytes.
  @param  key                          Pointer to the user-supplied key.
  @param  key_size                      key size in bytes.
  @param  hash_value                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
typedef boolean (*hmac_all_func)(IN const void *data, IN uintn data_size,
				 IN const uint8 *key, IN uintn key_size,
				 OUT uint8 *hmac_value);

/**
  Derive HMAC-based Expand key Derivation Function (HKDF) Expand.

  @param  prk                          Pointer to the user-supplied key.
  @param  prk_size                      key size in bytes.
  @param  info                         Pointer to the application specific info.
  @param  info_size                     info size in bytes.
  @param  out                          Pointer to buffer to receive hkdf value.
  @param  out_size                      size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
typedef boolean (*hkdf_expand_func)(IN const uint8 *prk, IN uintn prk_size,
				    IN const uint8 *info, IN uintn info_size,
				    OUT uint8 *out, IN uintn out_size);

/**
  Retrieve the asymmetric public key from one DER-encoded X509 certificate.

  @param  cert                         Pointer to the DER-encoded X509 certificate.
  @param  cert_size                     size of the X509 certificate in bytes.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
typedef boolean (*asym_get_public_key_from_x509_func)(IN const uint8 *cert,
						      IN uintn cert_size,
						      OUT void **context);

/**
  Release the specified asymmetric context.

  @param  context                      Pointer to the asymmetric context to be released.
**/
typedef void (*asym_free_func)(IN void *context);

/**
  Verifies the asymmetric signature.

  @param  context                      Pointer to asymmetric context for signature verification.
  @param  hash_nid                      hash NID
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to asymmetric signature to be verified.
  @param  sig_size                      size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
typedef boolean (*asym_verify_func)(IN void *context, IN uintn hash_nid,
				    IN const uint8 *message,
				    IN uintn message_size,
				    IN const uint8 *signature,
				    IN uintn sig_size);

/**
  Retrieve the Private key from the password-protected PEM key data.

  @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
  @param  pem_size                      size of the PEM key data in bytes.
  @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
typedef boolean (*asym_get_private_key_from_pem_func)(IN const uint8 *pem_data,
						      IN uintn pem_size,
						      IN const char8 *password,
						      OUT void **context);

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  context                      Pointer to asymmetric context for signature generation.
  @param  hash_nid                      hash NID
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
typedef boolean (*asym_sign_func)(IN void *context, IN uintn hash_nid,
				  IN const uint8 *message,
				  IN uintn message_size, OUT uint8 *signature,
				  IN OUT uintn *sig_size);

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use.

  @param nid cipher NID

  @return  Pointer to the Diffie-Hellman context that has been initialized.
**/
typedef void *(*dhe_new_by_nid_func)(IN uintn nid);

/**
  Generates DHE public key.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  @param  context                      Pointer to the DHE context.
  @param  public_key                    Pointer to the buffer to receive generated public key.
  @param  public_key_size                On input, the size of public_key buffer in bytes.
                                       On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  public_key_size is not large enough.
**/
typedef boolean (*dhe_generate_key_func)(IN OUT void *context,
					 OUT uint8 *public_key,
					 IN OUT uintn *public_key_size);

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  context                      Pointer to the DHE context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            size of peer's public key in bytes.
  @param  key                          Pointer to the buffer to receive generated key.
  @param  key_size                      On input, the size of key buffer in bytes.
                                       On output, the size of data returned in key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
**/
typedef boolean (*dhe_compute_key_func)(IN OUT void *context,
					IN const uint8 *peer_public,
					IN uintn peer_public_size,
					OUT uint8 *key, IN OUT uintn *key_size);

/**
  Release the specified DHE context.

  @param  context                      Pointer to the DHE context to be released.
**/
typedef void (*dhe_free_func)(IN void *context);

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD).

  @param  key                          Pointer to the encryption key.
  @param  key_size                      size of the encryption key in bytes.
  @param  iv                           Pointer to the IV value.
  @param  iv_size                       size of the IV value in bytes.
  @param  a_data                        Pointer to the additional authenticated data (AAD).
  @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
  @param  data_in                       Pointer to the input data buffer to be encrypted.
  @param  data_in_size                   size of the input data buffer in bytes.
  @param  tag_out                       Pointer to a buffer that receives the authentication tag output.
  @param  tag_size                      size of the authentication tag in bytes.
  @param  data_out                      Pointer to a buffer that receives the encryption output.
  @param  data_out_size                  size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
typedef boolean (*aead_encrypt_func)(
	IN const uint8 *key, IN uintn key_size, IN const uint8 *iv,
	IN uintn iv_size, IN const uint8 *a_data, IN uintn a_data_size,
	IN const uint8 *data_in, IN uintn data_in_size, OUT uint8 *tag_out,
	IN uintn tag_size, OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD).

  @param  key                          Pointer to the encryption key.
  @param  key_size                      size of the encryption key in bytes.
  @param  iv                           Pointer to the IV value.
  @param  iv_size                       size of the IV value in bytes.
  @param  a_data                        Pointer to the additional authenticated data (AAD).
  @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
  @param  data_in                       Pointer to the input data buffer to be decrypted.
  @param  data_in_size                   size of the input data buffer in bytes.
  @param  tag                          Pointer to a buffer that contains the authentication tag.
  @param  tag_size                      size of the authentication tag in bytes.
  @param  data_out                      Pointer to a buffer that receives the decryption output.
  @param  data_out_size                  size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
typedef boolean (*aead_decrypt_func)(
	IN const uint8 *key, IN uintn key_size, IN const uint8 *iv,
	IN uintn iv_size, IN const uint8 *a_data, IN uintn a_data_size,
	IN const uint8 *data_in, IN uintn data_in_size, IN const uint8 *tag,
	IN uintn tag_size, OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  This function returns the SPDM hash algorithm size.

  @param  base_hash_algo                  SPDM base_hash_algo

  @return SPDM hash algorithm size.
**/
uint32 spdm_get_hash_size(IN uint32 base_hash_algo);

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  data                         Pointer to the buffer containing the data to be hashed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the hash value.

  @retval TRUE   hash computation succeeded.
  @retval FALSE  hash computation failed.
**/
boolean spdm_hash_all(IN uint32 base_hash_algo, IN const void *data,
		      IN uintn data_size, OUT uint8 *hash_value);

/**
  This function returns the SPDM measurement hash algorithm size.

  @param  measurement_hash_algo          SPDM measurement_hash_algo

  @return SPDM measurement hash algorithm size.
  @return 0xFFFFFFFF for RAW_BIT_STREAM_ONLY.
**/
uint32 spdm_get_measurement_hash_size(IN uint32 measurement_hash_algo);

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  measurement_hash_algo          SPDM measurement_hash_algo
  @param  data                         Pointer to the buffer containing the data to be hashed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the hash value.

  @retval TRUE   hash computation succeeded.
  @retval FALSE  hash computation failed.
**/
boolean spdm_measurement_hash_all(IN uint32 measurement_hash_algo,
				  IN const void *data, IN uintn data_size,
				  OUT uint8 *hash_value);

/**
  Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  data                         Pointer to the buffer containing the data to be HMACed.
  @param  data_size                     size of data buffer in bytes.
  @param  key                          Pointer to the user-supplied key.
  @param  key_size                      key size in bytes.
  @param  hash_value                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
boolean spdm_hmac_all(IN uint32 base_hash_algo, IN const void *data,
		      IN uintn data_size, IN const uint8 *key,
		      IN uintn key_size, OUT uint8 *hmac_value);

/**
  Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  prk                          Pointer to the user-supplied key.
  @param  prk_size                      key size in bytes.
  @param  info                         Pointer to the application specific info.
  @param  info_size                     info size in bytes.
  @param  out                          Pointer to buffer to receive hkdf value.
  @param  out_size                      size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
boolean spdm_hkdf_expand(IN uint32 base_hash_algo, IN const uint8 *prk,
			 IN uintn prk_size, IN const uint8 *info,
			 IN uintn info_size, OUT uint8 *out, IN uintn out_size);

/**
  This function returns the SPDM asymmetric algorithm size.

  @param  base_asym_algo                 SPDM base_hash_algo

  @return SPDM asymmetric algorithm size.
**/
uint32 spdm_get_asym_signature_size(IN uint32 base_asym_algo);

/**
  Retrieve the asymmetric public key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  cert                         Pointer to the DER-encoded X509 certificate.
  @param  cert_size                     size of the X509 certificate in bytes.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
boolean spdm_asym_get_public_key_from_x509(IN uint32 base_asym_algo,
					   IN const uint8 *cert,
					   IN uintn cert_size,
					   OUT void **context);

/**
  Release the specified asymmetric context,
  based upon negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  context                      Pointer to the asymmetric context to be released.
**/
void spdm_asym_free(IN uint32 base_asym_algo, IN void *context);

/**
  Verifies the asymmetric signature,
  based upon negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature verification.
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to asymmetric signature to be verified.
  @param  sig_size                      size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
boolean spdm_asym_verify(IN uint32 base_asym_algo, IN uint32 base_hash_algo,
			 IN void *context, IN const uint8 *message,
			 IN uintn message_size, IN const uint8 *signature,
			 IN uintn sig_size);

/**
  Retrieve the Private key from the password-protected PEM key data.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
  @param  pem_size                      size of the PEM key data in bytes.
  @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
boolean spdm_asym_get_private_key_from_pem(IN uint32 base_asym_algo,
					   IN const uint8 *pem_data,
					   IN uintn pem_size,
					   IN const char8 *password,
					   OUT void **context);

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature generation.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean spdm_asym_sign(IN uint32 base_asym_algo, IN uint32 base_hash_algo,
		       IN void *context, IN const uint8 *message,
		       IN uintn message_size, OUT uint8 *signature,
		       IN OUT uintn *sig_size);

/**
  This function returns the SPDM requester asymmetric algorithm size.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return SPDM requester asymmetric algorithm size.
**/
uint32 spdm_get_req_asym_signature_size(IN uint16 req_base_asym_alg);

/**
  Retrieve the asymmetric public key from one DER-encoded X509 certificate,
  based upon negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  cert                         Pointer to the DER-encoded X509 certificate.
  @param  cert_size                     size of the X509 certificate in bytes.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
boolean spdm_req_asym_get_public_key_from_x509(IN uint16 req_base_asym_alg,
					       IN const uint8 *cert,
					       IN uintn cert_size,
					       OUT void **context);

/**
  Release the specified asymmetric context,
  based upon negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  context                      Pointer to the asymmetric context to be released.
**/
void spdm_req_asym_free(IN uint16 req_base_asym_alg, IN void *context);

/**
  Verifies the asymmetric signature,
  based upon negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature verification.
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to asymmetric signature to be verified.
  @param  sig_size                      size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
boolean spdm_req_asym_verify(IN uint16 req_base_asym_alg,
			     IN uint32 base_hash_algo, IN void *context,
			     IN const uint8 *message, IN uintn message_size,
			     IN const uint8 *signature, IN uintn sig_size);

/**
  Retrieve the Private key from the password-protected PEM key data.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
  @param  pem_size                      size of the PEM key data in bytes.
  @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
boolean spdm_req_asym_get_private_key_from_pem(IN uint16 req_base_asym_alg,
					       IN const uint8 *pem_data,
					       IN uintn pem_size,
					       IN const char8 *password,
					       OUT void **context);

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature generation.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean spdm_req_asym_sign(IN uint16 req_base_asym_alg,
			   IN uint32 base_hash_algo, IN void *context,
			   IN const uint8 *message, IN uintn message_size,
			   OUT uint8 *signature, IN OUT uintn *sig_size);

/**
  This function returns the SPDM DHE algorithm key size.

  @param  dhe_named_group                SPDM dhe_named_group

  @return SPDM DHE algorithm key size.
**/
uint32 spdm_get_dhe_pub_key_size(IN uint16 dhe_named_group);

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return  Pointer to the Diffie-Hellman context that has been initialized.
**/
void *spdm_dhe_new(IN uint16 dhe_named_group);

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  context                      Pointer to the DHE context to be released.
**/
void spdm_dhe_free(IN uint16 dhe_named_group, IN void *context);

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  context                      Pointer to the DHE context.
  @param  public_key                    Pointer to the buffer to receive generated public key.
  @param  public_key_size                On input, the size of public_key buffer in bytes.
                                       On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  public_key_size is not large enough.
**/
boolean spdm_dhe_generate_key(IN uint16 dhe_named_group, IN OUT void *context,
			      OUT uint8 *public_key,
			      IN OUT uintn *public_key_size);

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  context                      Pointer to the DHE context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            size of peer's public key in bytes.
  @param  key                          Pointer to the buffer to receive generated key.
  @param  key_size                      On input, the size of key buffer in bytes.
                                       On output, the size of data returned in key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
**/
boolean spdm_dhe_compute_key(IN uint16 dhe_named_group, IN OUT void *context,
			     IN const uint8 *peer_public,
			     IN uintn peer_public_size, OUT uint8 *key,
			     IN OUT uintn *key_size);

/**
  This function returns the SPDM AEAD algorithm key size.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return SPDM AEAD algorithm key size.
**/
uint32 spdm_get_aead_key_size(IN uint16 aead_cipher_suite);

/**
  This function returns the SPDM AEAD algorithm iv size.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return SPDM AEAD algorithm iv size.
**/
uint32 spdm_get_aead_iv_size(IN uint16 aead_cipher_suite);

/**
  This function returns the SPDM AEAD algorithm tag size.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return SPDM AEAD algorithm tag size.
**/
uint32 spdm_get_aead_tag_size(IN uint16 aead_cipher_suite);

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  aead_cipher_suite              SPDM aead_cipher_suite
  @param  key                          Pointer to the encryption key.
  @param  key_size                      size of the encryption key in bytes.
  @param  iv                           Pointer to the IV value.
  @param  iv_size                       size of the IV value in bytes.
  @param  a_data                        Pointer to the additional authenticated data (AAD).
  @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
  @param  data_in                       Pointer to the input data buffer to be encrypted.
  @param  data_in_size                   size of the input data buffer in bytes.
  @param  tag_out                       Pointer to a buffer that receives the authentication tag output.
  @param  tag_size                      size of the authentication tag in bytes.
  @param  data_out                      Pointer to a buffer that receives the encryption output.
  @param  data_out_size                  size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
boolean spdm_aead_encryption(IN uint16 aead_cipher_suite, IN const uint8 *key,
			     IN uintn key_size, IN const uint8 *iv,
			     IN uintn iv_size, IN const uint8 *a_data,
			     IN uintn a_data_size, IN const uint8 *data_in,
			     IN uintn data_in_size, OUT uint8 *tag_out,
			     IN uintn tag_size, OUT uint8 *data_out,
			     OUT uintn *data_out_size);

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  aead_cipher_suite              SPDM aead_cipher_suite
  @param  key                          Pointer to the encryption key.
  @param  key_size                      size of the encryption key in bytes.
  @param  iv                           Pointer to the IV value.
  @param  iv_size                       size of the IV value in bytes.
  @param  a_data                        Pointer to the additional authenticated data (AAD).
  @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
  @param  data_in                       Pointer to the input data buffer to be decrypted.
  @param  data_in_size                   size of the input data buffer in bytes.
  @param  tag                          Pointer to a buffer that contains the authentication tag.
  @param  tag_size                      size of the authentication tag in bytes.
  @param  data_out                      Pointer to a buffer that receives the decryption output.
  @param  data_out_size                  size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
boolean spdm_aead_decryption(IN uint16 aead_cipher_suite, IN const uint8 *key,
			     IN uintn key_size, IN const uint8 *iv,
			     IN uintn iv_size, IN const uint8 *a_data,
			     IN uintn a_data_size, IN const uint8 *data_in,
			     IN uintn data_in_size, IN const uint8 *tag,
			     IN uintn tag_size, OUT uint8 *data_out,
			     OUT uintn *data_out_size);

/**
  Generates a random byte stream of the specified size.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  size                         size of random bytes to generate.
  @param  rand                         Pointer to buffer to receive random value.
**/
void spdm_get_random_number(IN uintn size, OUT uint8 *rand);

/**
  Certificate Check for SPDM leaf cert.

  @param[in]  cert            Pointer to the DER-encoded certificate data.
  @param[in]  cert_size        The size of certificate data in bytes.

  @retval  TRUE   Success.
  @retval  FALSE  Certificate is not valid
**/
boolean spdm_x509_certificate_check(IN const uint8 *cert, IN uintn cert_size);

/**
  Retrieve the SubjectAltName from SubjectAltName Bytes.

  @param[in]      buffer           Pointer to subjectAltName oct bytes.
  @param[in]      len              size of buffer in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate
                                   SubjectAltName. At most name_buffer_size bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     oid              OID of otherName
  @param[in,out]  oid_size          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   name_buffer_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status spdm_get_dmtf_subject_alt_name_from_bytes(
	IN const uint8 *buffer, IN intn len, OUT char8 *name_buffer,
	OPTIONAL IN OUT uintn *name_buffer_size, OUT uint8 *oid,
	OPTIONAL IN OUT uintn *oid_size);

/**
  Retrieve the SubjectAltName from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate
                                   SubjectAltName. At most name_buffer_size bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     oid              OID of otherName
  @param[in,out]  oid_size          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   name_buffer_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status
spdm_get_dmtf_subject_alt_name(IN const uint8 *cert, IN intn cert_size,
			       OUT char8 *name_buffer,
			       OPTIONAL IN OUT uintn *name_buffer_size,
			       OUT uint8 *oid, OPTIONAL IN OUT uintn *oid_size);

/**
  This function verifies the integrity of certificate chain data without spdm_cert_chain_t header.

  @param  cert_chain_data          The certificate chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size      size in bytes of the certificate chain data.

  @retval TRUE  certificate chain data integrity verification pass.
  @retval FALSE certificate chain data integrity verification fail.
**/
boolean spdm_verify_cert_chain_data(IN uint8 *cert_chain_data,
				    IN uintn cert_chain_data_size);

/**
  This function verifies the integrity of certificate chain buffer including spdm_cert_chain_t header.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  cert_chain_buffer              The certificate chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certificate chain buffer.

  @retval TRUE  certificate chain buffer integrity verification pass.
  @retval FALSE certificate chain buffer integrity verification fail.
**/
boolean spdm_verify_certificate_chain_buffer(IN uint32 base_hash_algo,
					     IN void *cert_chain_buffer,
					     IN uintn cert_chain_buffer_size);

#endif