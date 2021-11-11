/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_secured_message_lib.h"

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return  Pointer to the Diffie-Hellman context that has been initialized.
**/
void *spdm_secured_message_dhe_new(IN uint16 dhe_named_group)
{
	return spdm_dhe_new(dhe_named_group);
}

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context to be released.
**/
void spdm_secured_message_dhe_free(IN uint16 dhe_named_group,
				   IN void *dhe_context)
{
	spdm_dhe_free(dhe_named_group, dhe_context);
}

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context.
  @param  public_key                    Pointer to the buffer to receive generated public key.
  @param  public_key_size                On input, the size of public_key buffer in bytes.
                                       On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  public_key_size is not large enough.
**/
boolean spdm_secured_message_dhe_generate_key(IN uint16 dhe_named_group,
					      IN OUT void *dhe_context,
					      OUT uint8 *public_key,
					      IN OUT uintn *public_key_size)
{
	return spdm_dhe_generate_key(dhe_named_group, dhe_context, public_key,
				     public_key_size);
}

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            size of peer's public key in bytes.
  @param  key                          Pointer to the buffer to receive generated key.
  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
**/
boolean spdm_secured_message_dhe_compute_key(
	IN uint16 dhe_named_group, IN OUT void *dhe_context,
	IN const uint8 *peer_public, IN uintn peer_public_size,
	IN OUT void *spdm_secured_message_context)
{
	spdm_secured_message_context_t *secured_message_context;
	uint8 final_key[MAX_DHE_KEY_SIZE];
	uintn final_key_size;
	boolean ret;

	secured_message_context = spdm_secured_message_context;

	final_key_size = sizeof(final_key);
	ret = spdm_dhe_compute_key(dhe_named_group, dhe_context, peer_public,
				   peer_public_size, final_key,
				   &final_key_size);
	if (!ret) {
		return ret;
	}
	copy_mem(secured_message_context->master_secret.dhe_secret, final_key,
		 final_key_size);
	secured_message_context->dhe_key_size = final_key_size;
	return TRUE;
}
