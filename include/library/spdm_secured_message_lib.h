/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_SECURED_MESSAGE_LIB_H__
#define __SPDM_SECURED_MESSAGE_LIB_H__

#ifndef LIBSPDM_CONFIG
#include "library/spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#include "hal/base.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_secured_message.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "hal/library/cryptlib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_device_secret_lib.h"

#define BIN_CONCAT_LABEL "spdm1.1 "
#define BIN_STR_0_LABEL "derived"
#define BIN_STR_1_LABEL "req hs data"
#define BIN_STR_2_LABEL "rsp hs data"
#define BIN_STR_3_LABEL "req app data"
#define BIN_STR_4_LABEL "rsp app data"
#define BIN_STR_5_LABEL "key"
#define BIN_STR_6_LABEL "iv"
#define BIN_STR_7_LABEL "finished"
#define BIN_STR_8_LABEL "exp master"
#define BIN_STR_9_LABEL "traffic upd"

typedef enum {
    SPDM_SESSION_TYPE_NONE,
    SPDM_SESSION_TYPE_MAC_ONLY,
    SPDM_SESSION_TYPE_ENC_MAC,
    SPDM_SESSION_TYPE_MAX,
} spdm_session_type_t;

typedef enum {
    
    /* Before send KEY_EXCHANGE/PSK_EXCHANGE*/
    /* or after END_SESSION*/
    
    SPDM_SESSION_STATE_NOT_STARTED,
    
    /* After send KEY_EXHCNAGE, before send FINISH*/
    
    SPDM_SESSION_STATE_HANDSHAKING,
    
    /* After send FINISH, before END_SESSION*/
    
    SPDM_SESSION_STATE_ESTABLISHED,
    
    /* MAX*/
    
    SPDM_SESSION_STATE_MAX,
} spdm_session_state_t;

/**
  Return the size in bytes of the SPDM secured message context.

  @return the size in bytes of the SPDM secured message context.
**/
uintn spdm_secured_message_get_context_size(void);

/**
  Initialize an SPDM secured message context.

  The size in bytes of the spdm_secured_message_context can be returned by spdm_secured_message_get_context_size.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
*/
void spdm_secured_message_init_context(IN void *spdm_secured_message_context);

/**
  Set use_psk to an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  use_psk                       Indicate if the SPDM session use PSK.
*/
void spdm_secured_message_set_use_psk(IN void *spdm_secured_message_context,
                      IN boolean use_psk);

/**
  Return if finished_key is ready.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @retval TRUE  finished_key is ready.
  @retval FALSE finished_key is not ready.
*/
boolean
spdm_secured_message_is_finished_key_ready(IN void *spdm_secured_message_context);

/**
  Set session_state to an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  session_state                 Indicate the SPDM session state.
*/
void spdm_secured_message_set_session_state(
    IN void *spdm_secured_message_context,
    IN spdm_session_state_t session_state);

/**
  Return session_state of an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @return the SPDM session state.
*/
spdm_session_state_t
spdm_secured_message_get_session_state(IN void *spdm_secured_message_context);

/**
  Set session_type to an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  session_type                  Indicate the SPDM session type.
*/
void spdm_secured_message_set_session_type(IN void *spdm_secured_message_context,
                       IN spdm_session_type_t session_type);

/**
  Set algorithm to an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  base_hash_algo                 Indicate the negotiated base_hash_algo for the SPDM session.
  @param  dhe_named_group                Indicate the negotiated dhe_named_group for the SPDM session.
  @param  aead_cipher_suite              Indicate the negotiated aead_cipher_suite for the SPDM session.
  @param  key_schedule                  Indicate the negotiated key_schedule for the SPDM session.
*/
void spdm_secured_message_set_algorithms(IN void *spdm_secured_message_context,
                     IN spdm_version_number_t version,
                     IN spdm_version_number_t secured_message_version,
                     IN uint32_t base_hash_algo,
                     IN uint16_t dhe_named_group,
                     IN uint16_t aead_cipher_suite,
                     IN uint16_t key_schedule);

/**
  Set the psk_hint to an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  psk_hint                      Indicate the PSK hint.
  @param  psk_hint_size                  The size in bytes of the PSK hint.
*/
void spdm_secured_message_set_psk_hint(IN void *spdm_secured_message_context,
                       IN void *psk_hint,
                       IN uintn psk_hint_size);

/**
  Import the DHE Secret to an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  dhe_secret                    Indicate the DHE secret.
  @param  dhe_secret_size                The size in bytes of the DHE secret.

  @retval RETURN_SUCCESS  DHE Secret is imported.
*/
return_status
spdm_secured_message_import_dhe_secret(IN void *spdm_secured_message_context,
                       IN void *dhe_secret,
                       IN uintn dhe_secret_size);

/**
  Export the export_master_secret from an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  export_master_secret           Indicate the buffer to store the export_master_secret.
  @param  export_master_secret_size       The size in bytes of the export_master_secret.

  @retval RETURN_SUCCESS  export_master_secret is exported.
*/
return_status spdm_secured_message_export_master_secret(
    IN void *spdm_secured_message_context, OUT void *export_master_secret,
    IN OUT uintn *export_master_secret_size);

#define SPDM_SECURE_SESSION_KEYS_STRUCT_VERSION 1

#pragma pack(1)
typedef struct {
    uint32_t version;
    uint32_t aead_key_size;
    uint32_t aead_iv_size;
    /*  uint8_t                request_data_encryption_key[aead_key_size];*/
    /*  uint8_t                request_data_salt[aead_iv_size];*/
    /*  uint64_t               request_data_sequence_number;*/
    /*  uint8_t                response_data_encryption_key[aead_key_size];*/
    /*  uint8_t                response_data_salt[aead_iv_size];*/
    /*  uint64_t               response_data_sequence_number;*/
} spdm_secure_session_keys_struct_t;
#pragma pack()

/**
  Export the SessionKeys from an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  SessionKeys                  Indicate the buffer to store the SessionKeys in spdm_secure_session_keys_struct_t.
  @param  SessionKeysSize              The size in bytes of the SessionKeys in spdm_secure_session_keys_struct_t.

  @retval RETURN_SUCCESS  SessionKeys are exported.
*/
return_status
spdm_secured_message_export_session_keys(IN void *spdm_secured_message_context,
                     OUT void *SessionKeys,
                     IN OUT uintn *SessionKeysSize);

/**
  Import the SessionKeys from an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  SessionKeys                  Indicate the buffer to store the SessionKeys in spdm_secure_session_keys_struct_t.
  @param  SessionKeysSize              The size in bytes of the SessionKeys in spdm_secure_session_keys_struct_t.

  @retval RETURN_SUCCESS  SessionKeys are imported.
*/
return_status
spdm_secured_message_import_session_keys(IN void *spdm_secured_message_context,
                     IN void *SessionKeys,
                     IN uintn SessionKeysSize);

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return  Pointer to the Diffie-Hellman context that has been initialized.
**/
void *spdm_secured_message_dhe_new(IN uint16_t dhe_named_group);

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context to be released.
**/
void spdm_secured_message_dhe_free(IN uint16_t dhe_named_group,
                   IN void *dhe_context);

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
boolean spdm_secured_message_dhe_generate_key(IN uint16_t dhe_named_group,
                          IN OUT void *dhe_context,
                          OUT uint8_t *public_key,
                          IN OUT uintn *public_key_size);

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            size of peer's public key in bytes.
  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
**/
boolean spdm_secured_message_dhe_compute_key(
    IN uint16_t dhe_named_group, IN OUT void *dhe_context,
    IN const uint8_t *peer_public, IN uintn peer_public_size,
    IN OUT void *spdm_secured_message_context);

/**
  This function used to clear handshake secret.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
**/
void spdm_clear_handshake_secret(IN void *spdm_secured_message_context);

/**
  Allocates and initializes one HMAC context for subsequent use, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @return Pointer to the HMAC context that has been initialized.
**/
void *
spdm_hmac_new_with_request_finished_key(
    IN void *spdm_secured_message_context);

/**
  Release the specified HMAC context, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx                   Pointer to the HMAC context to be released.
**/
void spdm_hmac_free_with_request_finished_key(
    IN void *spdm_secured_message_context, IN void *hmac_ctx);

/**
  Set request_finished_key for subsequent use. It must be done before any
  calling to hmac_update().

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx  Pointer to HMAC context.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
**/
boolean spdm_hmac_init_with_request_finished_key(
    IN void *spdm_secured_message_context, OUT void *hmac_ctx);

/**
  Makes a copy of an existing HMAC context, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx     Pointer to HMAC context being copied.
  @param  new_hmac_ctx  Pointer to new HMAC context.

  @retval TRUE   HMAC context copy succeeded.
  @retval FALSE  HMAC context copy failed.
**/
boolean spdm_hmac_duplicate_with_request_finished_key(
    IN void *spdm_secured_message_context,
    IN const void *hmac_ctx, OUT void *new_hmac_ctx);

/**
  Digests the input data and updates HMAC context, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx     Pointer to HMAC context being copied.
  @param  data              Pointer to the buffer containing the data to be digested.
  @param  data_size          size of data buffer in bytes.

  @retval TRUE   HMAC data digest succeeded.
  @retval FALSE  HMAC data digest failed.
**/
boolean spdm_hmac_update_with_request_finished_key(
    IN void *spdm_secured_message_context,
    OUT void *hmac_ctx, IN const void *data,
    IN uintn data_size);

/**
  Completes computation of the HMAC digest value, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx     Pointer to HMAC context being copied.
  @param  hmac_value          Pointer to a buffer that receives the HMAC digest value

  @retval TRUE   HMAC data digest succeeded.
  @retval FALSE  HMAC data digest failed.
**/
boolean spdm_hmac_final_with_request_finished_key(
    IN void *spdm_secured_message_context,
    OUT void *hmac_ctx,  OUT uint8_t *hmac_value);

/**
  Computes the HMAC of a input data buffer, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  data                         Pointer to the buffer containing the data to be HMACed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
boolean
spdm_hmac_all_with_request_finished_key(IN void *spdm_secured_message_context,
                    IN const void *data, IN uintn data_size,
                    OUT uint8_t *hmac_value);

/**
  Allocates and initializes one HMAC context for subsequent use, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @return Pointer to the HMAC context that has been initialized.
**/
void *
spdm_hmac_new_with_response_finished_key(
    IN void *spdm_secured_message_context);

/**
  Release the specified HMAC context, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx                   Pointer to the HMAC context to be released.
**/
void spdm_hmac_free_with_response_finished_key(
    IN void *spdm_secured_message_context, IN void *hmac_ctx);

/**
  Set response_finished_key for subsequent use. It must be done before any
  calling to hmac_update().

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx  Pointer to HMAC context.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
**/
boolean spdm_hmac_init_with_response_finished_key(
    IN void *spdm_secured_message_context, OUT void *hmac_ctx);

/**
  Makes a copy of an existing HMAC context, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx     Pointer to HMAC context being copied.
  @param  new_hmac_ctx  Pointer to new HMAC context.

  @retval TRUE   HMAC context copy succeeded.
  @retval FALSE  HMAC context copy failed.
**/
boolean spdm_hmac_duplicate_with_response_finished_key(
    IN void *spdm_secured_message_context,
    IN const void *hmac_ctx, OUT void *new_hmac_ctx);

/**
  Digests the input data and updates HMAC context, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx     Pointer to HMAC context being copied.
  @param  data              Pointer to the buffer containing the data to be digested.
  @param  data_size          size of data buffer in bytes.

  @retval TRUE   HMAC data digest succeeded.
  @retval FALSE  HMAC data digest failed.
**/
boolean spdm_hmac_update_with_response_finished_key(
    IN void *spdm_secured_message_context,
    OUT void *hmac_ctx, IN const void *data,
    IN uintn data_size);

/**
  Completes computation of the HMAC digest value, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx     Pointer to HMAC context being copied.
  @param  hmac_value          Pointer to a buffer that receives the HMAC digest value

  @retval TRUE   HMAC data digest succeeded.
  @retval FALSE  HMAC data digest failed.
**/
boolean spdm_hmac_final_with_response_finished_key(
    IN void *spdm_secured_message_context,
    OUT void *hmac_ctx,  OUT uint8_t *hmac_value);

/**
  Computes the HMAC of a input data buffer, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  data                         Pointer to the buffer containing the data to be HMACed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
boolean spdm_hmac_all_with_response_finished_key(
    IN void *spdm_secured_message_context, IN const void *data,
    IN uintn data_size, OUT uint8_t *hmac_value);

/**
  This function concatenates binary data, which is used as info in HKDF expand later.

  @param  label                        An ascii string label for the spdm_bin_concat.
  @param  label_size                    The size in bytes of the ASCII string label, not including NULL terminator.
  @param  context                      A pre-defined hash value as the context for the spdm_bin_concat.
  @param  length                       16 bits length for the spdm_bin_concat.
  @param  hash_size                     The size in bytes of the context hash.
  @param  out_bin                       The buffer to store the output binary.
  @param  out_bin_size                   The size in bytes for the out_bin.

  @retval RETURN_SUCCESS               The binary spdm_bin_concat data is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status spdm_bin_concat(IN char8 *label, IN uintn label_size,
                  IN uint8_t *context, IN uint16_t length,
                  IN uintn hash_size, OUT uint8_t *out_bin,
                  IN OUT uintn *out_bin_size);

/**
  This function generates SPDM HandshakeKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  th1_hash_data                  th1 hash

  @retval RETURN_SUCCESS  SPDM HandshakeKey for a session is generated.
**/
return_status
spdm_generate_session_handshake_key(IN void *spdm_secured_message_context,
                    IN uint8_t *th1_hash_data);

/**
  This function generates SPDM DataKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  th2_hash_data                  th2 hash

  @retval RETURN_SUCCESS  SPDM DataKey for a session is generated.
**/
return_status
spdm_generate_session_data_key(IN void *spdm_secured_message_context,
                   IN uint8_t *th2_hash_data);

typedef enum {
    SPDM_KEY_UPDATE_ACTION_REQUESTER,
    SPDM_KEY_UPDATE_ACTION_RESPONDER,
    SPDM_KEY_UPDATE_ACTION_MAX,
} spdm_key_update_action_t;

/**
  This function creates the updates of SPDM DataKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  action                       Indicate of the key update action.

  @retval RETURN_SUCCESS  SPDM DataKey update is created.
**/
return_status
spdm_create_update_session_data_key(IN void *spdm_secured_message_context,
                    IN spdm_key_update_action_t action);

/**
  This function activates the update of SPDM DataKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  action                       Indicate of the key update action.
  @param  use_new_key                    Indicate if the new key should be used.

  @retval RETURN_SUCCESS  SPDM DataKey update is activated.
**/
return_status
spdm_activate_update_session_data_key(IN void *spdm_secured_message_context,
                      IN spdm_key_update_action_t action,
                      IN boolean use_new_key);

/**
  Get sequence number in an SPDM secure message.

  This value is transport layer specific.

  @param sequence_number        The current sequence number used to encode or decode message.
  @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
                               The size in byte of the output buffer shall be 8.

  @return size in byte of the sequence_number_buffer.
          It shall be no greater than 8.
          0 means no sequence number is required.
**/
typedef uint8_t (*spdm_secured_message_get_sequence_number_func)(
    IN uint64_t sequence_number, IN OUT uint8_t *sequence_number_buffer);

/**
  Return max random number count in an SPDM secure message.

  This value is transport layer specific.

  @return Max random number count in an SPDM secured message.
          0 means no randum number is required.
**/
typedef uint32_t (*spdm_secured_message_get_max_random_number_count_func)(void);

#define SPDM_SECURED_MESSAGE_CALLBACKS_VERSION 1

typedef struct {
    uint32_t version;
    spdm_secured_message_get_sequence_number_func get_sequence_number;
    spdm_secured_message_get_max_random_number_count_func
        get_max_random_number_count;
} spdm_secured_message_callbacks_t;

typedef struct {
    uint8_t error_code;
    uint32_t session_id;
} spdm_error_struct_t;

/**
  Encode an application message to a secured message.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  session_id                    The session ID of the SPDM session.
  @param  is_requester                  Indicates if it is a requester message.
  @param  app_message_size               size in bytes of the application message data buffer.
  @param  app_message                   A pointer to a source buffer to store the application message.
  @param  secured_message_size           size in bytes of the secured message data buffer.
  @param  secured_message               A pointer to a destination buffer to store the secured message.
  @param  spdm_secured_message_callbacks_t  A pointer to a secured message callback functions structure.

  @retval RETURN_SUCCESS               The application message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status spdm_encode_secured_message(
    IN void *spdm_secured_message_context, IN uint32_t session_id,
    IN boolean is_requester, IN uintn app_message_size,
    IN void *app_message, IN OUT uintn *secured_message_size,
    OUT void *secured_message,
    IN spdm_secured_message_callbacks_t *spdm_secured_message_callbacks_t);

/**
  Decode an application message from a secured message.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  session_id                    The session ID of the SPDM session.
  @param  is_requester                  Indicates if it is a requester message.
  @param  secured_message_size           size in bytes of the secured message data buffer.
  @param  secured_message               A pointer to a source buffer to store the secured message.
  @param  app_message_size               size in bytes of the application message data buffer.
  @param  app_message                   A pointer to a destination buffer to store the application message.
  @param  spdm_secured_message_callbacks_t  A pointer to a secured message callback functions structure.

  @retval RETURN_SUCCESS               The application message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
  @retval RETURN_UNSUPPORTED           The secured_message is unsupported.
**/
return_status spdm_decode_secured_message(
    IN void *spdm_secured_message_context, IN uint32_t session_id,
    IN boolean is_requester, IN uintn secured_message_size,
    IN void *secured_message, IN OUT uintn *app_message_size,
    OUT void *app_message,
    IN spdm_secured_message_callbacks_t *spdm_secured_message_callbacks_t);

/**
  Get the last SPDM error struct of an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  last_spdm_error                Last SPDM error struct of an SPDM secured message context.
*/
void spdm_secured_message_get_last_spdm_error_struct(
    IN void *spdm_secured_message_context,
    OUT spdm_error_struct_t *last_spdm_error);

/**
  Set the last SPDM error struct of an SPDM secured message context.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  last_spdm_error                Last SPDM error struct of an SPDM secured message context.
*/
void spdm_secured_message_set_last_spdm_error_struct(
    IN void *spdm_secured_message_context,
    IN spdm_error_struct_t *last_spdm_error);

#endif