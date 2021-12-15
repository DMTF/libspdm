/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_secured_message_lib.h"

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_zero_filled_buffer[64];

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex_str(IN uint8_t *data, IN uintn size);

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_data(IN uint8_t *data, IN uintn size);

/**
  This function dump raw data with colume format.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex(IN uint8_t *data, IN uintn size);

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
                  IN OUT uintn *out_bin_size)
{
    uintn final_size;

    final_size = sizeof(uint16_t) + sizeof(BIN_CONCAT_LABEL) - 1 + label_size;
    if (context != NULL) {
        final_size += hash_size;
    }
    if (*out_bin_size < final_size) {
        *out_bin_size = final_size;
        return RETURN_BUFFER_TOO_SMALL;
    }

    *out_bin_size = final_size;

    copy_mem(out_bin, &length, sizeof(uint16_t));
    copy_mem(out_bin + sizeof(uint16_t), BIN_CONCAT_LABEL,
         sizeof(BIN_CONCAT_LABEL) - 1);
    copy_mem(out_bin + sizeof(uint16_t) + sizeof(BIN_CONCAT_LABEL) - 1, label,
         label_size);
    if (context != NULL) {
        copy_mem(out_bin + sizeof(uint16_t) + sizeof(BIN_CONCAT_LABEL) -
                 1 + label_size,
             context, hash_size);
    }

    return RETURN_SUCCESS;
}

/**
  This function generates SPDM AEAD key and IV for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  major_secret                  The major secret.
  @param  key                          The buffer to store the AEAD key.
  @param  iv                           The buffer to store the AEAD IV.

  @retval RETURN_SUCCESS  SPDM AEAD key and IV for a session is generated.
**/
return_status spdm_generate_aead_key_and_iv(
    IN spdm_secured_message_context_t *secured_message_context,
    IN uint8_t *major_secret, OUT uint8_t *key, OUT uint8_t *iv)
{
    return_status status;
    boolean ret_val;
    uintn hash_size;
    uintn key_length;
    uintn iv_length;
    uint8_t bin_str5[128];
    uintn bin_str5_size;
    uint8_t bin_str6[128];
    uintn bin_str6_size;

    hash_size = secured_message_context->hash_size;
    key_length = secured_message_context->aead_key_size;
    iv_length = secured_message_context->aead_iv_size;

    bin_str5_size = sizeof(bin_str5);
    status = spdm_bin_concat(BIN_STR_5_LABEL, sizeof(BIN_STR_5_LABEL) - 1,
                 NULL, (uint16_t)key_length, hash_size, bin_str5,
                 &bin_str5_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str5 (0x%x):\n", bin_str5_size));
    internal_dump_hex(bin_str5, bin_str5_size);
    ret_val = spdm_hkdf_expand(secured_message_context->base_hash_algo,
                   major_secret, hash_size, bin_str5,
                   bin_str5_size, key, key_length);
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "key (0x%x) - ", key_length));
    internal_dump_data(key, key_length);
    DEBUG((DEBUG_INFO, "\n"));

    bin_str6_size = sizeof(bin_str6);
    status = spdm_bin_concat(BIN_STR_6_LABEL, sizeof(BIN_STR_6_LABEL) - 1,
                 NULL, (uint16_t)iv_length, hash_size, bin_str6,
                 &bin_str6_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str6 (0x%x):\n", bin_str6_size));
    internal_dump_hex(bin_str6, bin_str6_size);
    ret_val = spdm_hkdf_expand(secured_message_context->base_hash_algo,
                   major_secret, hash_size, bin_str6,
                   bin_str6_size, iv, iv_length);
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "iv (0x%x) - ", iv_length));
    internal_dump_data(iv, iv_length);
    DEBUG((DEBUG_INFO, "\n"));

    return RETURN_SUCCESS;
}

/**
  This function generates SPDM finished_key for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  handshake_secret              The handshake secret.
  @param  finished_key                  The buffer to store the finished key.

  @retval RETURN_SUCCESS  SPDM finished_key for a session is generated.
**/
return_status spdm_generate_finished_key(
    IN spdm_secured_message_context_t *secured_message_context,
    IN uint8_t *handshake_secret, OUT uint8_t *finished_key)
{
    return_status status;
    boolean ret_val;
    uintn hash_size;
    uint8_t bin_str7[128];
    uintn bin_str7_size;

    hash_size = secured_message_context->hash_size;

    bin_str7_size = sizeof(bin_str7);
    status = spdm_bin_concat(BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1,
                 NULL, (uint16_t)hash_size, hash_size, bin_str7,
                 &bin_str7_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str7 (0x%x):\n", bin_str7_size));
    internal_dump_hex(bin_str7, bin_str7_size);
    ret_val = spdm_hkdf_expand(secured_message_context->base_hash_algo,
                   handshake_secret, hash_size, bin_str7,
                   bin_str7_size, finished_key, hash_size);
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "finished_key (0x%x) - ", hash_size));
    internal_dump_data(finished_key, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    return RETURN_SUCCESS;
}

/**
  This function generates SPDM HandshakeKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  th1_hash_data                  th1 hash

  @retval RETURN_SUCCESS  SPDM HandshakeKey for a session is generated.
**/
return_status
spdm_generate_session_handshake_key(IN void *spdm_secured_message_context,
                    IN uint8_t *th1_hash_data)
{
    return_status status;
    boolean ret_val;
    uintn hash_size;
    uint8_t bin_str0[128];
    uintn bin_str0_size;
    uint8_t bin_str1[128];
    uintn bin_str1_size;
    uint8_t bin_str2[128];
    uintn bin_str2_size;
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;

    hash_size = secured_message_context->hash_size;

    bin_str0_size = sizeof(bin_str0);
    status = spdm_bin_concat(BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1,
                 NULL, (uint16_t)hash_size, hash_size, bin_str0,
                 &bin_str0_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str0 (0x%x):\n", bin_str0_size));
    internal_dump_hex(bin_str0, bin_str0_size);

    if (secured_message_context->use_psk) {
        // No handshake_secret generation for PSK.
    } else {
        DEBUG((DEBUG_INFO, "[DHE Secret]: "));
        internal_dump_hex_str(
            secured_message_context->master_secret.dhe_secret,
            secured_message_context->dhe_key_size);
        DEBUG((DEBUG_INFO, "\n"));
        ret_val = spdm_hmac_all(
            secured_message_context->base_hash_algo,
            m_zero_filled_buffer, hash_size,
            secured_message_context->master_secret.dhe_secret,
            secured_message_context->dhe_key_size,
            secured_message_context->master_secret.handshake_secret);
        ASSERT(ret_val);
        DEBUG((DEBUG_INFO, "handshake_secret (0x%x) - ", hash_size));
        internal_dump_data(
            secured_message_context->master_secret.handshake_secret,
            hash_size);
        DEBUG((DEBUG_INFO, "\n"));
    }

    bin_str1_size = sizeof(bin_str1);
    status = spdm_bin_concat(BIN_STR_1_LABEL, sizeof(BIN_STR_1_LABEL) - 1,
                 th1_hash_data, (uint16_t)hash_size, hash_size,
                 bin_str1, &bin_str1_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str1 (0x%x):\n", bin_str1_size));
    internal_dump_hex(bin_str1, bin_str1_size);
    if (secured_message_context->use_psk) {
        ret_val = spdm_psk_handshake_secret_hkdf_expand(
            secured_message_context->version,
            secured_message_context->base_hash_algo,
            secured_message_context->psk_hint,
            secured_message_context->psk_hint_size, bin_str1,
            bin_str1_size,
            secured_message_context->handshake_secret
                .request_handshake_secret,
            hash_size);
        if (!ret_val) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->master_secret.handshake_secret,
            hash_size, bin_str1, bin_str1_size,
            secured_message_context->handshake_secret
                .request_handshake_secret,
            hash_size);
    }
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "request_handshake_secret (0x%x) - ", hash_size));
    internal_dump_data(secured_message_context->handshake_secret
                   .request_handshake_secret,
               hash_size);
    DEBUG((DEBUG_INFO, "\n"));
    bin_str2_size = sizeof(bin_str2);
    status = spdm_bin_concat(BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1,
                 th1_hash_data, (uint16_t)hash_size, hash_size,
                 bin_str2, &bin_str2_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str2 (0x%x):\n", bin_str2_size));
    internal_dump_hex(bin_str2, bin_str2_size);
    if (secured_message_context->use_psk) {
        ret_val = spdm_psk_handshake_secret_hkdf_expand(
            secured_message_context->version,
            secured_message_context->base_hash_algo,
            secured_message_context->psk_hint,
            secured_message_context->psk_hint_size, bin_str2,
            bin_str2_size,
            secured_message_context->handshake_secret
                .response_handshake_secret,
            hash_size);
        if (!ret_val) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->master_secret.handshake_secret,
            hash_size, bin_str2, bin_str2_size,
            secured_message_context->handshake_secret
                .response_handshake_secret,
            hash_size);
    }
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "response_handshake_secret (0x%x) - ", hash_size));
    internal_dump_data(secured_message_context->handshake_secret
                   .response_handshake_secret,
               hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    status = spdm_generate_finished_key(
        secured_message_context,
        secured_message_context->handshake_secret
            .request_handshake_secret,
        secured_message_context->handshake_secret.request_finished_key);
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = spdm_generate_finished_key(
        secured_message_context,
        secured_message_context->handshake_secret
            .response_handshake_secret,
        secured_message_context->handshake_secret.response_finished_key);
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = spdm_generate_aead_key_and_iv(secured_message_context,
                      secured_message_context->handshake_secret
                          .request_handshake_secret,
                      secured_message_context->handshake_secret
                          .request_handshake_encryption_key,
                      secured_message_context->handshake_secret
                          .request_handshake_salt);
    if (RETURN_ERROR(status)) {
        return status;
    }
    secured_message_context->handshake_secret
        .request_handshake_sequence_number = 0;

    status = spdm_generate_aead_key_and_iv(
        secured_message_context,
        secured_message_context->handshake_secret
            .response_handshake_secret,
        secured_message_context->handshake_secret
            .response_handshake_encryption_key,
        secured_message_context->handshake_secret
            .response_handshake_salt);
    if (RETURN_ERROR(status)) {
        return status;
    }
    secured_message_context->handshake_secret
        .response_handshake_sequence_number = 0;

    zero_mem(secured_message_context->master_secret.dhe_secret,
        MAX_DHE_KEY_SIZE);
   
    secured_message_context->finished_key_ready = TRUE;
    return RETURN_SUCCESS;
}

/**
  This function generates SPDM DataKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  th2_hash_data                  th2 hash

  @retval RETURN_SUCCESS  SPDM DataKey for a session is generated.
**/
return_status
spdm_generate_session_data_key(IN void *spdm_secured_message_context,
                   IN uint8_t *th2_hash_data)
{
    return_status status;
    boolean ret_val;
    uintn hash_size;
    uint8_t salt1[64];
    uint8_t bin_str0[128];
    uintn bin_str0_size;
    uint8_t bin_str3[128];
    uintn bin_str3_size;
    uint8_t bin_str4[128];
    uintn bin_str4_size;
    uint8_t bin_str8[128];
    uintn bin_str8_size;
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;

    hash_size = secured_message_context->hash_size;

    if (secured_message_context->use_psk) {
        // No master_secret generation for PSK.
    } else {
        bin_str0_size = sizeof(bin_str0);
        status = spdm_bin_concat(BIN_STR_0_LABEL,
                     sizeof(BIN_STR_0_LABEL) - 1, NULL,
                     (uint16_t)hash_size, hash_size, bin_str0,
                     &bin_str0_size);
        ASSERT_RETURN_ERROR(status);
        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->master_secret.handshake_secret,
            hash_size, bin_str0, bin_str0_size, salt1, hash_size);
        ASSERT(ret_val);
        DEBUG((DEBUG_INFO, "salt1 (0x%x) - ", hash_size));
        internal_dump_data(salt1, hash_size);
        DEBUG((DEBUG_INFO, "\n"));

        ret_val = spdm_hmac_all(
            secured_message_context->base_hash_algo,
            m_zero_filled_buffer, hash_size, salt1, hash_size,
            secured_message_context->master_secret.master_secret);
        ASSERT(ret_val);
        DEBUG((DEBUG_INFO, "master_secret (0x%x) - ", hash_size));
        internal_dump_data(
            secured_message_context->master_secret.master_secret,
            hash_size);
        DEBUG((DEBUG_INFO, "\n"));
    }

    bin_str3_size = sizeof(bin_str3);
    status = spdm_bin_concat(BIN_STR_3_LABEL, sizeof(BIN_STR_3_LABEL) - 1,
                 th2_hash_data, (uint16_t)hash_size, hash_size,
                 bin_str3, &bin_str3_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str3 (0x%x):\n", bin_str3_size));
    internal_dump_hex(bin_str3, bin_str3_size);
    if (secured_message_context->use_psk) {
        ret_val = spdm_psk_master_secret_hkdf_expand(
            secured_message_context->version,
            secured_message_context->base_hash_algo,
            secured_message_context->psk_hint,
            secured_message_context->psk_hint_size, bin_str3,
            bin_str3_size,
            secured_message_context->application_secret
                .request_data_secret,
            hash_size);
        if (!ret_val) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->master_secret.master_secret,
            hash_size, bin_str3, bin_str3_size,
            secured_message_context->application_secret
                .request_data_secret,
            hash_size);
    }
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "request_data_secret (0x%x) - ", hash_size));
    internal_dump_data(
        secured_message_context->application_secret.request_data_secret,
        hash_size);
    DEBUG((DEBUG_INFO, "\n"));
    bin_str4_size = sizeof(bin_str4);
    status = spdm_bin_concat(BIN_STR_4_LABEL, sizeof(BIN_STR_4_LABEL) - 1,
                 th2_hash_data, (uint16_t)hash_size, hash_size,
                 bin_str4, &bin_str4_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str4 (0x%x):\n", bin_str4_size));
    internal_dump_hex(bin_str4, bin_str4_size);
    if (secured_message_context->use_psk) {
        ret_val = spdm_psk_master_secret_hkdf_expand(
            secured_message_context->version,
            secured_message_context->base_hash_algo,
            secured_message_context->psk_hint,
            secured_message_context->psk_hint_size, bin_str4,
            bin_str4_size,
            secured_message_context->application_secret
                .response_data_secret,
            hash_size);
        if (!ret_val) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->master_secret.master_secret,
            hash_size, bin_str4, bin_str4_size,
            secured_message_context->application_secret
                .response_data_secret,
            hash_size);
    }
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "response_data_secret (0x%x) - ", hash_size));
    internal_dump_data(
        secured_message_context->application_secret.response_data_secret,
        hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    bin_str8_size = sizeof(bin_str8);
    status = spdm_bin_concat(BIN_STR_8_LABEL, sizeof(BIN_STR_8_LABEL) - 1,
                 th2_hash_data, (uint16_t)hash_size, hash_size,
                 bin_str8, &bin_str8_size);
    ASSERT_RETURN_ERROR(status);
    DEBUG((DEBUG_INFO, "bin_str8 (0x%x):\n", bin_str8_size));
    internal_dump_hex(bin_str8, bin_str8_size);
    if (secured_message_context->use_psk) {
        ret_val = spdm_psk_master_secret_hkdf_expand(
            secured_message_context->version,
            secured_message_context->base_hash_algo,
            secured_message_context->psk_hint,
            secured_message_context->psk_hint_size, bin_str8,
            bin_str8_size,
            secured_message_context->handshake_secret
                .export_master_secret,
            hash_size);
        if (!ret_val) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->master_secret.master_secret,
            hash_size, bin_str8, bin_str8_size,
            secured_message_context->handshake_secret
                .export_master_secret,
            hash_size);
    }
    ASSERT(ret_val);
    DEBUG((DEBUG_INFO, "export_master_secret (0x%x) - ", hash_size));
    internal_dump_data(
        secured_message_context->handshake_secret.export_master_secret,
        hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    status = spdm_generate_aead_key_and_iv(
        secured_message_context,
        secured_message_context->application_secret.request_data_secret,
        secured_message_context->application_secret
            .request_data_encryption_key,
        secured_message_context->application_secret.request_data_salt);
    if (RETURN_ERROR(status)) {
        return status;
    }
    secured_message_context->application_secret
        .request_data_sequence_number = 0;

    status = spdm_generate_aead_key_and_iv(
        secured_message_context,
        secured_message_context->application_secret.response_data_secret,
        secured_message_context->application_secret
            .response_data_encryption_key,
        secured_message_context->application_secret.response_data_salt);
    if (RETURN_ERROR(status)) {
        return status;
    }
    secured_message_context->application_secret
        .response_data_sequence_number = 0;

    return RETURN_SUCCESS;
}

/**
  This function creates the updates of SPDM DataKey for a session.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  action                       Indicate of the key update action.

  @retval RETURN_SUCCESS  SPDM DataKey update is created.
**/
return_status
spdm_create_update_session_data_key(IN void *spdm_secured_message_context,
                    IN spdm_key_update_action_t action)
{
    return_status status;
    boolean ret_val;
    uintn hash_size;
    uint8_t bin_str9[128];
    uintn bin_str9_size;
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;

    hash_size = secured_message_context->hash_size;

    bin_str9_size = sizeof(bin_str9);
    status = spdm_bin_concat(BIN_STR_9_LABEL, sizeof(BIN_STR_9_LABEL) - 1,
                 NULL, (uint16_t)hash_size, hash_size, bin_str9,
                 &bin_str9_size);
    ASSERT_RETURN_ERROR(status);
    if (RETURN_ERROR(status)) {
        return status;
    }
    DEBUG((DEBUG_INFO, "bin_str9 (0x%x):\n", bin_str9_size));
    internal_dump_hex(bin_str9, bin_str9_size);

    if ((action & SPDM_KEY_UPDATE_ACTION_REQUESTER) != 0) {
        copy_mem(&secured_message_context->application_secret_backup
                  .request_data_secret,
             &secured_message_context->application_secret
                  .request_data_secret,
             MAX_HASH_SIZE);
        copy_mem(&secured_message_context->application_secret_backup
                  .request_data_encryption_key,
             &secured_message_context->application_secret
                  .request_data_encryption_key,
             MAX_AEAD_KEY_SIZE);
        copy_mem(&secured_message_context->application_secret_backup
                  .request_data_salt,
             &secured_message_context->application_secret
                  .request_data_salt,
             MAX_AEAD_IV_SIZE);
        secured_message_context->application_secret_backup
            .request_data_sequence_number =
            secured_message_context->application_secret
                .request_data_sequence_number;

        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->application_secret
                .request_data_secret,
            hash_size, bin_str9, bin_str9_size,
            secured_message_context->application_secret
                .request_data_secret,
            hash_size);
        ASSERT(ret_val);
        if (!ret_val) {
            return RETURN_DEVICE_ERROR;
        }
        DEBUG((DEBUG_INFO, "RequestDataSecretUpdate (0x%x) - ",
               hash_size));
        internal_dump_data(secured_message_context->application_secret
                       .request_data_secret,
                   hash_size);
        DEBUG((DEBUG_INFO, "\n"));

        status = spdm_generate_aead_key_and_iv(
            secured_message_context,
            secured_message_context->application_secret
                .request_data_secret,
            secured_message_context->application_secret
                .request_data_encryption_key,
            secured_message_context->application_secret
                .request_data_salt);
        if (RETURN_ERROR(status)) {
            return status;
        }
        secured_message_context->application_secret
            .request_data_sequence_number = 0;

        secured_message_context->requester_backup_valid = TRUE;
    }

    if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
        copy_mem(&secured_message_context->application_secret_backup
                  .response_data_secret,
             &secured_message_context->application_secret
                  .response_data_secret,
             MAX_HASH_SIZE);
        copy_mem(&secured_message_context->application_secret_backup
                  .response_data_encryption_key,
             &secured_message_context->application_secret
                  .response_data_encryption_key,
             MAX_AEAD_KEY_SIZE);
        copy_mem(&secured_message_context->application_secret_backup
                  .response_data_salt,
             &secured_message_context->application_secret
                  .response_data_salt,
             MAX_AEAD_IV_SIZE);
        secured_message_context->application_secret_backup
            .response_data_sequence_number =
            secured_message_context->application_secret
                .response_data_sequence_number;

        ret_val = spdm_hkdf_expand(
            secured_message_context->base_hash_algo,
            secured_message_context->application_secret
                .response_data_secret,
            hash_size, bin_str9, bin_str9_size,
            secured_message_context->application_secret
                .response_data_secret,
            hash_size);
        ASSERT(ret_val);
        if (!ret_val) {
            return RETURN_DEVICE_ERROR;
        }
        DEBUG((DEBUG_INFO, "ResponseDataSecretUpdate (0x%x) - ",
               hash_size));
        internal_dump_data(secured_message_context->application_secret
                       .response_data_secret,
                   hash_size);
        DEBUG((DEBUG_INFO, "\n"));

        status = spdm_generate_aead_key_and_iv(
            secured_message_context,
            secured_message_context->application_secret
                .response_data_secret,
            secured_message_context->application_secret
                .response_data_encryption_key,
            secured_message_context->application_secret
                .response_data_salt);
        if (RETURN_ERROR(status)) {
            return status;
        }
        secured_message_context->application_secret
            .response_data_sequence_number = 0;

        secured_message_context->responder_backup_valid = TRUE;
    }
    return RETURN_SUCCESS;
}

/**
  This function used to clear handshake secret.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
**/
void spdm_clear_handshake_secret(IN void *spdm_secured_message_context)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;

    zero_mem(secured_message_context->master_secret.handshake_secret,
            MAX_HASH_SIZE);
    zero_mem(&(secured_message_context->handshake_secret),
            sizeof(spdm_session_info_struct_handshake_secret_t));

    secured_message_context->requester_backup_valid = FALSE;
    secured_message_context->responder_backup_valid = FALSE;
}

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
                      IN boolean use_new_key)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;

    if (!use_new_key) {
        if (((action & SPDM_KEY_UPDATE_ACTION_REQUESTER) != 0) &&
            secured_message_context->requester_backup_valid) {
            copy_mem(&secured_message_context->application_secret
                      .request_data_secret,
                 &secured_message_context
                      ->application_secret_backup
                      .request_data_secret,
                 MAX_HASH_SIZE);
            copy_mem(&secured_message_context->application_secret
                      .request_data_encryption_key,
                 &secured_message_context
                      ->application_secret_backup
                      .request_data_encryption_key,
                 MAX_AEAD_KEY_SIZE);
            copy_mem(&secured_message_context->application_secret
                      .request_data_salt,
                 &secured_message_context
                      ->application_secret_backup
                      .request_data_salt,
                 MAX_AEAD_IV_SIZE);
            secured_message_context->application_secret
                .request_data_sequence_number =
                secured_message_context
                    ->application_secret_backup
                    .request_data_sequence_number;
        }
        if (((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) &&
            secured_message_context->responder_backup_valid) {
            copy_mem(&secured_message_context->application_secret
                      .response_data_secret,
                 &secured_message_context
                      ->application_secret_backup
                      .response_data_secret,
                 MAX_HASH_SIZE);
            copy_mem(&secured_message_context->application_secret
                      .response_data_encryption_key,
                 &secured_message_context
                      ->application_secret_backup
                      .response_data_encryption_key,
                 MAX_AEAD_KEY_SIZE);
            copy_mem(&secured_message_context->application_secret
                      .response_data_salt,
                 &secured_message_context
                      ->application_secret_backup
                      .response_data_salt,
                 MAX_AEAD_IV_SIZE);
            secured_message_context->application_secret
                .response_data_sequence_number =
                secured_message_context
                    ->application_secret_backup
                    .response_data_sequence_number;
        }
    }

    if ((action & SPDM_KEY_UPDATE_ACTION_REQUESTER) != 0) {
        zero_mem(&secured_message_context->application_secret_backup
                  .request_data_secret,
             MAX_HASH_SIZE);
        zero_mem(&secured_message_context->application_secret_backup
                  .request_data_encryption_key,
             MAX_AEAD_KEY_SIZE);
        zero_mem(&secured_message_context->application_secret_backup
                  .request_data_salt,
             MAX_AEAD_IV_SIZE);
        secured_message_context->application_secret_backup
            .request_data_sequence_number = 0;
        secured_message_context->requester_backup_valid = FALSE;
    }
    if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
        zero_mem(&secured_message_context->application_secret_backup
                  .response_data_secret,
             MAX_HASH_SIZE);
        zero_mem(&secured_message_context->application_secret_backup
                  .response_data_encryption_key,
             MAX_AEAD_KEY_SIZE);
        zero_mem(&secured_message_context->application_secret_backup
                  .response_data_salt,
             MAX_AEAD_IV_SIZE);
        secured_message_context->application_secret_backup
            .response_data_sequence_number = 0;
        secured_message_context->responder_backup_valid = FALSE;
    }
    return RETURN_SUCCESS;
}

/**
  Allocates and initializes one HMAC context for subsequent use, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @return Pointer to the HMAC context that has been initialized.
**/
void *
spdm_hmac_new_with_request_finished_key(
    IN void *spdm_secured_message_context)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_new(secured_message_context->base_hash_algo);
}

/**
  Release the specified HMAC context, with request_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx                   Pointer to the HMAC context to be released.
**/
void spdm_hmac_free_with_request_finished_key(
    IN void *spdm_secured_message_context, IN void *hmac_ctx)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    spdm_hmac_free(secured_message_context->base_hash_algo, hmac_ctx);
}

/**
  Set request_finished_key for subsequent use. It must be done before any
  calling to hmac_update().

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx  Pointer to HMAC context.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
**/
boolean spdm_hmac_init_with_request_finished_key(
    IN void *spdm_secured_message_context, OUT void *hmac_ctx)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_init(
        secured_message_context->base_hash_algo, hmac_ctx,
        secured_message_context->handshake_secret.request_finished_key,
        secured_message_context->hash_size);
}

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
    IN const void *hmac_ctx, OUT void *new_hmac_ctx)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_duplicate(
        secured_message_context->base_hash_algo, hmac_ctx,
        new_hmac_ctx);
}

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
    IN uintn data_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_update(
        secured_message_context->base_hash_algo, hmac_ctx,
        data, data_size);
}

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
    OUT void *hmac_ctx,  OUT uint8_t *hmac_value)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_final(
        secured_message_context->base_hash_algo, hmac_ctx,
        hmac_value);
}

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
                    OUT uint8_t *hmac_value)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_all(
        secured_message_context->base_hash_algo, data, data_size,
        secured_message_context->handshake_secret.request_finished_key,
        secured_message_context->hash_size, hmac_value);
}

/**
  Allocates and initializes one HMAC context for subsequent use, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @return Pointer to the HMAC context that has been initialized.
**/
void *
spdm_hmac_new_with_response_finished_key(
    IN void *spdm_secured_message_context)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_new(secured_message_context->base_hash_algo);
}

/**
  Release the specified HMAC context, with response_finished_key.

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx                   Pointer to the HMAC context to be released.
**/
void spdm_hmac_free_with_response_finished_key(
    IN void *spdm_secured_message_context, IN void *hmac_ctx)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    spdm_hmac_free(secured_message_context->base_hash_algo, hmac_ctx);
}

/**
  Set response_finished_key for subsequent use. It must be done before any
  calling to hmac_update().

  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
  @param  hmac_ctx  Pointer to HMAC context.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
**/
boolean spdm_hmac_init_with_response_finished_key(
    IN void *spdm_secured_message_context, OUT void *hmac_ctx)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_init(
        secured_message_context->base_hash_algo, hmac_ctx,
        secured_message_context->handshake_secret.response_finished_key,
        secured_message_context->hash_size);
}

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
    IN const void *hmac_ctx, OUT void *new_hmac_ctx)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_duplicate(
        secured_message_context->base_hash_algo, hmac_ctx,
        new_hmac_ctx);
}

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
    IN uintn data_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_update(
        secured_message_context->base_hash_algo, hmac_ctx,
        data, data_size);
}

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
    OUT void *hmac_ctx,  OUT uint8_t *hmac_value)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_final(
        secured_message_context->base_hash_algo, hmac_ctx,
        hmac_value);
}

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
    IN uintn data_size, OUT uint8_t *hmac_value)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return spdm_hmac_all(
        secured_message_context->base_hash_algo, data, data_size,
        secured_message_context->handshake_secret.response_finished_key,
        secured_message_context->hash_size, hmac_value);
}
