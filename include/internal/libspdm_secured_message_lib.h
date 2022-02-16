/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_SECURED_MESSAGE_LIB_INTERNAL_H__
#define __SPDM_SECURED_MESSAGE_LIB_INTERNAL_H__

#include "library/spdm_secured_message_lib.h"

typedef struct {
    uint8_t dhe_secret[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t master_secret[LIBSPDM_MAX_HASH_SIZE];
} spdm_session_info_struct_master_secret_t;

typedef struct {
    uint8_t request_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t export_master_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_handshake_encryption_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
    uint8_t request_handshake_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
    uint64_t request_handshake_sequence_number;
    uint8_t response_handshake_encryption_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
    uint8_t response_handshake_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
    uint64_t response_handshake_sequence_number;
} spdm_session_info_struct_handshake_secret_t;

typedef struct {
    uint8_t request_data_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t response_data_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_data_encryption_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
    uint8_t request_data_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
    uint64_t request_data_sequence_number;
    uint8_t response_data_encryption_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
    uint8_t response_data_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
    uint64_t response_data_sequence_number;
} spdm_session_info_struct_application_secret_t;

typedef struct {
    libspdm_session_type_t session_type;
    spdm_version_number_t version;
    spdm_version_number_t secured_message_version;
    uint32_t base_hash_algo;
    uint16_t dhe_named_group;
    uint16_t aead_cipher_suite;
    uint16_t key_schedule;
    uintn hash_size;
    uintn dhe_key_size;
    uintn aead_key_size;
    uintn aead_iv_size;
    uintn aead_tag_size;
    bool use_psk;
    bool finished_key_ready;
    libspdm_session_state_t session_state;
    spdm_session_info_struct_master_secret_t master_secret;
    spdm_session_info_struct_handshake_secret_t handshake_secret;
    spdm_session_info_struct_application_secret_t application_secret;
    spdm_session_info_struct_application_secret_t application_secret_backup;
    bool requester_backup_valid;
    bool responder_backup_valid;
    uintn psk_hint_size;
    const void *psk_hint;

    /* Cache the error in libspdm_decode_secured_message. It is handled in libspdm_build_response.*/

    libspdm_error_struct_t last_spdm_error;
} spdm_secured_message_context_t;

#endif
