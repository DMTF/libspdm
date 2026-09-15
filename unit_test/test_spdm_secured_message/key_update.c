/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_AEAD_AES_256_GCM_SUPPORT

static libspdm_secured_message_context_t m_secured_message_context;

#define OLD_SECRET_BYTE 0xAA
#define OLD_KEY_BYTE    0xBB
#define OLD_SALT_BYTE   0xCC
#define OLD_SEQ_NUMBER  0x42

/* An okm_len above 255 * hash_size is rejected by HKDF-Expand per RFC 5869
 * Section 2.3. The check is on the requested length alone, so the derivation
 * fails before anything is written to the output buffer. */
#define OVERSIZED_AEAD_KEY_SIZE (255 * LIBSPDM_SHA256_DIGEST_SIZE + 1)

static void initialize_key_update_context(libspdm_key_update_action_t action)
{
    libspdm_zero_mem(&m_secured_message_context, sizeof(m_secured_message_context));

    m_secured_message_context.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    m_secured_message_context.version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    m_secured_message_context.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    m_secured_message_context.aead_cipher_suite = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    m_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_ENC_MAC;
    m_secured_message_context.session_state = LIBSPDM_SESSION_STATE_ESTABLISHED;
    m_secured_message_context.hash_size = LIBSPDM_SHA256_DIGEST_SIZE;
    m_secured_message_context.aead_key_size = 32;
    m_secured_message_context.aead_iv_size = 12;

    /* Populate the live keys with a recognizable pattern so a successful
     * rollback can be distinguished from a partially-updated state. */
    if (action == LIBSPDM_KEY_UPDATE_ACTION_REQUESTER) {
        libspdm_set_mem(m_secured_message_context.application_secret.request_data_secret,
                        LIBSPDM_SHA256_DIGEST_SIZE, OLD_SECRET_BYTE);
        libspdm_set_mem(m_secured_message_context.application_secret.request_data_encryption_key,
                        m_secured_message_context.aead_key_size, OLD_KEY_BYTE);
        libspdm_set_mem(m_secured_message_context.application_secret.request_data_salt,
                        m_secured_message_context.aead_iv_size, OLD_SALT_BYTE);
        m_secured_message_context.application_secret.request_data_sequence_number =
            OLD_SEQ_NUMBER;
    } else {
        libspdm_set_mem(m_secured_message_context.application_secret.response_data_secret,
                        LIBSPDM_SHA256_DIGEST_SIZE, OLD_SECRET_BYTE);
        libspdm_set_mem(m_secured_message_context.application_secret.response_data_encryption_key,
                        m_secured_message_context.aead_key_size, OLD_KEY_BYTE);
        libspdm_set_mem(m_secured_message_context.application_secret.response_data_salt,
                        m_secured_message_context.aead_iv_size, OLD_SALT_BYTE);
        m_secured_message_context.application_secret.response_data_sequence_number =
            OLD_SEQ_NUMBER;
    }
}

/**
 * Assert that the live keys for the given direction still hold the pre-update
 * pattern, i.e. that a rollback fully restored them.
 **/
static void assert_old_keys_restored(libspdm_key_update_action_t action)
{
    const libspdm_session_info_struct_application_secret_t *secret =
        &m_secured_message_context.application_secret;
    const uint8_t *data_secret;
    const uint8_t *encryption_key;
    const uint8_t *salt;
    uint64_t sequence_number;
    size_t index;

    if (action == LIBSPDM_KEY_UPDATE_ACTION_REQUESTER) {
        data_secret = secret->request_data_secret;
        encryption_key = secret->request_data_encryption_key;
        salt = secret->request_data_salt;
        sequence_number = secret->request_data_sequence_number;
    } else {
        data_secret = secret->response_data_secret;
        encryption_key = secret->response_data_encryption_key;
        salt = secret->response_data_salt;
        sequence_number = secret->response_data_sequence_number;
    }

    for (index = 0; index < LIBSPDM_SHA256_DIGEST_SIZE; index++) {
        assert_int_equal(data_secret[index], OLD_SECRET_BYTE);
    }
    for (index = 0; index < 32; index++) {
        assert_int_equal(encryption_key[index], OLD_KEY_BYTE);
    }
    for (index = 0; index < 12; index++) {
        assert_int_equal(salt[index], OLD_SALT_BYTE);
    }
    assert_int_equal(sequence_number, OLD_SEQ_NUMBER);
}

/**
 * Test 1: A failure while deriving the new Requester keys leaves the backup
 * recoverable, so a rollback restores the original keys.
 *
 * libspdm_create_update_session_data_key() snapshots the old keys into the
 * backup slot and then derives the new ones. If a derivation fails after the
 * snapshot was taken, the backup must already be marked valid, otherwise
 * libspdm_activate_update_session_data_key(..., use_new_key = false) has
 * nothing to roll back to and the old keys are lost for good.
 **/
static void libspdm_test_key_update_rollback_after_derive_failure_case1(void **state)
{
    bool result;

    initialize_key_update_context(LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

    /* Force the AEAD key derivation, which runs after the data-secret update,
     * to fail. The data-secret update itself is sized by hash_size and still
     * succeeds, so this reproduces a failure part-way through the update. */
    m_secured_message_context.aead_key_size = OVERSIZED_AEAD_KEY_SIZE;

    result = libspdm_create_update_session_data_key(&m_secured_message_context,
                                                    LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
    assert_false(result);

    /* The backup holds a complete snapshot of the old keys and must be usable. */
    assert_true(m_secured_message_context.requester_backup_valid);

    /* Restore aead_key_size so the rollback copies the real key length. */
    m_secured_message_context.aead_key_size = 32;

    result = libspdm_activate_update_session_data_key(&m_secured_message_context,
                                                      LIBSPDM_KEY_UPDATE_ACTION_REQUESTER,
                                                      false);
    assert_true(result);

    assert_old_keys_restored(LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

    /* The backup is consumed by the rollback. */
    assert_false(m_secured_message_context.requester_backup_valid);
}

/**
 * Test 2: The same property for the Responder direction.
 **/
static void libspdm_test_key_update_rollback_after_derive_failure_case2(void **state)
{
    bool result;

    initialize_key_update_context(LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);

    m_secured_message_context.aead_key_size = OVERSIZED_AEAD_KEY_SIZE;

    result = libspdm_create_update_session_data_key(&m_secured_message_context,
                                                    LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
    assert_false(result);

    assert_true(m_secured_message_context.responder_backup_valid);

    m_secured_message_context.aead_key_size = 32;

    result = libspdm_activate_update_session_data_key(&m_secured_message_context,
                                                      LIBSPDM_KEY_UPDATE_ACTION_RESPONDER,
                                                      false);
    assert_true(result);

    assert_old_keys_restored(LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);

    assert_false(m_secured_message_context.responder_backup_valid);
}

/**
 * Test 3: A successful key update still marks the backup valid and commits the
 * new keys, so the fix does not regress the success path.
 **/
static void libspdm_test_key_update_success_path_case3(void **state)
{
    bool result;

    initialize_key_update_context(LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

    result = libspdm_create_update_session_data_key(&m_secured_message_context,
                                                    LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
    assert_true(result);
    assert_true(m_secured_message_context.requester_backup_valid);

    /* The live secret has been replaced by the derived one. */
    assert_memory_not_equal(m_secured_message_context.application_secret.request_data_secret,
                            m_secured_message_context.application_secret_backup
                            .request_data_secret,
                            LIBSPDM_SHA256_DIGEST_SIZE);
    assert_int_equal(m_secured_message_context.application_secret.request_data_sequence_number, 0);

    /* Committing the new keys discards the backup. */
    result = libspdm_activate_update_session_data_key(&m_secured_message_context,
                                                      LIBSPDM_KEY_UPDATE_ACTION_REQUESTER,
                                                      true);
    assert_true(result);
    assert_false(m_secured_message_context.requester_backup_valid);
}

int libspdm_secured_message_key_update_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Requester: rollback works after a mid-update derivation failure */
        cmocka_unit_test(libspdm_test_key_update_rollback_after_derive_failure_case1),
        /* Responder: rollback works after a mid-update derivation failure */
        cmocka_unit_test(libspdm_test_key_update_rollback_after_derive_failure_case2),
        /* Success path is unaffected */
        cmocka_unit_test(libspdm_test_key_update_success_path_case3),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}

#endif /* LIBSPDM_AEAD_AES_256_GCM_SUPPORT */
