/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"

/* The largest sizes that the context's arrays hold in this configuration. */
#define AEAD_KEY_SIZE LIBSPDM_MAX_AEAD_KEY_SIZE
#define AEAD_IV_SIZE LIBSPDM_MAX_AEAD_IV_SIZE
#define SESSION_KEYS_SIZE (sizeof(libspdm_secure_session_keys_struct_t) + \
                           (AEAD_KEY_SIZE + AEAD_IV_SIZE + sizeof(uint64_t)) * 2)

static libspdm_secured_message_context_t m_secured_message_context;
static libspdm_secured_message_context_t m_peer_secured_message_context;

/* Sets the AEAD sizes, and application data keys, salts and sequence numbers derived from seed. */
static void set_application_secret(libspdm_secured_message_context_t *secured_message_context,
                                   uint8_t seed)
{
    uint8_t index;

    libspdm_zero_mem(secured_message_context, sizeof(*secured_message_context));
    secured_message_context->aead_key_size = AEAD_KEY_SIZE;
    secured_message_context->aead_iv_size = AEAD_IV_SIZE;
    for (index = 0; index < AEAD_KEY_SIZE; index++) {
        secured_message_context->application_secret.request_data_encryption_key[index] =
            (uint8_t)(seed + index);
        secured_message_context->application_secret.response_data_encryption_key[index] =
            (uint8_t)(seed + 0x40 + index);
    }
    for (index = 0; index < AEAD_IV_SIZE; index++) {
        secured_message_context->application_secret.request_data_salt[index] =
            (uint8_t)(seed + 0x80 + index);
        secured_message_context->application_secret.response_data_salt[index] =
            (uint8_t)(seed + 0xC0 + index);
    }
    secured_message_context->application_secret.request_data_sequence_number = seed + 1;
    secured_message_context->application_secret.response_data_sequence_number = seed + 2;
}

/**
 * Test 1: Export the session keys of one secured message context and import them into another.
 * Expected Behavior: both calls succeed, and the importing context holds the exporting context's
 * application data keys, salts and sequence numbers.
 **/
static void libspdm_test_secured_message_context_data_case1(void **state)
{
    uint8_t session_keys[SESSION_KEYS_SIZE];
    size_t session_keys_size;
    libspdm_session_info_struct_application_secret_t *exported;
    libspdm_session_info_struct_application_secret_t *imported;

    set_application_secret(&m_secured_message_context, 0x01);
    set_application_secret(&m_peer_secured_message_context, 0x20);

    session_keys_size = sizeof(session_keys);
    assert_true(libspdm_secured_message_export_session_keys(&m_secured_message_context,
                                                            session_keys, &session_keys_size));
    assert_int_equal(session_keys_size, sizeof(session_keys));

    assert_true(libspdm_secured_message_import_session_keys(&m_peer_secured_message_context,
                                                            session_keys, session_keys_size));

    exported = &m_secured_message_context.application_secret;
    imported = &m_peer_secured_message_context.application_secret;
    assert_memory_equal(imported->request_data_encryption_key,
                        exported->request_data_encryption_key, AEAD_KEY_SIZE);
    assert_memory_equal(imported->request_data_salt, exported->request_data_salt, AEAD_IV_SIZE);
    assert_int_equal(imported->request_data_sequence_number,
                     exported->request_data_sequence_number);
    assert_memory_equal(imported->response_data_encryption_key,
                        exported->response_data_encryption_key, AEAD_KEY_SIZE);
    assert_memory_equal(imported->response_data_salt, exported->response_data_salt, AEAD_IV_SIZE);
    assert_int_equal(imported->response_data_sequence_number,
                     exported->response_data_sequence_number);
}

/**
 * Test 2: Export the session keys into a buffer that is one byte too small.
 * Expected Behavior: libspdm_secured_message_export_session_keys returns false and returns the
 * required size.
 **/
static void libspdm_test_secured_message_context_data_case2(void **state)
{
    uint8_t session_keys[SESSION_KEYS_SIZE];
    size_t session_keys_size;

    set_application_secret(&m_secured_message_context, 0x01);

    session_keys_size = sizeof(session_keys) - 1;
    assert_false(libspdm_secured_message_export_session_keys(&m_secured_message_context,
                                                             session_keys, &session_keys_size));
    assert_int_equal(session_keys_size, sizeof(session_keys));
}

/**
 * Test 3: Import session keys whose size does not match the context's AEAD key and IV sizes.
 * Expected Behavior: libspdm_secured_message_import_session_keys returns false and leaves the
 * context's application data keys unchanged.
 **/
static void libspdm_test_secured_message_context_data_case3(void **state)
{
    uint8_t session_keys[SESSION_KEYS_SIZE];
    size_t session_keys_size;
    uint8_t request_data_encryption_key[AEAD_KEY_SIZE];

    set_application_secret(&m_secured_message_context, 0x01);
    set_application_secret(&m_peer_secured_message_context, 0x20);

    session_keys_size = sizeof(session_keys);
    assert_true(libspdm_secured_message_export_session_keys(&m_secured_message_context,
                                                            session_keys, &session_keys_size));
    libspdm_copy_mem(request_data_encryption_key, sizeof(request_data_encryption_key),
                     m_peer_secured_message_context.application_secret
                     .request_data_encryption_key, AEAD_KEY_SIZE);

    /* {ERROR} The session keys are one byte shorter than the context requires. */
    assert_false(libspdm_secured_message_import_session_keys(&m_peer_secured_message_context,
                                                             session_keys,
                                                             session_keys_size - 1));
    assert_memory_equal(m_peer_secured_message_context.application_secret
                        .request_data_encryption_key,
                        request_data_encryption_key, AEAD_KEY_SIZE);
}

/**
 * Test 4: Import a shared secret of the size that the context expects.
 * Expected Behavior: libspdm_secured_message_import_shared_secret returns true, and the context
 * holds the shared secret and its size.
 **/
static void libspdm_test_secured_message_context_data_case4(void **state)
{
    uint8_t shared_secret[LIBSPDM_MAX_SHARED_KEY_SIZE];

    libspdm_zero_mem(&m_secured_message_context, sizeof(m_secured_message_context));
    m_secured_message_context.shared_key_size = sizeof(shared_secret);
    libspdm_set_mem(shared_secret, sizeof(shared_secret), 0x5A);

    assert_true(libspdm_secured_message_import_shared_secret(&m_secured_message_context,
                                                             shared_secret,
                                                             sizeof(shared_secret)));
    assert_int_equal(m_secured_message_context.shared_key_size, sizeof(shared_secret));
    assert_memory_equal(m_secured_message_context.master_secret.shared_secret, shared_secret,
                        sizeof(shared_secret));
}

/**
 * Test 5: Import a shared secret that is larger than the context expects.
 * Expected Behavior: libspdm_secured_message_import_shared_secret returns false and leaves the
 * context's shared secret size unchanged.
 **/
static void libspdm_test_secured_message_context_data_case5(void **state)
{
    uint8_t shared_secret[LIBSPDM_MAX_SHARED_KEY_SIZE];

    libspdm_zero_mem(&m_secured_message_context, sizeof(m_secured_message_context));
    /* {ERROR} The shared secret is one byte larger than the context expects. */
    m_secured_message_context.shared_key_size = sizeof(shared_secret) - 1;
    libspdm_set_mem(shared_secret, sizeof(shared_secret), 0x5A);

    assert_false(libspdm_secured_message_import_shared_secret(&m_secured_message_context,
                                                              shared_secret,
                                                              sizeof(shared_secret)));
    assert_int_equal(m_secured_message_context.shared_key_size, sizeof(shared_secret) - 1);
}

/**
 * Test 6: Export the session keys into a buffer that is one byte larger than they are, then import
 * them.
 * Expected Behavior: libspdm_secured_message_export_session_keys returns true and the size of the
 * session keys rather than the size of the buffer, and
 * libspdm_secured_message_import_session_keys accepts that size.
 **/
static void libspdm_test_secured_message_context_data_case6(void **state)
{
    uint8_t session_keys[SESSION_KEYS_SIZE + 1];
    size_t session_keys_size;

    set_application_secret(&m_secured_message_context, 0x01);
    set_application_secret(&m_peer_secured_message_context, 0x20);

    session_keys_size = sizeof(session_keys);
    assert_true(libspdm_secured_message_export_session_keys(&m_secured_message_context,
                                                            session_keys, &session_keys_size));
    assert_int_equal(session_keys_size, SESSION_KEYS_SIZE);

    assert_true(libspdm_secured_message_import_session_keys(&m_peer_secured_message_context,
                                                            session_keys, session_keys_size));
}

static libspdm_test_context_t m_libspdm_secured_message_context_data_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    NULL,
    NULL,
};

int libspdm_secured_message_context_data_test_main(void)
{
    const struct CMUnitTest spdm_secured_message_context_data_tests[] = {
        cmocka_unit_test(libspdm_test_secured_message_context_data_case1),
        cmocka_unit_test(libspdm_test_secured_message_context_data_case2),
        cmocka_unit_test(libspdm_test_secured_message_context_data_case3),
        cmocka_unit_test(libspdm_test_secured_message_context_data_case4),
        cmocka_unit_test(libspdm_test_secured_message_context_data_case5),
        cmocka_unit_test(libspdm_test_secured_message_context_data_case6),
    };

    libspdm_setup_test_context(&m_libspdm_secured_message_context_data_test_context);

    return cmocka_run_group_tests(spdm_secured_message_context_data_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
