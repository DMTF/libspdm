/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_crypt_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

size_t libspdm_get_max_buffer_size(void)
{
    return 4096;
}

static uint8_t libspdm_get_data_u8(const uint8_t *buffer, size_t buffer_size,
                                   size_t *offset, uint8_t default_value)
{
    if (*offset >= buffer_size) {
        return default_value;
    }
    return buffer[(*offset)++];
}

static size_t libspdm_get_data_block(const uint8_t *buffer, size_t buffer_size,
                                     size_t *offset, uint8_t *output,
                                     size_t output_size)
{
    size_t available;
    size_t copy_size;

    if ((*offset >= buffer_size) || (output_size == 0)) {
        return 0;
    }

    available = buffer_size - *offset;
    copy_size = available;
    if (copy_size > output_size) {
        copy_size = output_size;
    }

    libspdm_copy_mem(output, output_size, buffer + *offset, copy_size);
    *offset += copy_size;
    return copy_size;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    const uint8_t *buffer;
    size_t offset;
    size_t nids[4] = {
        LIBSPDM_CRYPTO_NID_ML_KEM_512,
        LIBSPDM_CRYPTO_NID_ML_KEM_768,
        LIBSPDM_CRYPTO_NID_ML_KEM_1024,
        (size_t)-1
    };
    size_t local_nid;
    void *kem_local;
    void *kem_peer;
    uint8_t peer_public_key[1568];
    uint8_t cipher_text[1568];
    uint8_t shared_secret[64];
    size_t peer_public_key_size;
    size_t cipher_text_size;
    size_t shared_secret_size;
    bool status;

    if ((test_buffer == NULL) || (test_buffer_size == 0)) {
        return;
    }

    buffer = (const uint8_t *)test_buffer;
    offset = 0;

    local_nid = nids[libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0) % 4];
    kem_local = libspdm_mlkem_new_by_name(local_nid);
    if (kem_local == NULL) {
        return;
    }

    kem_peer = libspdm_mlkem_new_by_name(
        nids[libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0) % 3]);
    if (kem_peer == NULL) {
        libspdm_mlkem_free(kem_local);
        return;
    }

    peer_public_key_size =
        (size_t)libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0);
    status = libspdm_mlkem_generate_key(kem_peer, peer_public_key,
                                        &peer_public_key_size);
    if (!status) {
        peer_public_key_size = sizeof(peer_public_key);
        status = libspdm_mlkem_generate_key(kem_peer, peer_public_key,
                                            &peer_public_key_size);
    }

    if ((libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0) & 0x1) != 0) {
        /* Exercise invalid public-key size path. */
        cipher_text_size = sizeof(cipher_text);
        shared_secret_size = sizeof(shared_secret);
        (void)libspdm_mlkem_encapsulate(kem_local, peer_public_key,
                                        peer_public_key_size == 0 ? 1 : peer_public_key_size - 1,
                                        cipher_text, &cipher_text_size,
                                        shared_secret, &shared_secret_size);
    }

    if (status) {
        cipher_text_size =
            (size_t)libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0);
        shared_secret_size =
            (size_t)libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0);

        if (cipher_text_size == 0) {
            cipher_text_size = sizeof(cipher_text);
        }
        if (shared_secret_size == 0) {
            shared_secret_size = sizeof(shared_secret);
        }

        status = libspdm_mlkem_encapsulate(kem_local, peer_public_key,
                                           peer_public_key_size,
                                           cipher_text, &cipher_text_size,
                                           shared_secret, &shared_secret_size);

        if (status &&
            ((libspdm_get_data_u8(buffer, test_buffer_size, &offset, 0) & 0x1) != 0)) {
            size_t bad_shared_secret_size =
                (size_t)libspdm_get_data_u8(buffer, test_buffer_size, &offset, 1);
            (void)libspdm_mlkem_decapsulate(kem_peer, cipher_text,
                                            cipher_text_size,
                                            shared_secret,
                                            &bad_shared_secret_size);
        }

        if (status) {
            shared_secret_size = sizeof(shared_secret);
            (void)libspdm_mlkem_decapsulate(kem_peer, cipher_text,
                                            cipher_text_size,
                                            shared_secret,
                                            &shared_secret_size);
        }
    }

    /* Exercise decapsulation with fuzzer-provided ciphertext too. */
    cipher_text_size =
        libspdm_get_data_block(buffer, test_buffer_size, &offset,
                               cipher_text, sizeof(cipher_text));
    if (cipher_text_size > 0) {
        shared_secret_size = sizeof(shared_secret);
        (void)libspdm_mlkem_decapsulate(kem_peer, cipher_text,
                                        cipher_text_size,
                                        shared_secret,
                                        &shared_secret_size);
    }

    libspdm_mlkem_free(kem_peer);
    libspdm_mlkem_free(kem_local);
}
