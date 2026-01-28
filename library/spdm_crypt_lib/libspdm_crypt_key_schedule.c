/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"

void libspdm_bin_concat(spdm_version_number_t spdm_version,
                        const char *label, size_t label_size,
                        const uint8_t *context, uint16_t length,
                        size_t hash_size, uint8_t *out_bin,
                        size_t *out_bin_size)
{
    size_t final_size;

    /* The correct version characters (1.1 or 1.2) will replace the x.x. */
    #define LIBSPDM_BIN_CONCAT_LABEL "spdmx.x "

    final_size = sizeof(uint16_t) + sizeof(LIBSPDM_BIN_CONCAT_LABEL) - 1 + label_size;
    if (context != NULL) {
        final_size += hash_size;
    }

    LIBSPDM_ASSERT(*out_bin_size >= final_size);

    *out_bin_size = final_size;

    libspdm_copy_mem(out_bin, *out_bin_size, &length, sizeof(uint16_t));
    libspdm_copy_mem(out_bin + sizeof(uint16_t), *out_bin_size - sizeof(uint16_t),
                     LIBSPDM_BIN_CONCAT_LABEL, sizeof(LIBSPDM_BIN_CONCAT_LABEL) - 1);

    /* Patch the version. */
    out_bin[6] = (char)('0' + ((spdm_version >> 12) & 0xF));
    out_bin[8] = (char)('0' + ((spdm_version >> 8) & 0xF));
    libspdm_copy_mem(out_bin + sizeof(uint16_t) + sizeof(LIBSPDM_BIN_CONCAT_LABEL) - 1,
                     *out_bin_size - (sizeof(uint16_t) + sizeof(LIBSPDM_BIN_CONCAT_LABEL) - 1),
                     label, label_size);

    if (context != NULL) {
        libspdm_copy_mem(out_bin + sizeof(uint16_t) + sizeof(LIBSPDM_BIN_CONCAT_LABEL) -
                         1 + label_size,
                         *out_bin_size - (sizeof(uint16_t) + sizeof(LIBSPDM_BIN_CONCAT_LABEL) -
                                          1 + label_size), context, hash_size);
    }

    #undef LIBSPDM_BIN_CONCAT_LABEL
}

bool libspdm_generate_handshake_key (
    spdm_version_number_t spdm_version,
    const uint8_t *shared_secret, size_t shared_secret_size,
    bool shared_secret_use_psk,
    const uint8_t *psk_hint, size_t psk_hint_size,
    bool use_psk_hint,
    uint32_t base_hash_algo,
    const uint8_t *th1_hash_data,
    uint8_t *handshake_secret, size_t *handshake_secret_size,
    uint8_t *request_handshake_secret, size_t *request_handshake_secret_size,
    uint8_t *response_handshake_secret, size_t *response_handshake_secret_size)
{
    bool status = false;
    size_t hash_size;
    uint8_t bin_str1[128];
    size_t bin_str1_size;
    uint8_t bin_str2[128];
    size_t bin_str2_size;
    uint8_t salt0[LIBSPDM_MAX_HASH_SIZE];

    if (!use_psk_hint) {
        if (shared_secret == NULL || shared_secret_size == 0) {
            return false;
        }
    }

    hash_size = libspdm_get_hash_size(base_hash_algo);

    if (*handshake_secret_size < hash_size ||
        *request_handshake_secret_size < hash_size ||
        *response_handshake_secret_size < hash_size) {
        return false;
    }
    *handshake_secret_size = hash_size;
    *request_handshake_secret_size = hash_size;
    *response_handshake_secret_size = hash_size;

    bin_str1_size = sizeof(bin_str1);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_1_LABEL, sizeof(SPDM_BIN_STR_1_LABEL) - 1,
                       th1_hash_data, (uint16_t)hash_size, hash_size,
                       bin_str1, &bin_str1_size);

    bin_str2_size = sizeof(bin_str2);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                       th1_hash_data, (uint16_t)hash_size, hash_size,
                       bin_str2, &bin_str2_size);

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (use_psk_hint) {
        status = libspdm_psk_handshake_secret_hkdf_expand(
            spdm_version,
            base_hash_algo,
            psk_hint, psk_hint_size,
            bin_str1, bin_str1_size,
            request_handshake_secret, hash_size);

        if (!status) {
            return false;
        }

        status = libspdm_psk_handshake_secret_hkdf_expand(
            spdm_version,
            base_hash_algo,
            psk_hint, psk_hint_size,
            bin_str2, bin_str2_size,
            response_handshake_secret, hash_size);

        if (!status) {
            return false;
        }

    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

    if (!use_psk_hint) {
        libspdm_zero_mem(salt0, sizeof(salt0));
        #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        if ((shared_secret_use_psk) &&
            ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13)) {
            libspdm_set_mem(salt0, hash_size, 0xff);
        }
        #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

        status = libspdm_hkdf_extract(
            base_hash_algo,
            shared_secret, shared_secret_size,
            salt0, hash_size,
            handshake_secret, hash_size);
        if (!status) {
            return false;
        }

        status = libspdm_hkdf_expand(
            base_hash_algo,
            handshake_secret,
            hash_size, bin_str1, bin_str1_size,
            request_handshake_secret, hash_size);

        if (!status) {
            return false;
        }

        status = libspdm_hkdf_expand(
            base_hash_algo,
            handshake_secret,
            hash_size, bin_str2, bin_str2_size,
            response_handshake_secret, hash_size);

        if (!status) {
            return false;
        }
    }

    return status;
}

bool libspdm_generate_data_key (
    spdm_version_number_t spdm_version,
    const uint8_t *handshake_secret, size_t handshake_secret_size,
    const uint8_t *psk_hint, size_t psk_hint_size,
    bool use_psk_hint,
    uint32_t base_hash_algo,
    const uint8_t *th2_hash_data,
    uint8_t *master_secret, size_t *master_secret_size,
    uint8_t *request_data_secret, size_t *request_data_secret_size,
    uint8_t *response_data_secret, size_t *response_data_secret_size,
    uint8_t *export_master_secret, size_t *export_master_secret_size)
{
    bool status = false;
    size_t hash_size;
    uint8_t salt1[LIBSPDM_MAX_HASH_SIZE];
    uint8_t bin_str0[128];
    size_t bin_str0_size;
    uint8_t bin_str3[128];
    size_t bin_str3_size;
    uint8_t bin_str4[128];
    size_t bin_str4_size;
    uint8_t bin_str8[128];
    size_t bin_str8_size;
    uint8_t zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];

    if (!use_psk_hint) {
        if (handshake_secret == NULL || handshake_secret_size == 0) {
            return false;
        }
    }

    hash_size = libspdm_get_hash_size(base_hash_algo);

    if (*master_secret_size < hash_size ||
        *request_data_secret_size < hash_size ||
        *response_data_secret_size < hash_size ||
        *export_master_secret_size < hash_size) {
        return false;
    }
    *master_secret_size = hash_size;
    *request_data_secret_size = hash_size;
    *response_data_secret_size = hash_size;
    *export_master_secret_size = hash_size;

    bin_str3_size = sizeof(bin_str3);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_3_LABEL, sizeof(SPDM_BIN_STR_3_LABEL) - 1,
                       th2_hash_data, (uint16_t)hash_size, hash_size,
                       bin_str3, &bin_str3_size);

    bin_str4_size = sizeof(bin_str4);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_4_LABEL, sizeof(SPDM_BIN_STR_4_LABEL) - 1,
                       th2_hash_data, (uint16_t)hash_size, hash_size,
                       bin_str4, &bin_str4_size);

    bin_str8_size = sizeof(bin_str8);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_8_LABEL, sizeof(SPDM_BIN_STR_8_LABEL) - 1,
                       th2_hash_data, (uint16_t)hash_size, hash_size,
                       bin_str8, &bin_str8_size);

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (use_psk_hint) {
        status = libspdm_psk_master_secret_hkdf_expand(
            spdm_version,
            base_hash_algo,
            psk_hint, psk_hint_size,
            bin_str3, bin_str3_size,
            request_data_secret, hash_size);

        if (!status) {
            goto cleanup;
        }

        status = libspdm_psk_master_secret_hkdf_expand(
            spdm_version,
            base_hash_algo,
            psk_hint, psk_hint_size,
            bin_str4, bin_str4_size,
            response_data_secret, hash_size);

        if (!status) {
            goto cleanup;
        }

        status = libspdm_psk_master_secret_hkdf_expand(
            spdm_version,
            base_hash_algo,
            psk_hint, psk_hint_size,
            bin_str8, bin_str8_size,
            export_master_secret, hash_size);

        if (!status) {
            goto cleanup;
        }
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

    if (!use_psk_hint) {
        bin_str0_size = sizeof(bin_str0);
        libspdm_bin_concat(spdm_version,
                           SPDM_BIN_STR_0_LABEL,
                           sizeof(SPDM_BIN_STR_0_LABEL) - 1, NULL,
                           (uint16_t)hash_size, hash_size, bin_str0,
                           &bin_str0_size);

        status = libspdm_hkdf_expand(
            base_hash_algo, handshake_secret,
            hash_size, bin_str0, bin_str0_size, salt1, hash_size);
        if (!status) {
            goto cleanup;
        }

        libspdm_zero_mem(zero_filled_buffer, sizeof(zero_filled_buffer));
        status = libspdm_hkdf_extract(
            base_hash_algo,
            zero_filled_buffer, hash_size, salt1, hash_size,
            master_secret, hash_size);
        if (!status) {
            goto cleanup;
        }

        status = libspdm_hkdf_expand(
            base_hash_algo,
            master_secret, hash_size,
            bin_str3, bin_str3_size,
            request_data_secret, hash_size);

        if (!status) {
            goto cleanup;
        }

        status = libspdm_hkdf_expand(
            base_hash_algo,
            master_secret, hash_size,
            bin_str4, bin_str4_size,
            response_data_secret, hash_size);

        if (!status) {
            goto cleanup;
        }

        status = libspdm_hkdf_expand(
            base_hash_algo,
            master_secret, hash_size,
            bin_str8, bin_str8_size,
            export_master_secret, hash_size);

        if (!status) {
            goto cleanup;
        }
    }

cleanup:
    /*zero salt1 for security*/
    libspdm_zero_mem(salt1, hash_size);
    return status;
}
