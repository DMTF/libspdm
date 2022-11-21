/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SHA-256/384/512 digest Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

#undef libspdm_sha256_new
#undef libspdm_sha256_init
#undef libspdm_sha256_update
#undef libspdm_sha256_final
#undef libspdm_sha256_hash_all

#undef libspdm_sha384_new
#undef libspdm_sha384_init
#undef libspdm_sha384_update
#undef libspdm_sha384_final
#undef libspdm_sha384_hash_all

#undef libspdm_sha512_new
#undef libspdm_sha512_init
#undef libspdm_sha512_update
#undef libspdm_sha512_final
#undef libspdm_sha512_hash_all

bool m_libspdm_sha256_new_error = false;
bool m_libspdm_sha256_init_error = false;
bool m_libspdm_sha256_update_error = false;
bool m_libspdm_sha256_final_error = false;
bool m_libspdm_sha256_hash_all_error = false;

bool m_libspdm_sha384_new_error = false;
bool m_libspdm_sha384_init_error = false;
bool m_libspdm_sha384_update_error = false;
bool m_libspdm_sha384_final_error = false;
bool m_libspdm_sha384_hash_all_error = false;

bool m_libspdm_sha512_new_error = false;
bool m_libspdm_sha512_init_error = false;
bool m_libspdm_sha512_update_error = false;
bool m_libspdm_sha512_final_error = false;
bool m_libspdm_sha512_hash_all_error = false;

void *libspdm_sha256_new_internal(void);
bool libspdm_sha256_init_internal(void *sha256_context);
bool libspdm_sha256_update_internal(void *sha256_context, const void *data, size_t data_size);
bool libspdm_sha256_final_internal(void *sha256_context, uint8_t *hash_value);
bool libspdm_sha256_hash_all_internal(const void *data, size_t data_size, uint8_t *hash_value);

void *libspdm_sha384_new_internal(void);
bool libspdm_sha384_init_internal(void *sha384_context);
bool libspdm_sha384_update_internal(void *sha384_context, const void *data, size_t data_size);
bool libspdm_sha384_final_internal(void *sha384_context, uint8_t *hash_value);
bool libspdm_sha384_hash_all_internal(const void *data, size_t data_size, uint8_t *hash_value);

void *libspdm_sha512_new_internal(void);
bool libspdm_sha512_init_internal(void *sha512_context);
bool libspdm_sha512_update_internal(void *sha512_context, const void *data, size_t data_size);
bool libspdm_sha512_final_internal(void *sha512_context, uint8_t *hash_value);
bool libspdm_sha512_hash_all_internal(const void *data, size_t data_size, uint8_t *hash_value);

void *libspdm_sha256_new(void)
{
    if (m_libspdm_sha256_new_error) {
        return NULL;
    } else {
        return libspdm_sha256_new_internal();
    }
}

bool libspdm_sha256_init(void *sha256_context)
{
    if (m_libspdm_sha256_init_error) {
        return false;
    } else {
        return libspdm_sha256_init_internal(sha256_context);
    }
}

bool libspdm_sha256_update(void *sha256_context, const void *data, size_t data_size)
{
    if (m_libspdm_sha256_update_error) {
        return false;
    } else {
        return libspdm_sha256_update_internal(sha256_context, data, data_size);
    }
}

bool libspdm_sha256_final(void *sha256_context, uint8_t *hash_value)
{
    if (m_libspdm_sha256_final_error) {
        return false;
    } else {
        return libspdm_sha256_final_internal(sha256_context, hash_value);
    }
}

bool libspdm_sha256_hash_all(const void *data, size_t data_size, uint8_t *hash_value)
{
    if (m_libspdm_sha256_hash_all_error) {
        return false;
    } else {
        return libspdm_sha256_hash_all_internal(data, data_size, hash_value);
    }
}

void *libspdm_sha384_new(void)
{
    if (m_libspdm_sha384_new_error) {
        return NULL;
    } else {
        return libspdm_sha384_new_internal();
    }
}

bool libspdm_sha384_init(void *sha384_context)
{
    if (m_libspdm_sha384_init_error) {
        return false;
    } else {
        return libspdm_sha384_init_internal(sha384_context);
    }
}

bool libspdm_sha384_update(void *sha384_context, const void *data,
                           size_t data_size)
{
    if (m_libspdm_sha384_update_error) {
        return false;
    } else {
        return libspdm_sha384_update_internal(sha384_context, data, data_size);
    }
}

bool libspdm_sha384_final(void *sha384_context, uint8_t *hash_value)
{
    if (m_libspdm_sha384_final_error) {
        return false;
    } else {
        return libspdm_sha384_final_internal(sha384_context, hash_value);
    }
}

bool libspdm_sha384_hash_all(const void *data, size_t data_size, uint8_t *hash_value)
{
    if (m_libspdm_sha384_hash_all_error) {
        return false;
    } else {
        return libspdm_sha384_hash_all_internal(data, data_size, hash_value);
    }
}

void *libspdm_sha512_new(void)
{
    if (m_libspdm_sha512_new_error) {
        return NULL;
    } else {
        return libspdm_sha512_new_internal();
    }
}

bool libspdm_sha512_init(void *sha512_context)
{
    if (m_libspdm_sha512_init_error) {
        return false;
    } else {
        return libspdm_sha512_init_internal(sha512_context);
    }
}

bool libspdm_sha512_update(void *sha512_context, const void *data,
                           size_t data_size)
{
    if (m_libspdm_sha512_update_error) {
        return false;
    } else {
        return libspdm_sha512_update_internal(sha512_context, data, data_size);
    }
}

bool libspdm_sha512_final(void *sha512_context, uint8_t *hash_value)
{
    if (m_libspdm_sha512_final_error) {
        return false;
    } else {
        return libspdm_sha512_final_internal(sha512_context, hash_value);
    }
}

bool libspdm_sha512_hash_all(const void *data, size_t data_size, uint8_t *hash_value)
{
    if (m_libspdm_sha512_hash_all_error) {
        return false;
    } else {
        return libspdm_sha512_hash_all_internal(data, data_size, hash_value);
    }
}
