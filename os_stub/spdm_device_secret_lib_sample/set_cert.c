/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
    defined(LIBSPDM_CPU_ARM)))
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"

bool g_in_trusted_environment = false;
bool g_set_cert_is_busy = false;

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment(void *spdm_context)
{
    return g_in_trusted_environment;
}

static bool libspdm_write_certificate_to_nvm(
    void *spdm_context,
    uint8_t slot_id, const void * cert_chain,
    size_t cert_chain_size,
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    bool *need_reset, bool *is_busy)
{
    if (g_set_cert_is_busy) {
        *is_busy = true;

        return false;
    } else {
    #if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
        defined(LIBSPDM_CPU_ARM)))
        FILE *fp_out;
    #else
        int64_t fp_out;
    #endif

        char file_name[] = "slot_id_0_cert_chain.der";
        /*change the file name, for example: slot_id_1_cert_chain.der*/
        file_name[8] = (char)(slot_id+'0');

        /*check the input parameter*/
        if ((cert_chain == NULL) ^ (cert_chain_size == 0) ) {
            return false;
        }

    #if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
        defined(LIBSPDM_CPU_ARM)))
        if ((fp_out = fopen(file_name, "w+b")) == NULL) {
            printf("Unable to open file %s\n", file_name);
            return false;
        }

        if (cert_chain != NULL) {
            if ((fwrite(cert_chain, 1, cert_chain_size, fp_out)) != cert_chain_size) {
                printf("Write output file error %s\n", file_name);
                fclose(fp_out);
                return false;
            }
        }

        fclose(fp_out);
    #else
        if (cert_chain != NULL) {
            if ((fp_out = open(file_name, O_WRONLY | O_CREAT, S_IRWXU)) == -1) {
                printf("Unable to open file %s\n", file_name);
                return false;
            }

            if ((write(fp_out, cert_chain, cert_chain_size)) != cert_chain_size) {
                printf("Write output file error %s\n", file_name);
                close(fp_out);
                return false;
            }
        } else {
            if ((fp_out = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU)) == -1) {
                printf("Unable to open file %s\n", file_name);
                return false;
            }
        }

        close(fp_out);
    #endif

        return true;
    }
}

uint32_t libspdm_get_cert_chain_slot_storage_size(
    void *spdm_context, uint8_t slot_id)
{
    return SPDM_MAX_CERTIFICATE_CHAIN_SIZE_14;
}

bool libspdm_update_local_cert_chain(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t slot_id,
    uint32_t base_hash_algo,
    uint32_t base_asym_algo,
    uint32_t pqc_asym_algo,
    size_t hash_size,
    const void *old_cert_chain,
    size_t old_cert_chain_size,
    const void *cert_chain,
    size_t *cert_chain_size,
    uint8_t cert_model,
    bool *need_reset,
    bool *is_busy)
{
    libspdm_data_parameter_t parameter;
    libspdm_return_t status;
    size_t header_size;
    uint8_t *new_buffer;
    bool result;
    const uint8_t *new_chain_bytes;

    if (slot_id >= SPDM_MAX_SLOT_COUNT) {
        return false;
    }

    if (cert_chain != NULL) {
        result = libspdm_write_certificate_to_nvm(
            spdm_context,
            slot_id,
            (const uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + hash_size,
            *cert_chain_size - (sizeof(spdm_cert_chain_t) + hash_size),
            base_hash_algo,
            base_asym_algo,
            pqc_asym_algo,
            need_reset,
            is_busy);
    } else {
        result = libspdm_write_certificate_to_nvm(
            spdm_context,
            slot_id,
            NULL,
            0,
            base_hash_algo,
            base_asym_algo,
            pqc_asym_algo,
            need_reset,
            is_busy);
    }

    if (!result) {
        return result;
    }

    if (cert_chain == NULL || cert_chain_size == NULL || *cert_chain_size == 0) {
        new_buffer = NULL;
        goto set_cert;
    }

    header_size = sizeof(spdm_cert_chain_t) + hash_size;
    if (*cert_chain_size < header_size) {
        return false;
    }

    new_chain_bytes = (const uint8_t *)cert_chain;

    if (cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT ||
        cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) {
        /* Device/generic certificate model: replace the entire local chain.*/

        new_buffer = (uint8_t *)malloc(*cert_chain_size);
        if (new_buffer == NULL) {
            return false;
        }

        libspdm_copy_mem(new_buffer, *cert_chain_size,
                         new_chain_bytes, *cert_chain_size);
    } else if (cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT) {
        /* Alias Cert Model, the new `cert_chain` shall contain a partial
         * certificate chain from the root CA to the Device Certificate CA.
         *
         * We need to update the old root CA to the Device Certificate CA
         * and leave the other certs as they are. Then update the hash and
         * the size.
         */
        const uint8_t *new_certs = new_chain_bytes + header_size;
        size_t new_certs_size = *cert_chain_size - header_size;
        const uint8_t *old_certs = (const uint8_t *)old_cert_chain + header_size;
        size_t old_certs_size = old_cert_chain_size - header_size;
        size_t old_offset = 0;
        int32_t cert_index = 0;
        size_t mutable_cert_offset = 0;
        spdm_cert_chain_t *new_cert_chain;
        const uint8_t *root_cert;
        size_t root_cert_len;

        /* First, find the offset of the Device Certificate CA in the old
         * certs. This should contain the Hardware identity OID.
         */
        while (old_offset < old_certs_size) {
            const uint8_t *cert = NULL;
            size_t cert_size = 0;

            if (!libspdm_x509_get_cert_from_cert_chain(
                    old_certs, old_certs_size, cert_index,
                    &cert, &cert_size)) {
                return false;
            }

            mutable_cert_offset += cert_size;

            if (libspdm_contains_hardware_id_oid(cert, cert_size)) {
                /* We found the Device Certificate CA */
                break;
            }

            cert_index++;
        }

        /* Now Allocate enough memory for the new cert chain and the old
         * mutable certs
         */
        size_t new_cert_chain_size = (old_certs_size - mutable_cert_offset) + *cert_chain_size;
        new_buffer = (uint8_t *)malloc(new_cert_chain_size);
        if (new_buffer == NULL) {
            return false;
        }


        /* Copy the new immutable certificates */
        libspdm_copy_mem(new_buffer + header_size, new_cert_chain_size - header_size,
                         new_certs, new_certs_size);

        /* Copy the old mutable certificates */
        libspdm_copy_mem(new_buffer + header_size + new_certs_size, new_cert_chain_size - header_size - new_certs_size,
                         old_certs + mutable_cert_offset, old_certs_size - mutable_cert_offset);

        /* Update the size */
        *cert_chain_size = new_cert_chain_size;

        new_cert_chain = (spdm_cert_chain_t*)new_buffer;
        new_cert_chain->length = (uint32_t)new_cert_chain_size;

        /* Get Root Certificate*/
        status = libspdm_x509_get_cert_from_cert_chain(new_buffer + header_size, new_cert_chain_size - header_size, 0,
                                                       &root_cert,
                                                       &root_cert_len);
        if (!status) {
            free(new_buffer);
            return false;
        }

        /* Update the certificate hash */
        libspdm_hash_all(
            base_hash_algo,
            root_cert,
            root_cert_len,
            new_buffer + 4);
    } else {
        return false;
    }

set_cert:

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    parameter.additional_data[0] = slot_id;
    if (cert_chain_size == NULL) {
        status = libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                  &parameter, new_buffer, 0);
    } else {
        status = libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                  &parameter, new_buffer, *cert_chain_size);
    }
    if (status != LIBSPDM_STATUS_SUCCESS) {
        free(new_buffer);
        return false;
    }

    /* `old_cert_chain` can be freed at this point. We can't
     * free() the const version supplied to this function and
     * stored in libspdm, so implementations need to keep track
     * of the buffer manually, probably by storing it in
     * `app_context_data_ptr`.
     */

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
