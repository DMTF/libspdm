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
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

bool g_in_trusted_environment = false;
bool g_set_cert_is_busy = false;

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context
#endif
    )
{
    return g_in_trusted_environment;
}

bool libspdm_write_certificate_to_nvm(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint8_t slot_id, const void * cert_chain,
    size_t cert_chain_size,
    uint32_t base_hash_algo, uint32_t base_asym_algo
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *need_reset, bool *is_busy
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
    )
{
#if LIBSPDM_SET_CERT_CSR_PARAMS
    if (g_set_cert_is_busy) {
        *is_busy = true;

        return false;
    } else
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
    {
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
            if ((fp_out = open(file_name, O_WRONLY | O_TRUNC)) == -1) {
                printf("Unable to open file %s\n", file_name);
                return false;
            }

            close(fp_out);
        }

        close(fp_out);
    #endif

        return true;
    }
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
