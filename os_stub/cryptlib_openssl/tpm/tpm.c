/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <complex.h>
#include <openssl/err.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tpm2_types.h>
#include "library/cryptlib/cryptlib_tpm.h"
#include "internal/libspdm_crypt_lib.h"

#include "key_context.h"

bool g_tpm_device_initialized = false;

static libspdm_key_context *create_key_context(EVP_PKEY *pkey)
{
    libspdm_key_context *context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    context->evp_pkey = pkey;
    return context;
}

bool libspdm_tpm_device_init()
{
    OSSL_PROVIDER *tpm_provider = NULL;

    if (g_tpm_device_initialized)
        return true;

    tpm_provider = OSSL_PROVIDER_load(NULL, "tpm2");
    if (tpm_provider == NULL)
    {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to load tpm2\n"));
        return false;
    }

    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    g_tpm_device_initialized = true;
    return true;
}

static bool get_keyinfo(const char *handle, void **context, int keyinfo_type)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    /* handle must look like: "tpm2tss:0x81010002" */
    store_ctx = OSSL_STORE_open_ex(handle, NULL, "provider=tpm2", NULL, NULL, NULL, NULL, NULL);
    if (!store_ctx)
    {
        return false;
    }

    while ((info = OSSL_STORE_load(store_ctx)) != NULL)
    {
        if (OSSL_STORE_INFO_get_type(info) == keyinfo_type)
        {
            switch (keyinfo_type)
            {
            case OSSL_STORE_INFO_PKEY:
                *context = OSSL_STORE_INFO_get1_PKEY(info);
                break;
            case OSSL_STORE_INFO_PUBKEY:
                *context = OSSL_STORE_INFO_get1_PUBKEY(info);
                break;
            case OSSL_STORE_INFO_CERT:
                *context = OSSL_STORE_INFO_get1_CERT(info);
                break;
            }
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (*context == NULL)
    {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no keyinfo %d foun on handle %s\n", keyinfo_type, handle));
        return false;
    }

    return true;
}

bool libspdm_tpm_get_private_key(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY))
    {
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

bool libspdm_tpm_get_public_key(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY))
    {
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

bool libspdm_tpm_get_certificate(void *handle, void **context)
{
    return get_keyinfo((const char *)handle, context, OSSL_STORE_INFO_CERT);
}

bool libspdm_tpm_dump_certificate(void *context, void **buffer, size_t *size)
{
    int len = 0;
    len = i2d_X509((X509 *)context, NULL);
    if (len < 0)
        return false;

    void *cert = OPENSSL_malloc(len);
    if (cert == NULL)
    {
        return false;
    }
    *buffer = cert;
    len = i2d_X509((X509 *)context, (unsigned char **)&cert);
    if (len < 0)
    {
        free(*buffer);
        *buffer = NULL;
        return false;
    }
    *size = len;
    return true;
}

bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size)
{
    TSS2_RC result;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    ESYS_CONTEXT *context = NULL;

    TPML_PCR_SELECTION sel = {
        .count = 1,
        .pcrSelections = {
            {
                .sizeofSelect = 3,
                .pcrSelect = {0x00, 0x00, 0x00, 0x00},
            },
        }};

    *size = 0;
    switch (hash_algo)
    {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
        *size = 32;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA384;
        *size = 48;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA512;
        *size = 64;
        break;
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported measurement hash algo %d\n", hash_algo));
        return false;
    }
    sel.pcrSelections[0].pcrSelect[(index - 1) / 8] |= 1 << ((index - 1) % 8);

    UINT32 uc;
    TPML_PCR_SELECTION *out = NULL;
    TPML_DIGEST *values = NULL;

    const char *tssconf = getenv("TPM2TOOLS_TCTI");
    if ((result = Tss2_TctiLdr_Initialize(tssconf, &tcti_context)) != TSS2_RC_SUCCESS)
    {
        goto finish;
    }

    // TODO: abi version check
    if ((result = Esys_Initialize(&context, tcti_context, NULL)) != TSS2_RC_SUCCESS)
    {
        goto cleanup_tcti;
    }

    if ((result = Esys_PCR_Read(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &sel, &uc, &out, &values)) != TSS2_RC_SUCCESS)
    {
        goto cleanup_esys;
    }

    memcpy(buffer, values->digests[0].buffer, *size);

cleanup_esys:
    Esys_Finalize(&context);

cleanup_tcti:
    Tss2_TctiLdr_Finalize(&tcti_context);

finish:
    return result == TSS2_RC_SUCCESS;
}