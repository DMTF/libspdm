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
#include <tss2/tss2_rc.h>
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
    if (tpm_provider == NULL){
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
    if (!store_ctx){
        return false;
    }

    while ((info = OSSL_STORE_load(store_ctx)) != NULL)
    {
        if (OSSL_STORE_INFO_get_type(info) == keyinfo_type){
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

    if (*context == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no keyinfo %d foun on handle %s\n", keyinfo_type, handle));
        return false;
    }

    return true;
}

bool libspdm_tpm_get_private_key(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

bool libspdm_tpm_get_public_key(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY)){
        return false;
    }
    *context = create_key_context(pkey);
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
        }
    };

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
    if ((result = Tss2_TctiLdr_Initialize(tssconf, &tcti_context)) != TSS2_RC_SUCCESS){
        goto finish;
    }

    /* TODO: abi version check */
    if ((result = Esys_Initialize(&context, tcti_context, NULL)) != TSS2_RC_SUCCESS){
        goto cleanup_tcti;
    }

    if ((result = Esys_PCR_Read(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &sel, &uc, &out,
                                &values)) != TSS2_RC_SUCCESS){
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

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR nv_tr = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nv_pub = NULL;
    TPM2B_NAME *nv_name = NULL;
    TPMS_CAPABILITY_DATA *cap = NULL;

    UINT16 nv_size;
    UINT32 max_nv_buf;
    UINT16 offset = 0;

    *buffer = NULL;
    *size = 0;

    rc = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_TR_FromTPMPublic(
        esys,
        index, /* TPM handle */
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_tr);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_NV_ReadPublic(
        esys,
        nv_tr,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_pub,
        &nv_name);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    nv_size = nv_pub->nvPublic.dataSize;

    rc = Esys_GetCapability(
        esys,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_NV_BUFFER_MAX,
        1,
        NULL,
        &cap);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    max_nv_buf = cap->data.tpmProperties.tpmProperty[0].value;

    *buffer = malloc(nv_size);
    if (!*buffer)
        goto out;

    while (offset < nv_size)
    {
        TPM2B_MAX_NV_BUFFER *chunk = NULL;
        UINT16 to_read = (nv_size - offset > max_nv_buf)
                             ? max_nv_buf
                             : nv_size - offset;

        rc = Esys_NV_Read(
            esys,
            nv_tr,
            nv_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            to_read,
            offset,
            &chunk);
        if (rc != TSS2_RC_SUCCESS){
            Esys_Free(chunk);
            goto out;
        }

        memcpy((uint8_t *)(*buffer) + offset,
               chunk->buffer,
               chunk->size);

        offset += chunk->size;
        Esys_Free(chunk);
    }

    *size = nv_size;
    rc = TSS2_RC_SUCCESS;

out:
    if (cap)
        Esys_Free(cap);
    if (nv_pub)
        Esys_Free(nv_pub);
    if (nv_name)
        Esys_Free(nv_name);
    if (nv_tr != ESYS_TR_NONE)
        Esys_FlushContext(esys, nv_tr);
    if (esys)
        Esys_Finalize(&esys);
    if (tcti)
        Tss2_TctiLdr_Finalize(&tcti);

    return rc == TSS2_RC_SUCCESS;
}
