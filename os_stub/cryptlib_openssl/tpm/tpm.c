/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <openssl/err.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_crypt_lib.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_secured_message.h"

#include "../key_context.h"

bool g_tpm_device_initialized = false;

static libspdm_key_context *create_key_context(EVP_PKEY *pkey)
{
    libspdm_key_context *context;

    if (pkey == NULL) {
        return NULL;
    }

    context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (context == NULL) {
        return NULL;
    }
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

    if (handle == NULL || context == NULL) {
        return false;
    }
    *context = NULL;

    /* handle must look like: "handle:0x81010002" or "tpm2tss:0x81010002" */
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
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (*context == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no keyinfo %d found on handle %s\n", keyinfo_type, handle));
        return false;
    }

    return true;
}

bool libspdm_tpm_get_pvt_key_handle(const void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;

    if (context == NULL) {
        return false;
    }
    *context = NULL;

    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    if (*context == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    return true;
}

bool libspdm_tpm_get_pub_key_handle(const void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;

    if (context == NULL) {
        return false;
    }
    *context = NULL;

    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    if (*context == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    return true;
}

bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size)
{
    TSS2_RC result = 1;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    ESYS_CONTEXT *context = NULL;
    TPML_PCR_SELECTION *out = NULL;
    TPML_DIGEST *values = NULL;
    size_t digest_size = 0;
    UINT32 uc;

    TPML_PCR_SELECTION sel = {
        .count = 1,
        .pcrSelections = {
            {
                .sizeofSelect = 3,
                .pcrSelect = {0x00, 0x00, 0x00, 0x00},
            },
        }
    };

    if (buffer == NULL || size == NULL) {
        return false;
    }

    if (index >= 24) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "invalid PCR index %u (max 23)\n", index));
        return false;
    }

    switch (hash_algo)
    {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
        digest_size = 32;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA384;
        digest_size = 48;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA512;
        digest_size = 64;
        break;
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported measurement hash algo %d\n", hash_algo));
        return false;
    }

    if (*size < digest_size) {
        *size = digest_size;
        return false;
    }

    sel.pcrSelections[0].pcrSelect[index / 8] |= (uint8_t)(1 << (index % 8));

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

    if (values == NULL || values->count == 0 || values->digests[0].size < digest_size) {
        result = 1;
        goto cleanup_esys;
    }

    memcpy(buffer, values->digests[0].buffer, digest_size);
    *size = digest_size;

cleanup_esys:
    if (out != NULL) {
        Esys_Free(out);
    }
    if (values != NULL) {
        Esys_Free(values);
    }
    Esys_Finalize(&context);

cleanup_tcti:
    Tss2_TctiLdr_Finalize(&tcti_context);

finish:
    return result == TSS2_RC_SUCCESS;
}

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size)
{
    TSS2_RC rc = 1;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR nv_tr = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nv_pub = NULL;
    TPM2B_NAME *nv_name = NULL;
    TPMS_CAPABILITY_DATA *cap = NULL;

    UINT16 nv_size;
    UINT32 max_nv_buf;
    UINT16 offset = 0;

    if (buffer == NULL || size == NULL) {
        return false;
    }

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
    if (nv_size == 0) {
        rc = 1;
        goto out;
    }

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

    if (cap != NULL && cap->data.tpmProperties.count > 0 &&
        cap->data.tpmProperties.tpmProperty[0].value > 0) {
        max_nv_buf = cap->data.tpmProperties.tpmProperty[0].value;
    } else {
        max_nv_buf = 1024;
    }

    *buffer = malloc(nv_size);
    if (!*buffer) {
        rc = 1;
        goto out;
    }

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

        if (chunk == NULL || chunk->size == 0) {
            rc = 1;
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
    if (rc != TSS2_RC_SUCCESS && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
        *size = 0;
    }
    if (cap)
        Esys_Free(cap);
    if (nv_pub)
        Esys_Free(nv_pub);
    if (nv_name)
        Esys_Free(nv_name);
    if (nv_tr != ESYS_TR_NONE)
        Esys_TR_Close(esys, &nv_tr);
    if (esys)
        Esys_Finalize(&esys);
    if (tcti)
        Tss2_TctiLdr_Finalize(&tcti);

    return rc == TSS2_RC_SUCCESS;
}

static uint32_t parse_tpm_key_handle(const void *handle_param)
{
#define TPM_HANDLE_START_RANGE 0x80000000
#define TPM_HANDLE_END_RANGE 0x81FFFFFF
#define TPM_HANDLE_HANDLE_PREFIX "handle:"
#define TPM_HANDLE_TPM2TSS_PREFIX "tpm2tss:"

    const char *handle_str = NULL;
    if (handle_param == NULL) {
        return 0;
    }

    if ((uintptr_t)handle_param >= TPM_HANDLE_START_RANGE && (uintptr_t)handle_param <= TPM_HANDLE_END_RANGE) {
        return (uint32_t)(uintptr_t)handle_param;
    }

    handle_str = (const char *)handle_param;
    if (strncmp(handle_str, TPM_HANDLE_HANDLE_PREFIX, sizeof(TPM_HANDLE_HANDLE_PREFIX) - 1) == 0) {
        return (uint32_t)strtoul(handle_str + sizeof(TPM_HANDLE_HANDLE_PREFIX) - 1, NULL, 16);
    }
    if (strncmp(handle_str, TPM_HANDLE_TPM2TSS_PREFIX, sizeof(TPM_HANDLE_TPM2TSS_PREFIX) - 1) == 0) {
        return (uint32_t)strtoul(handle_str + sizeof(TPM_HANDLE_TPM2TSS_PREFIX) - 1, NULL, 16);
    }

#undef TPM_HANDLE_START_RANGE
#undef TPM_HANDLE_END_RANGE
#undef TPM_HANDLE_HANDLE_PREFIX
#undef TPM_HANDLE_TPM2TSS_PREFIX

    return (uint32_t)strtoul(handle_str, NULL, 0);
}

static bool map_spdm_meas_hash_to_tpm(uint32_t meas_hash_algo, TPMI_ALG_HASH *tpm_hash)
{
    switch (meas_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        *tpm_hash = TPM2_ALG_SHA256;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        *tpm_hash = TPM2_ALG_SHA384;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        *tpm_hash = TPM2_ALG_SHA512;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        *tpm_hash = TPM2_ALG_SM3_256;
        return true;
    default:
        return false;
    }
}

bool libspdm_tpm_quote(
    const void *key_handle_str,
    uint32_t hash_algo,
    const uint8_t *pcr_indices,
    size_t pcr_count,
    const uint8_t *nonce,
    size_t nonce_size,
    void *quote_buffer,
    size_t *quote_buffer_size)
{
    TSS2_RC rc = 1;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR key_tr = ESYS_TR_NONE;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;
    uint32_t key_handle;
    TPMI_ALG_HASH tpm_hash;
    TPML_PCR_SELECTION pcr_selection;
    TPM2B_DATA qual_data;
    TPMT_SIG_SCHEME in_scheme;
    size_t required_size = 0;
    size_t offset = 0;
    size_t i;

    if (quote_buffer_size == NULL) {
        return false;
    }

    if (!map_spdm_meas_hash_to_tpm(hash_algo, &tpm_hash)) {
        return false;
    }

    key_handle = parse_tpm_key_handle(key_handle_str);
    if (key_handle == 0) {
        return false;
    }

    memset(&pcr_selection, 0, sizeof(pcr_selection));
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = tpm_hash;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;
    if (pcr_indices != NULL && pcr_count > 0) {
        for (i = 0; i < pcr_count; i++) {
            if (pcr_indices[i] < 24) {
                pcr_selection.pcrSelections[0].pcrSelect[pcr_indices[i] / 8] |=
                    (uint8_t)(1 << (pcr_indices[i] % 8));
            }
        }
    } else {
        pcr_selection.pcrSelections[0].pcrSelect[0] = 0x03; /* Default: PCR 0 and 1 */
    }

    memset(&qual_data, 0, sizeof(qual_data));
    if (nonce != NULL && nonce_size > 0) {
        qual_data.size = (UINT16)(nonce_size > sizeof(qual_data.buffer) ?
                                  sizeof(qual_data.buffer) : nonce_size);
        memcpy(qual_data.buffer, nonce, qual_data.size);
    }

    in_scheme.scheme = TPM2_ALG_NULL;

    rc = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_TR_FromTPMPublic(esys, key_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &key_tr);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_Quote(
        esys,
        key_tr,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &qual_data,
        &in_scheme,
        &pcr_selection,
        &quoted,
        &signature);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    /* Compute total required size */
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, NULL, 0, &required_size);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, NULL, 0, &required_size);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    if (quote_buffer == NULL || *quote_buffer_size < required_size) {
        *quote_buffer_size = required_size;
        rc = 1; /* Buffer insufficient or size query */
        goto out;
    }

    offset = 0;
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, (uint8_t *)quote_buffer, *quote_buffer_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, (uint8_t *)quote_buffer, *quote_buffer_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    *quote_buffer_size = offset;
    rc = TSS2_RC_SUCCESS;

out:
    if (quoted != NULL) {
        Esys_Free(quoted);
    }
    if (signature != NULL) {
        Esys_Free(signature);
    }
    if (key_tr != ESYS_TR_NONE) {
        Esys_TR_Close(esys, &key_tr);
    }
    if (esys != NULL) {
        Esys_Finalize(&esys);
    }
    if (tcti != NULL) {
        Tss2_TctiLdr_Finalize(&tcti);
    }

    return (rc == TSS2_RC_SUCCESS);
}

static uint32_t map_tpm_hash_to_base_hash(TPMI_ALG_HASH tpm_hash)
{
    switch (tpm_hash) {
    case TPM2_ALG_SHA256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    case TPM2_ALG_SHA384:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    case TPM2_ALG_SHA512:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
    case TPM2_ALG_SM3_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    default:
        return 0;
    }
}

bool libspdm_tpm_verify_quote(
    const void *pub_key_context,
    uint32_t base_asym_algo,
    uint32_t hash_algo,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size)
{
    TSS2_RC rc;
    TPM2B_ATTEST attest;
    TPMS_ATTEST tpms_attest;
    TPMT_SIGNATURE sig;
    size_t offset = 0;
    size_t attest_offset = 0;
    uint8_t hash_digest[64];
    size_t hash_size = 0;
    uint8_t raw_sig[64];

    if (pub_key_context == NULL || quote_buffer == NULL || quote_buffer_size == 0) {
        return false;
    }

    const uint8_t *raw_buf = (const uint8_t *)quote_buffer;
    size_t raw_size = quote_buffer_size;

    /* Check if quote_buffer is wrapped in SPDM Format 1 General Opaque Data Table */
    if (quote_buffer_size >= sizeof(spdm_general_opaque_data_table_header_t) +
        sizeof(opaque_element_table_header_t) + 4) {
        const spdm_general_opaque_data_table_header_t *tbl =
            (const spdm_general_opaque_data_table_header_t *)quote_buffer;
        if (tbl->total_elements >= 1 &&
            tbl->reserved[0] == 0 && tbl->reserved[1] == 0 && tbl->reserved[2] == 0) {
            const opaque_element_table_header_t *elem =
                (const opaque_element_table_header_t *)(tbl + 1);
            if (elem->id == SPDM_REGISTRY_ID_TCG) {
                const uint8_t *p = (const uint8_t *)(elem + 1) + elem->vendor_len;
                uint16_t elem_data_len = (uint16_t)(p[0] | (p[1] << 8));
                p += sizeof(uint16_t);
                if ((size_t)(p - (const uint8_t *)quote_buffer) + elem_data_len <= quote_buffer_size) {
                    raw_buf = p;
                    raw_size = elem_data_len;
                }
            }
        }
    }

    /* Unmarshal TPM2B_ATTEST */
    rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(raw_buf, raw_size, &offset, &attest);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    /* Unmarshal TPMT_SIGNATURE */
    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(raw_buf, raw_size, &offset, &sig);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    /* Parse inner TPMS_ATTEST to check magic, type, and nonce */
    rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest.attestationData, attest.size, &attest_offset, &tpms_attest);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    if (tpms_attest.magic != TPM2_GENERATED_VALUE) {
        return false;
    }
    if (tpms_attest.type != TPM2_ST_ATTEST_QUOTE) {
        return false;
    }

    if (expected_nonce != NULL && expected_nonce_size > 0) {
        if (tpms_attest.extraData.size != expected_nonce_size ||
            memcmp(tpms_attest.extraData.buffer, expected_nonce, expected_nonce_size) != 0) {
            return false;
        }
    }

    TPMI_ALG_HASH tpm_sig_hash = TPM2_ALG_NULL;
    if (sig.sigAlg == TPM2_ALG_ECDSA) {
        tpm_sig_hash = sig.signature.ecdsa.hash;
    } else if (sig.sigAlg == TPM2_ALG_RSASSA) {
        tpm_sig_hash = sig.signature.rsassa.hash;
    } else if (sig.sigAlg == TPM2_ALG_RSAPSS) {
        tpm_sig_hash = sig.signature.rsapss.hash;
    } else {
        return false;
    }

    /* If caller specified hash_algo, verify that it matches signature hash */
    if (hash_algo != 0) {
        TPMI_ALG_HASH expected_tpm_hash;
        if (map_spdm_meas_hash_to_tpm(hash_algo, &expected_tpm_hash)) {
            if (tpm_sig_hash != expected_tpm_hash) {
                return false;
            }
        }
    }

    uint32_t base_hash = map_tpm_hash_to_base_hash(tpm_sig_hash);
    if (base_hash == 0) {
        return false;
    }

    hash_size = libspdm_get_hash_size(base_hash);
    if (hash_size == 0 || hash_size > sizeof(hash_digest)) {
        return false;
    }

    if (!libspdm_hash_all(base_hash, attest.attestationData, attest.size, hash_digest)) {
        return false;
    }

    /* Extract signature according to algorithm.
     * Use spdm_version=0 so libspdm_asym_verify_hash verifies raw message_hash
     * directly without prepending the SPDM 1.2 signing context prefix. */
    if (sig.sigAlg == TPM2_ALG_ECDSA) {
        memset(raw_sig, 0, sizeof(raw_sig));
        if (sig.signature.ecdsa.signatureR.size <= 32) {
            memcpy(raw_sig + 32 - sig.signature.ecdsa.signatureR.size,
                   sig.signature.ecdsa.signatureR.buffer,
                   sig.signature.ecdsa.signatureR.size);
        } else if (sig.signature.ecdsa.signatureR.size == 33 && sig.signature.ecdsa.signatureR.buffer[0] == 0) {
            memcpy(raw_sig, sig.signature.ecdsa.signatureR.buffer + 1, 32);
        } else {
            return false;
        }

        if (sig.signature.ecdsa.signatureS.size <= 32) {
            memcpy(raw_sig + 64 - sig.signature.ecdsa.signatureS.size,
                   sig.signature.ecdsa.signatureS.buffer,
                   sig.signature.ecdsa.signatureS.size);
        } else if (sig.signature.ecdsa.signatureS.size == 33 && sig.signature.ecdsa.signatureS.buffer[0] == 0) {
            memcpy(raw_sig + 32, sig.signature.ecdsa.signatureS.buffer + 1, 32);
        } else {
            return false;
        }

        return libspdm_asym_verify_hash(
            0, 0,
            base_asym_algo, base_hash,
            (void *)pub_key_context,
            hash_digest, hash_size,
            raw_sig, sizeof(raw_sig));
    } else if (sig.sigAlg == TPM2_ALG_RSASSA || sig.sigAlg == TPM2_ALG_RSAPSS) {
        return libspdm_asym_verify_hash(
            0, 0,
            base_asym_algo, base_hash,
            (void *)pub_key_context,
            hash_digest, hash_size,
            sig.signature.rsassa.sig.buffer,
            sig.signature.rsassa.sig.size);
    }

    return false;
}
