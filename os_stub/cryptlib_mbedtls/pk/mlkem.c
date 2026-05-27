/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"
#include "library/spdm_crypt_lib.h"

#if LIBSPDM_ML_KEM_SUPPORT

#ifndef IPPCP_PREVIEW_ML_KEM
#define IPPCP_PREVIEW_ML_KEM
#endif
#include <ippcp.h>

typedef struct {
    IppsMLKEMParamSet param_set;
    IppsMLKEMInfo info;
    IppsMLKEMState *state;
    uint8_t *decap_key;
    bool has_decap_key;
} libspdm_mlkem_context;

typedef struct {
    const uint8_t *entropy;
    size_t entropy_size;
    size_t entropy_offset;
} libspdm_mlkem_entropy_context;

static bool libspdm_mlkem_nid_to_param_set(size_t nid, IppsMLKEMParamSet *param_set)
{
    if (param_set == NULL) {
        return false;
    }

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        *param_set = IPPCP_ML_KEM_512;
        return true;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        *param_set = IPPCP_ML_KEM_768;
        return true;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        *param_set = IPPCP_ML_KEM_1024;
        return true;
    default:
        return false;
    }
}

static IppStatus IPP_CALL libspdm_ippcp_bit_supplier(Ipp32u *p_rand, int n_bits,
                                                     void *p_ebs_params)
{
    size_t rand_size;
    uint8_t *rand_bytes;

    (void)p_ebs_params;

    if ((p_rand == NULL) || (n_bits <= 0)) {
        return ippStsErr;
    }

    rand_bytes = (uint8_t *)p_rand;
    rand_size = (size_t)(n_bits + 7) / 8;
    if (!libspdm_get_random_number(rand_size, rand_bytes)) {
        return ippStsErr;
    }

    if ((n_bits & 0x7) != 0) {
        rand_bytes[rand_size - 1] &= (uint8_t)((1u << (n_bits & 0x7)) - 1u);
    }

    return ippStsNoErr;
}

static IppStatus IPP_CALL libspdm_ippcp_entropy_supplier(Ipp32u *p_rand,
                                                         int n_bits,
                                                         void *p_ebs_params)
{
    libspdm_mlkem_entropy_context *entropy_context;
    size_t rand_size;
    uint8_t *rand_bytes;

    if ((p_rand == NULL) || (n_bits <= 0) || (p_ebs_params == NULL)) {
        return ippStsErr;
    }

    entropy_context = (libspdm_mlkem_entropy_context *)p_ebs_params;
    if (entropy_context->entropy == NULL) {
        return ippStsErr;
    }

    rand_bytes = (uint8_t *)p_rand;
    rand_size = (size_t)(n_bits + 7) / 8;
    if (entropy_context->entropy_offset + rand_size > entropy_context->entropy_size) {
        return ippStsErr;
    }

    libspdm_copy_mem(rand_bytes, rand_size,
                     entropy_context->entropy + entropy_context->entropy_offset,
                     rand_size);
    entropy_context->entropy_offset += rand_size;

    if ((n_bits & 0x7) != 0) {
        rand_bytes[rand_size - 1] &= (uint8_t)((1u << (n_bits & 0x7)) - 1u);
    }

    return ippStsNoErr;
}

static void libspdm_mlkem_free_internal(libspdm_mlkem_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->decap_key != NULL) {
        libspdm_zero_mem(ctx->decap_key, (size_t)ctx->info.decapsKeySize);
        free_pool(ctx->decap_key);
    }
    if (ctx->state != NULL) {
        free_pool(ctx->state);
    }
    libspdm_zero_mem(ctx, sizeof(*ctx));
    free_pool(ctx);
}

static uint8_t *libspdm_mlkem_alloc_scratch_keygen(libspdm_mlkem_context *ctx)
{
    int scratch_size;

    if ((ctx == NULL) || (ctx->state == NULL)) {
        return NULL;
    }
    if (ippsMLKEM_KeyGenBufferGetSize(&scratch_size, ctx->state) != ippStsNoErr) {
        return NULL;
    }

    return (uint8_t *)allocate_pool((size_t)scratch_size);
}

static uint8_t *libspdm_mlkem_alloc_scratch_encaps(libspdm_mlkem_context *ctx)
{
    int scratch_size;

    if ((ctx == NULL) || (ctx->state == NULL)) {
        return NULL;
    }
    if (ippsMLKEM_EncapsBufferGetSize(&scratch_size, ctx->state) != ippStsNoErr) {
        return NULL;
    }

    return (uint8_t *)allocate_pool((size_t)scratch_size);
}

static uint8_t *libspdm_mlkem_alloc_scratch_decaps(libspdm_mlkem_context *ctx)
{
    int scratch_size;

    if ((ctx == NULL) || (ctx->state == NULL)) {
        return NULL;
    }
    if (ippsMLKEM_DecapsBufferGetSize(&scratch_size, ctx->state) != ippStsNoErr) {
        return NULL;
    }

    return (uint8_t *)allocate_pool((size_t)scratch_size);
}

/**
 * Allocates and initializes one KEM context for subsequent use with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the KEM context that has been initialized.
 **/
void *libspdm_mlkem_new_by_name(size_t nid)
{
    libspdm_mlkem_context *ctx;
    int state_size;

    ctx = allocate_zero_pool(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    if (!libspdm_mlkem_nid_to_param_set(nid, &ctx->param_set)) {
        goto error;
    }

    if (ippsMLKEM_GetInfo(&ctx->info, ctx->param_set) != ippStsNoErr) {
        goto error;
    }
    if ((ctx->info.encapsKeySize <= 0) || (ctx->info.decapsKeySize <= 0) ||
        (ctx->info.cipherTextSize <= 0) || (ctx->info.sharedSecretSize <= 0)) {
        goto error;
    }

    if (ippsMLKEM_GetSize(&state_size, ctx->param_set) != ippStsNoErr) {
        goto error;
    }
    if (state_size <= 0) {
        goto error;
    }

    ctx->state = (IppsMLKEMState *)allocate_zero_pool((size_t)state_size);
    if (ctx->state == NULL) {
        goto error;
    }
    if (ippsMLKEM_Init(ctx->state, ctx->param_set) != ippStsNoErr) {
        goto error;
    }

    ctx->decap_key = (uint8_t *)allocate_zero_pool((size_t)ctx->info.decapsKeySize);
    if (ctx->decap_key == NULL) {
        goto error;
    }

    ctx->has_decap_key = false;
    return ctx;

error:
    libspdm_mlkem_free_internal(ctx);
    return NULL;
}

/**
 * Release the specified KEM context.
 *
 * @param[in]  kem_context  Pointer to the KEM context to be released.
 **/
void libspdm_mlkem_free(void *kem_context)
{
    libspdm_mlkem_free_internal((libspdm_mlkem_context *)kem_context);
}

/**
 * Generates KEM public key.
 *
 * @param[in, out]  kem_context       Pointer to the KEM context.
 * @param[out]      encap_key        Pointer to the buffer to receive generated public key.
 * @param[in, out]  encap_key_size   On input, the size of public_key buffer in bytes.
 *                                   On output, the size of data returned in public_key buffer in
 *                                   bytes.
 *
 * @retval true   KEM public key generation succeeded.
 * @retval false  KEM public key generation failed.
 * @retval false  public_key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_generate_key(void *kem_context, uint8_t *encap_key, size_t *encap_key_size)
{
    libspdm_mlkem_context *ctx;
    uint8_t *scratch;
    size_t required_size;
    IppStatus status;

    if ((kem_context == NULL) || (encap_key == NULL) || (encap_key_size == NULL)) {
        return false;
    }

    ctx = (libspdm_mlkem_context *)kem_context;
    required_size = (size_t)ctx->info.encapsKeySize;
    if (*encap_key_size < required_size) {
        *encap_key_size = required_size;
        return false;
    }

    scratch = libspdm_mlkem_alloc_scratch_keygen(ctx);
    if (scratch == NULL) {
        return false;
    }

    status = ippsMLKEM_KeyGen(encap_key, ctx->decap_key, ctx->state,
                              scratch, libspdm_ippcp_bit_supplier, NULL);
    free_pool(scratch);
    if (status != ippStsNoErr) {
        return false;
    }

    ctx->has_decap_key = true;
    *encap_key_size = required_size;
    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_encapsulate(void *kem_context, const uint8_t *peer_encap_key,
                               size_t peer_encap_key_size, uint8_t *cipher_text,
                               size_t *cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    libspdm_mlkem_context *ctx;
    uint8_t *scratch;
    size_t required_cipher_text_size;
    size_t required_shared_secret_size;
    IppStatus status;

    if ((kem_context == NULL) || (peer_encap_key == NULL) || (cipher_text == NULL) ||
        (cipher_text_size == NULL) || (shared_secret == NULL) ||
        (shared_secret_size == NULL)) {
        return false;
    }

    ctx = (libspdm_mlkem_context *)kem_context;
    if (peer_encap_key_size != (size_t)ctx->info.encapsKeySize) {
        return false;
    }

    required_cipher_text_size = (size_t)ctx->info.cipherTextSize;
    required_shared_secret_size = (size_t)ctx->info.sharedSecretSize;
    if (*cipher_text_size < required_cipher_text_size) {
        *cipher_text_size = required_cipher_text_size;
        return false;
    }
    if (*shared_secret_size < required_shared_secret_size) {
        *shared_secret_size = required_shared_secret_size;
        return false;
    }

    scratch = libspdm_mlkem_alloc_scratch_encaps(ctx);
    if (scratch == NULL) {
        return false;
    }

    status = ippsMLKEM_Encaps(peer_encap_key, cipher_text, shared_secret,
                              ctx->state, scratch,
                              libspdm_ippcp_bit_supplier, NULL);
    free_pool(scratch);
    if (status != ippStsNoErr) {
        return false;
    }

    *cipher_text_size = required_cipher_text_size;
    *shared_secret_size = required_shared_secret_size;
    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                               size_t peer_cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    libspdm_mlkem_context *ctx;
    uint8_t *scratch;
    size_t required_shared_secret_size;
    IppStatus status;

    if ((kem_context == NULL) || (peer_cipher_text == NULL) ||
        (shared_secret == NULL) || (shared_secret_size == NULL)) {
        return false;
    }

    ctx = (libspdm_mlkem_context *)kem_context;
    if (!ctx->has_decap_key) {
        return false;
    }
    if (peer_cipher_text_size != (size_t)ctx->info.cipherTextSize) {
        return false;
    }

    required_shared_secret_size = (size_t)ctx->info.sharedSecretSize;
    if (*shared_secret_size < required_shared_secret_size) {
        *shared_secret_size = required_shared_secret_size;
        return false;
    }

    scratch = libspdm_mlkem_alloc_scratch_decaps(ctx);
    if (scratch == NULL) {
        return false;
    }

    status = ippsMLKEM_Decaps(ctx->decap_key, peer_cipher_text,
                              shared_secret, ctx->state, scratch);
    free_pool(scratch);
    if (status != ippStsNoErr) {
        return false;
    }

    *shared_secret_size = required_shared_secret_size;
    return true;
}

#ifdef LIBSPDM_FIPS_MODE
/**
 * Computes exchanged common key. This API can be used for FIPS test.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      cipher_text           Pointer to the buffer to receive cipher text.
 * @param[in, out]  cipher_text_size      On input, the size of cipher text buffer in bytes.
 *                                        On output, the size of data returned in cipher text buffer in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared secret buffer in bytes.
 *                                        On output, the size of data returned in shared secret buffer in bytes.
 * @param[in]       entropy               Pointer to the buffer to receive entropy.
 * @param[in]       entropy_size          size of entropy buffer in bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  cipher_text_size is not large enough.
 * @retval false  shared_secret_size is not large enough.
 * @retval false  entropy_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_encapsulate_ex(void *kem_context, const uint8_t *peer_encap_key,
                                  size_t peer_encap_key_size, uint8_t *cipher_text,
                                  size_t *cipher_text_size, uint8_t *shared_secret,
                                  size_t *shared_secret_size, uint8_t *entropy,
                                  size_t entropy_size)
{
    libspdm_mlkem_context *ctx;
    uint8_t *scratch;
    size_t required_cipher_text_size;
    size_t required_shared_secret_size;
    IppStatus status;
    libspdm_mlkem_entropy_context entropy_context;

    if ((kem_context == NULL) || (peer_encap_key == NULL) || (cipher_text == NULL) ||
        (cipher_text_size == NULL) || (shared_secret == NULL) ||
        (shared_secret_size == NULL)) {
        return false;
    }

    if ((entropy == NULL) && (entropy_size == 0)) {
        return libspdm_mlkem_encapsulate(kem_context, peer_encap_key,
                                         peer_encap_key_size,
                                         cipher_text, cipher_text_size,
                                         shared_secret, shared_secret_size);
    }

    /* Align FIPS test contract with the OpenSSL backend: deterministic IKME is 32 bytes. */
    if ((entropy == NULL) || (entropy_size != 32)) {
        return false;
    }

    ctx = (libspdm_mlkem_context *)kem_context;
    if (peer_encap_key_size != (size_t)ctx->info.encapsKeySize) {
        return false;
    }

    required_cipher_text_size = (size_t)ctx->info.cipherTextSize;
    required_shared_secret_size = (size_t)ctx->info.sharedSecretSize;
    if (*cipher_text_size < required_cipher_text_size) {
        *cipher_text_size = required_cipher_text_size;
        return false;
    }
    if (*shared_secret_size < required_shared_secret_size) {
        *shared_secret_size = required_shared_secret_size;
        return false;
    }

    scratch = libspdm_mlkem_alloc_scratch_encaps(ctx);
    if (scratch == NULL) {
        return false;
    }

    entropy_context.entropy = entropy;
    entropy_context.entropy_size = entropy_size;
    entropy_context.entropy_offset = 0;
    status = ippsMLKEM_Encaps(peer_encap_key, cipher_text, shared_secret,
                              ctx->state, scratch,
                              libspdm_ippcp_entropy_supplier, &entropy_context);
    free_pool(scratch);
    if (status != ippStsNoErr) {
        return false;
    }

    *cipher_text_size = required_cipher_text_size;
    *shared_secret_size = required_shared_secret_size;
    return true;
}

/**
 * Sets the key component into the established KEM context.
 *
 * @param[in, out]  dsa_context  Pointer to KEM context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   KEM key component was set successfully.
 **/
bool libspdm_mlkem_set_privkey(void *kem_context, const uint8_t *key_data, size_t key_size)
{
    libspdm_mlkem_context *ctx;

    if ((kem_context == NULL) || (key_data == NULL)) {
        return false;
    }

    ctx = (libspdm_mlkem_context *)kem_context;
    if (key_size != (size_t)ctx->info.decapsKeySize) {
        return false;
    }

    libspdm_copy_mem(ctx->decap_key, (size_t)ctx->info.decapsKeySize,
                     key_data, key_size);
    ctx->has_decap_key = true;
    return true;
}
#endif /* LIBSPDM_FIPS_MODE */
#endif /* LIBSPDM_ML_KEM_SUPPORT */
