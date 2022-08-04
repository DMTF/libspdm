/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Elliptic Curve Wrapper Implementation.
 *
 * RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
 * FIPS 186-4 - Digital signature Standard (DSS)
 **/

#include "internal_crypt_lib.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

/* Max local buffer for internal use, make sure the buffer size can fit the largest DER sig. */
#define MAX_EC_BUFFER_SIZE  140 //(66 * 2 + 8)

/**
 * Allocates and Initializes one Elliptic Curve context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Elliptic Curve context that has been initialized.
 *         If the allocations fails, libspdm_ec_new_by_nid() returns NULL.
 *
 **/
void *libspdm_ec_new_by_nid(uintn nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    int32_t openssl_nid;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_SECP256R1:
        openssl_nid = NID_X9_62_prime256v1;
        break;
    case LIBSPDM_CRYPTO_NID_SECP384R1:
        openssl_nid = NID_secp384r1;
        break;
    case LIBSPDM_CRYPTO_NID_SECP521R1:
        openssl_nid = NID_secp521r1;
        break;
    default:
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_paramgen_init(pkey_ctx) != 1) {
        goto fail;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, openssl_nid) != 1) {
        goto fail;
    }

    pkey = NULL;
    if (EVP_PKEY_paramgen(pkey_ctx, &pkey) != 1) {
        pkey = NULL;
        goto fail;
    }

fail:
    EVP_PKEY_CTX_free(pkey_ctx);
    return (void *)pkey;
}

/**
 * Release the specified EC context.
 *
 * @param[in]  ec_context  Pointer to the EC context to be released.
 *
 **/
void libspdm_ec_free(void *ec_context)
{
    EVP_PKEY_free((EVP_PKEY *)ec_context);
}

/**
 * Sets the public key component into the established EC context.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to EC context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   EC public key component was set successfully.
 * @retval  false  Invalid EC public key component.
 *
 **/
bool libspdm_ec_set_pub_key(void *ec_context, const uint8_t *public_key,
                            uintn public_key_size)
{
    EVP_PKEY *pkey;
    uint8_t public_oct[MAX_EC_BUFFER_SIZE];
    uintn half_size;

    if (ec_context == NULL || public_key == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)ec_context;
    half_size = (EVP_PKEY_bits(pkey) + 7) / 8;
    if (public_key_size != half_size * 2) {
        return false;
    }

    /* convert raw key to octet key */
    public_oct[0] = POINT_CONVERSION_UNCOMPRESSED;
    libspdm_copy_mem(public_oct + 1, MAX_EC_BUFFER_SIZE - 1,
                     public_key, public_key_size);

    if (EVP_PKEY_set_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        public_oct, public_key_size + 1) != 1) {
        return false;
    }

    return true;
}

/**
 * Gets the public key component from the established EC context.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to EC context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   EC key component was retrieved successfully.
 * @retval  false  Invalid EC key component.
 *
 **/
bool libspdm_ec_get_pub_key(void *ec_context, uint8_t *public_key,
                            uintn *public_key_size)
{
    EVP_PKEY *pkey;
    bool ret_val;
    BIGNUM *bn_x;
    BIGNUM *bn_y;
    uintn half_size;
    intn x_size;
    intn y_size;

    if (ec_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    pkey = (EVP_PKEY *)ec_context;
    half_size = (EVP_PKEY_bits(pkey) + 7) / 8;
    if (*public_key_size < half_size * 2) {
        *public_key_size = half_size * 2;
        return false;
    }
    *public_key_size = half_size * 2;

    bn_x = NULL;
    bn_y = NULL;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y) != 1) {
        goto done;
    }

    x_size = BN_num_bytes(bn_x);
    y_size = BN_num_bytes(bn_y);
    if (x_size <= 0 || y_size <= 0) {
        ret_val = false;
        goto done;
    }
    LIBSPDM_ASSERT((uintn)x_size <= half_size && (uintn)y_size <= half_size);

    if (public_key != NULL) {
        libspdm_zero_mem(public_key, *public_key_size);
        BN_bn2bin(bn_x, &public_key[0 + half_size - x_size]);
        BN_bn2bin(bn_y, &public_key[half_size + half_size - y_size]);
    }
    ret_val = true;

done:
    if (bn_x != NULL) {
        BN_free(bn_x);
    }
    if (bn_y != NULL) {
        BN_free(bn_y);
    }
    return ret_val;
}

/**
 * Validates key components of EC context.
 * NOTE: This function performs integrity checks on all the EC key material, so
 *      the EC key structure must contain all the private key data.
 *
 * If ec_context is NULL, then return false.
 *
 * @param[in]  ec_context  Pointer to EC context to check.
 *
 * @retval  true   EC key components are valid.
 * @retval  false  EC key components are not valid.
 *
 **/
bool libspdm_ec_check_key(const void *ec_context)
{
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pkey_ctx;
    bool ret_val;

    if (ec_context == NULL) {
        return false;
    }

    pkey = ec_context;
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        return false;
    }

    ret_val = (bool) EVP_PKEY_public_check(pkey_ctx);

    EVP_PKEY_CTX_free(pkey_ctx);
    return ret_val;
}

/**
 * Generates EC key and returns EC public key (X, Y).
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * EC context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * If ec_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  ec_context      Pointer to the EC context.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   EC public X,Y generation succeeded.
 * @retval false  EC public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ec_generate_key(void *ec_context, uint8_t *public,
                             uintn *public_size)
{
    bool ret_val;
    EVP_PKEY *pkey;
    EVP_PKEY *gkey;
    EVP_PKEY_CTX *gkey_ctx;

    if (ec_context == NULL || public_size == NULL) {
        return false;
    }

    if (public == NULL && *public_size != 0) {
        return false;
    }

    gkey = EVP_PKEY_new();
    gkey_ctx = NULL;
    if (gkey == NULL) {
        return false;
    }

    ret_val = false;
    pkey = ec_context;

    if (EVP_PKEY_copy_parameters(gkey, pkey) != 1) {
        goto fail;
    }

    gkey_ctx = EVP_PKEY_CTX_new(gkey, NULL);
    if (gkey_ctx == NULL) {
        goto fail;
    }
    if (EVP_PKEY_keygen_init(gkey_ctx) != 1) {
        goto fail;
    }

    if (EVP_PKEY_keygen(gkey_ctx, &pkey) != 1) {
        goto fail;
    }

    if (libspdm_ec_get_pub_key(pkey, public, public_size) != true) {
        goto fail;
    }

    ret_val = true;
fail:
    EVP_PKEY_free(gkey);
    EVP_PKEY_CTX_free(gkey_ctx);
    return ret_val;
}

/**
 * Computes exchanged common key.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 * X is the first half of peer_public with size being peer_public_size / 2,
 * Y is the second half of peer_public with size being peer_public_size / 2.
 *
 * If ec_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 *
 * For P-256, the peer_public_size is 64. first 32-byte is X, second 32-byte is Y. The key_size is 32.
 * For P-384, the peer_public_size is 96. first 48-byte is X, second 48-byte is Y. The key_size is 48.
 * For P-521, the peer_public_size is 132. first 66-byte is X, second 66-byte is Y. The key_size is 66.
 *
 * @param[in, out]  ec_context          Pointer to the EC context.
 * @param[in]       peer_public         Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size     size of peer's public X,Y in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                    On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   EC exchanged key generation succeeded.
 * @retval false  EC exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
bool libspdm_ec_compute_key(void *ec_context, const uint8_t *peer_public,
                            uintn peer_public_size, uint8_t *key,
                            uintn *key_size)
{
    bool ret_val;
    EVP_PKEY *pkey;
    EVP_PKEY *peer_pkey;
    EVP_PKEY_CTX *pkey_ctx;
    uintn secret_size;

    if (ec_context == NULL || peer_public == NULL || key_size == NULL) {
        return false;
    }

    if (peer_public_size > INT_MAX) {
        return false;
    }

    if (key == NULL && *key_size != 0) {
        return false;
    }

    peer_pkey = EVP_PKEY_new();
    if (peer_pkey == NULL) {
        return false;
    }

    ret_val = false;
    pkey = (EVP_PKEY *)ec_context;
    pkey_ctx = NULL;
    if (EVP_PKEY_copy_parameters(peer_pkey, pkey) != 1) {
        goto fail;
    }

    if (libspdm_ec_set_pub_key(peer_pkey, peer_public, peer_public_size) != true) {
        goto fail;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        goto fail;
    }

    if ((EVP_PKEY_derive_init(pkey_ctx) != 1) ||
        (EVP_PKEY_derive_set_peer(pkey_ctx, peer_pkey) != 1) ||
        (EVP_PKEY_derive(pkey_ctx, NULL, &secret_size) != 1)) {
        goto fail;
    }

    if (*key_size < secret_size) {
        *key_size = secret_size;
        goto fail;
    }
    *key_size = secret_size;

    if (EVP_PKEY_derive(pkey_ctx, key, key_size) != 1) {
        goto fail;
    }

    ret_val = true;
fail:
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret_val;
}

/**
 * Carries out the EC-DSA signature.
 *
 * This function carries out the EC-DSA signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If ec_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
 * For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.
 *
 * @param[in]       ec_context    Pointer to EC context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive EC-DSA signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in EC-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_ecdsa_sign(void *ec_context, uintn hash_nid,
                        const uint8_t *message_hash, uintn hash_size,
                        uint8_t *signature, uintn *sig_size)
{
    bool ret_val;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx;
    uintn half_size;
    ECDSA_SIG *ecdsa_sig;
    uint8_t sig_der[MAX_EC_BUFFER_SIZE];
    const uint8_t *sig_der_head;
    uintn sig_der_size;
    BIGNUM *bn_r;
    BIGNUM *bn_s;
    int r_size;
    int s_size;

    if (ec_context == NULL || message_hash == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = ec_context;
    half_size = (EVP_PKEY_bits(pkey) + 7) / 8;

    if (*sig_size < half_size * 2) {
        *sig_size = half_size * 2;
        return false;
    }
    *sig_size = half_size * 2;
    libspdm_zero_mem(signature, *sig_size);

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        return false;
    }

    ret_val = false;
    pkey = (EVP_PKEY *)ec_context;
    sig_der_size = MAX_EC_BUFFER_SIZE;
    if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) != 1) {
        goto fail;
    }
    if (EVP_DigestSign(mctx, sig_der, &sig_der_size, message_hash, hash_size) != 1) {
        goto fail;
    }

    ecdsa_sig = ECDSA_SIG_new();
    sig_der_head = sig_der;
    if (d2i_ECDSA_SIG(&ecdsa_sig, &sig_der_head, sig_der_size) == NULL) {
        goto fail;
    }

    ECDSA_SIG_get0(ecdsa_sig, (const BIGNUM **)&bn_r,
                   (const BIGNUM **)&bn_s);

    r_size = BN_num_bytes(bn_r);
    s_size = BN_num_bytes(bn_s);
    if (r_size <= 0 || s_size <= 0) {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }
    LIBSPDM_ASSERT((uintn)r_size <= half_size && (uintn)s_size <= half_size);

    BN_bn2bin(bn_r, &signature[0 + half_size - r_size]);
    BN_bn2bin(bn_s, &signature[half_size + half_size - s_size]);

    ECDSA_SIG_free(ecdsa_sig);

    ret_val = true;
fail:
    EVP_MD_CTX_free(mctx);
    return ret_val;
}

/**
 * Verifies the EC-DSA signature.
 *
 * If ec_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
 * For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.
 *
 * @param[in]  ec_context    Pointer to EC context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to EC-DSA signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in EC-DSA.
 * @retval  false  Invalid signature or invalid EC context.
 *
 **/
bool libspdm_ecdsa_verify(void *ec_context, uintn hash_nid,
                          const uint8_t *message_hash, uintn hash_size,
                          const uint8_t *signature, uintn sig_size)
{
    bool ret_val;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx;
    uintn half_size;
    ECDSA_SIG *ecdsa_sig;
    uint8_t sig_der[MAX_EC_BUFFER_SIZE];
    uint8_t *sig_der_head;
    uintn sig_der_size;
    BIGNUM *bn_r;
    BIGNUM *bn_s;

    if (ec_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    pkey = ec_context;
    half_size = (EVP_PKEY_bits(pkey) + 7) / 8;
    if (sig_size != half_size * 2) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;
    default:
        return false;
    }

    ret_val = false;
    ecdsa_sig = ECDSA_SIG_new();
    mctx = EVP_MD_CTX_new();
    bn_r = BN_bin2bn(signature, (uint32_t)half_size, NULL);
    bn_s = BN_bin2bn(signature + half_size, (uint32_t)half_size, NULL);
    if (ecdsa_sig == NULL || mctx == NULL || bn_r == NULL || bn_s == NULL) {
        BN_free(bn_r);
        BN_free(bn_s);
        goto fail;
    }

    ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s);
    sig_der_head = sig_der;
    sig_der_size = i2d_ECDSA_SIG(ecdsa_sig, &sig_der_head);
    if (sig_der_size < 0) {
        goto fail;
    }

    if (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey) != 1) {
        goto fail;
    }
    if (EVP_DigestVerify(mctx, sig_der, sig_der_size, message_hash, hash_size) != 1) {
        goto fail;
    }

    ret_val = true;

fail:
    ECDSA_SIG_free(ecdsa_sig);
    EVP_MD_CTX_free(mctx);
    return ret_val;
}
