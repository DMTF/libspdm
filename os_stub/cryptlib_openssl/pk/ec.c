/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Elliptic Curve Wrapper Implementation.
 *
 * RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
 * FIPS 186-4 - Digital signature Standard (DSS)
 **/

#include "base.h"
#include "internal_crypt_lib.h"
#include "library/memlib.h"
#include "openssl/params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include <crypto/evp.h>
#include <string.h>

#define MAX_CURVE_BYTES 66 /* P-521 */
#define MAX_KEY_SIZE 66 * 2 + 1 /* One extra byte for EVP_PKEY compression format */

/* MAX_DER_SIGN_SIZE = (MAX_CURVE_BYTES + SEQ_HEADER) X 2 + PADDING
 * SEQ_HEADER = <TAG> <FORM> <LEN>
 * TAG = 0x30
 * FORM = 0x81 (size total content size is > 127 so using long form)
 * LEN = Content Size = 138 for P-521
 */
#define MAX_DER_SIGN_SIZE (MAX_CURVE_BYTES + 3) * 2 + 6

static bool raw_to_der_signature(const unsigned char *raw_sig, size_t raw_len,
                                 unsigned char *der_sig, size_t *der_len);

static bool der_to_raw_rs(const uint8_t *der_sig, size_t der_sig_len,
                          uint8_t *out_raw, size_t expected_half_size);

static EVP_PKEY *import_peer_pubkey(const char* curve_name, const unsigned char *pub, size_t pub_len);

static void get_evp_compatible_public_key(EVP_PKEY *evp_pkey,
                                          const uint8_t *public_key, size_t public_key_size,
                                          uint8_t *compatible_key, size_t *comptable_key_size);

/**
 * Half size of EC component of EVP_PKEY without
 * using EC API.
 *
 * Curve                Size Bits                Half Size
 * secp256r1            256 bits                  32
 * secp384r1            384 bits                  48
 * secp521r1            521 bits                  66
 */
static inline int evp_pkey_get_half_size(EVP_PKEY *evp_pkey) {
    switch (EVP_PKEY_bits(evp_pkey)) {
    case 256:
        return 32;
    case 384:
        return 48;
    case 521:
        return 66;
    default:
        return -1;
    }
}

static inline const char* evp_pkey_get_curve_name(EVP_PKEY *evp_pkey) {
    switch (EVP_PKEY_bits(evp_pkey)) {
    case 256:
        return "prime256v1";
    case 384:
        return "secp384r1";
    case 521:
        return "secp521r1";
    default:
        return NULL;
    }
}

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
void *libspdm_ec_new_by_nid(size_t nid)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM params[2];
    const char* curve_name;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_SECP256R1:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256:
        curve_name = "prime256v1";
        break;
    case LIBSPDM_CRYPTO_NID_SECP384R1:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384:
        curve_name = "secp384r1";
        break;
    case LIBSPDM_CRYPTO_NID_SECP521R1:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521:
        curve_name = "secp521r1";
        break;
    default:
        return NULL;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *) curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        goto cleanup;
    }

cleanup:
    EVP_PKEY_CTX_free(pctx);

    return pkey;
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
                            size_t public_key_size)
{
    bool result = false;
    EVP_PKEY *evp_pkey;
    EVP_PKEY_CTX *ctx;
    OSSL_PARAM params[3];
    uint8_t compatible_key[MAX_KEY_SIZE];
    size_t compatible_key_size = 0;

    evp_pkey = (EVP_PKEY *) ec_context;
    if (EVP_PKEY_get_base_id(evp_pkey) != EVP_PKEY_EC) {
        return false;
    }

    get_evp_compatible_public_key(evp_pkey, public_key, public_key_size,
                                  compatible_key, &compatible_key_size);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *) evp_pkey_get_curve_name(evp_pkey),
                                                 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *) compatible_key,
                                                  compatible_key_size);
    params[2] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        return false;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        goto cleanup_ctx;
    }

    EVP_PKEY *new_evp_pkey = NULL;
    if (EVP_PKEY_fromdata(ctx, &new_evp_pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        goto cleanup_ctx;
    }

    if (evp_pkey_copy_downgraded(&evp_pkey, new_evp_pkey) == 1) {
        result = true;
    }
    EVP_PKEY_free(new_evp_pkey);

cleanup_ctx:
    EVP_PKEY_CTX_free(ctx);

    return result;
}

/**
 * Sets the private key component into the established EC context.
 *
 * For P-256, the private_key_size is 32 byte.
 * For P-384, the private_key_size is 48 byte.
 * For P-521, the private_key_size is 66 byte.
 *
 * @param[in, out]  ec_context       Pointer to EC context being set.
 * @param[in]       private_key      Pointer to the private key buffer.
 * @param[in]       private_key_size The size of private key buffer in bytes.
 *
 * @retval  true   EC private key component was set successfully.
 * @retval  false  Invalid EC private key component.
 *
 **/
bool libspdm_ec_set_priv_key(void *ec_context, const uint8_t *private_key,
                             size_t private_key_size)
{
    EVP_PKEY *evp_pkey;
    EC_KEY *ec_key = NULL;
    bool ret_val;
    BIGNUM * priv_key;
    size_t half_size;

    if (ec_context == NULL || private_key == NULL) {
        return false;
    }

    evp_pkey = (EVP_PKEY *) ec_context;
    ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
    half_size = evp_pkey_get_half_size(evp_pkey);
    if (private_key_size != half_size) {
        return false;
    }

    priv_key = BN_bin2bn(private_key, private_key_size, NULL);
    if (priv_key == NULL) {
        ret_val = false;
        goto done;
    }
    ret_val = (bool)EC_KEY_set_private_key(ec_key, priv_key);
    if (!ret_val) {
        goto done;
    }

    if (!EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key)) {
        goto done;
    }
    ec_key = NULL;
    ret_val = true;

done:
    if (priv_key != NULL) {
        BN_free(priv_key);
    }
    return ret_val;
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
                            size_t *public_key_size)
{
    EVP_PKEY *evp_pkey;
    uint8_t buffer[MAX_KEY_SIZE];
    size_t len = 0;

    if (ec_context == NULL || public_key == NULL ||
        public_key_size == NULL) {
        return false;
    }

    evp_pkey = (EVP_PKEY *)ec_context;
    if (EVP_PKEY_get_octet_string_param(evp_pkey, OSSL_PKEY_PARAM_PUB_KEY, buffer, sizeof(buffer), &len) <= 0) {
        return false;
    }

    /* EVP_PKEY includes an extra leading byte only for the compression format.
     * Since only the uncompressed format is supported, this byte (always 0x04)
     * can be safely ignored to maintain compatibility. */
    if (*public_key_size < len - 1) {
        *public_key_size = len - 1;
        return false;
    }

    *public_key_size = len - 1;
    /* buffer[0] = 0x04 indicates the uncompressed format (EVP_PKEY uses this as a format ID).
     * Only the raw key bytes (excluding this prefix) should be copied into public_key. */
    memcpy(public_key, buffer+1, *public_key_size);

    return true;
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
    EVP_PKEY *evp_pkey;
    const EC_KEY *ec_key;
    bool ret_val;

    if (ec_context == NULL) {
        return false;
    }

    evp_pkey = (EVP_PKEY *) ec_context;
    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);

    ret_val = (bool)EC_KEY_check_key(ec_key);
    if (!ret_val) {
        return false;
    }

    return true;
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
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   EC public X,Y generation succeeded.
 * @retval false  EC public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ec_generate_key(void *ec_context, uint8_t *public_data,
                             size_t *public_size)
{
    return libspdm_ec_get_pub_key(ec_context, public_data, public_size);
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
                            size_t peer_public_size, uint8_t *key,
                            size_t *key_size)
{
    EVP_PKEY *evp_pkey;
    EVP_PKEY *peer_pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t compatible_key[MAX_KEY_SIZE];
    size_t compatible_key_size = 0;
    bool result = false;

    evp_pkey = (EVP_PKEY *) ec_context;
    if (EVP_PKEY_get_base_id(evp_pkey) != EVP_PKEY_EC) {
        return false;
    }

    get_evp_compatible_public_key(evp_pkey, peer_public, peer_public_size,
                                  compatible_key, &compatible_key_size);

    peer_pkey = import_peer_pubkey(evp_pkey_get_curve_name(evp_pkey), compatible_key, compatible_key_size);
    if (peer_pkey == NULL) {
        return false;
    }

    ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
    if (ctx == NULL) {
        goto cleanup_peer;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup_ctx;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        goto cleanup_ctx;
    }

    if (EVP_PKEY_derive(ctx, key, key_size) <= 0) {
        goto cleanup_ctx;
    }

    result = true;

cleanup_ctx:
    EVP_PKEY_CTX_free(ctx);

cleanup_peer:
    EVP_PKEY_free(peer_pkey);

    return result;
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
bool libspdm_ecdsa_sign(void *ec_context, size_t hash_nid,
                        const uint8_t *message_hash, size_t hash_size,
                        uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY *evp_pkey = NULL;
    uint8_t half_size;
    const EVP_MD *md_type = NULL;
    bool result = false;
    uint8_t der_sign[MAX_DER_SIGN_SIZE];
    size_t der_sign_len = 0;

    if (ec_context == NULL || message_hash == NULL) {
        return false;
    }

    if (signature == NULL) {
        return false;
    }

    evp_pkey = (EVP_PKEY *)ec_context;
    if (EVP_PKEY_get_base_id(evp_pkey) != EVP_PKEY_EC) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (*sig_size < (size_t)(half_size * 2)) {
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
        md_type = EVP_sha256();
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha384();
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha512();
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha3_256();
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha3_384();
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha3_512();
        break;

    default:
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, evp_pkey, NULL);
    if (!ctx) {
        return false;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        goto cleanup_ctx;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md_type) <= 0) {
        goto cleanup_ctx;
    }

    if (EVP_PKEY_sign(ctx, NULL, &der_sign_len, message_hash, hash_size) != 1) {
        goto cleanup_ctx;
    }

    if (EVP_PKEY_sign(ctx, der_sign, &der_sign_len, message_hash, hash_size) != 1) {
        goto cleanup_ctx;
    }

    result = der_to_raw_rs(der_sign, der_sign_len, signature, half_size);

cleanup_ctx:
    EVP_PKEY_CTX_free(ctx);

    return result;
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
bool libspdm_ecdsa_verify(void *ec_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          const uint8_t *signature, size_t sig_size)
{
    EVP_PKEY *evp_pkey;
    uint8_t half_size;
    uint8_t der_sig[MAX_DER_SIGN_SIZE];
    size_t der_sig_len;
    bool result = false;
    const EVP_MD *md_type = NULL;

    if (ec_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    evp_pkey = (EVP_PKEY *)ec_context;
    if (EVP_PKEY_get_base_id(evp_pkey) != EVP_PKEY_EC) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (sig_size != (size_t)(half_size * 2)) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha256();
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha384();
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha512();
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha3_256();
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha3_384();
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        md_type = EVP_sha3_512();
        break;

    default:
        return false;
    }

    if (!raw_to_der_signature(signature, sig_size, der_sig, &der_sig_len)) {
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, evp_pkey, NULL);
    if (!ctx) {
        return false;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md_type) <= 0) {
        goto cleanup;
    }

    result = EVP_PKEY_verify(ctx, der_sig, der_sig_len, message_hash, hash_size) == 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);

    return result;
}

#if LIBSPDM_FIPS_MODE
/*setup random number*/
static int libspdm_ecdsa_sign_setup_random(EC_KEY *eckey, BIGNUM **kinvp, BIGNUM **rp,
                                           uint8_t* random, size_t random_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *r = NULL, *X = NULL, *e = NULL;
    const BIGNUM *order;
    EC_POINT *tmp_point = NULL;
    const EC_GROUP *group;
    int ret = 0;
    int order_bits;
    const BIGNUM *priv_key;


    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
        return 0;
    }
    if ((priv_key = EC_KEY_get0_private_key(eckey)) == NULL) {
        return 0;
    }

    if (!EC_KEY_can_sign(eckey)) {
        return 0;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        return 0;
    }

    /* this value is later returned in *kinvp */
    k = BN_new();
    /* this value is later returned in *rp */
    r = BN_new();
    X = BN_new();

    if (k == NULL || r == NULL || X == NULL) {
        return 0;
    }
    if ((tmp_point = EC_POINT_new(group)) == NULL) {
        return 0;
    }
    order = EC_GROUP_get0_order(group);

    /* Preallocate space */
    order_bits = BN_num_bits(order);
    if (!BN_set_bit(k, order_bits)
        || !BN_set_bit(r, order_bits)
        || !BN_set_bit(X, order_bits)) {
        goto err;
    }

    e = BN_CTX_get(ctx);
    if (e == NULL) {
        return 0;
    }

    /*random number*/
    k = BN_bin2bn(random, random_len, NULL);

    /* compute r the x-coordinate of generator * k */
    if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx)) {
        goto err;
    }
    if (!EC_POINT_get_affine_coordinates(group, tmp_point, X, NULL, ctx)) {
        goto err;
    }
    if (!BN_nnmod(r, X, order, ctx)) {
        goto err;
    }

    /*
     * compute the inverse of k
     * Based on ossl_ec_group_do_inverse_ord() from OpenSSL
     */
    BN_CTX_start(ctx);
    if (!BN_set_word(e, 2)) {
        BN_CTX_end(ctx);
        goto err;
    }
    if (!BN_sub(e, order, e)) {
        BN_CTX_end(ctx);
        goto err;
    }
    if (!BN_mod_exp_mont(k, k, e, order, ctx, EC_GROUP_get_mont_data(group))) {
        BN_CTX_end(ctx);
        goto err;
    }
    BN_CTX_end(ctx);

    /* clear old values if necessary */
    BN_clear_free(*rp);
    BN_clear_free(*kinvp);
    /* save the pre-computed values  */
    *rp = r;
    *kinvp = k;
    ret = 1;

err:
    if (!ret) {
        BN_clear_free(k);
        BN_clear_free(r);
    }

    BN_CTX_free(ctx);
    EC_POINT_free(tmp_point);
    BN_clear_free(X);
    return ret;
}

/**
 * Carries out the EC-DSA signature with caller input random function. This API can be used for FIPS test.
 *
 * @param[in]       ec_context    Pointer to EC context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     Size of the message hash in bytes.
 * @param[out]      signature     Pointer to buffer to receive EC-DSA signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                                On output, the size of data returned in signature buffer in bytes.
 * @param[in]       random_func   random number function
 *
 * @retval  true   signature successfully generated in EC-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_ecdsa_sign_ex(void *ec_context, size_t hash_nid,
                           const uint8_t *message_hash, size_t hash_size,
                           uint8_t *signature, size_t *sig_size,
                           int (*random_func)(void *, unsigned char *, size_t))
{
    EVP_PKEY *evp_pkey;
    const EC_KEY *ec_key = NULL;
    ECDSA_SIG *ecdsa_sig;
    int32_t openssl_nid;
    uint8_t half_size;
    BIGNUM *bn_r;
    BIGNUM *bn_s;
    int r_size;
    int s_size;
    /*random number*/
    uint8_t random[32];
    bool result;

    result = true;

    BIGNUM *kinv = NULL;
    BIGNUM *rp = NULL;

    kinv = NULL;
    rp = NULL;

    if (ec_context == NULL || message_hash == NULL) {
        return false;
    }

    if (signature == NULL) {
        return false;
    }

    evp_pkey = (EVP_PKEY *)ec_context;

    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
    switch (openssl_nid) {
    case NID_X9_62_prime256v1:
        half_size = 32;
        break;
    case NID_secp384r1:
        half_size = 48;
        break;
    case NID_secp521r1:
        half_size = 66;
        break;
    default:
        return false;
    }
    if (*sig_size < (size_t)(half_size * 2)) {
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

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    /*retrieve random number for ecdsa sign*/
    if (random_func(NULL, random, sizeof(random)) != 0) {
        result = false;
        goto cleanup;
    }
    if (!libspdm_ecdsa_sign_setup_random((EC_KEY *)ec_key, &kinv, &rp, random, sizeof(random))) {
        result = false;
        goto cleanup;
    }

    ecdsa_sig = ECDSA_do_sign_ex(message_hash, (uint32_t)hash_size, kinv, rp,
                                 (EC_KEY *)ec_key);
    if (ecdsa_sig == NULL) {
        result = false;
        goto cleanup;
    }

    ECDSA_SIG_get0(ecdsa_sig, (const BIGNUM **)&bn_r,
                   (const BIGNUM **)&bn_s);

    r_size = BN_num_bytes(bn_r);
    s_size = BN_num_bytes(bn_s);
    if (r_size <= 0 || s_size <= 0) {
        ECDSA_SIG_free(ecdsa_sig);
        result = false;
        goto cleanup;
    }
    LIBSPDM_ASSERT((size_t)r_size <= half_size && (size_t)s_size <= half_size);

    BN_bn2bin(bn_r, &signature[0 + half_size - r_size]);
    BN_bn2bin(bn_s, &signature[half_size + half_size - s_size]);

    ECDSA_SIG_free(ecdsa_sig);

cleanup:
    if (kinv != NULL) {
        BN_clear_free(kinv);
    }
    if (rp != NULL) {
        BN_clear_free(rp);
    }

    libspdm_zero_mem(random, sizeof(random));
    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/

/**
 * Helper functions for EC -> EVP signature format conversion
 * and compatibility
 */


/**
 * Convert raw signature to DER encoded signature.
 * raw_sig is in the format of r || s, where r and s are fixed-size
 * integers (padded with leading zeros as necessary).
 *
 * The caller is responsible to free the buffer allocated for der_sig.
 *
 * @param[in]  raw_sig     Pointer to the raw signature.
 * @param[in]  raw_len     size of the raw signature in bytes.
 * @param[out] der_sig     Pointer to the buffer to receive DER encoded signature.
 * @param[out] der_len     Pointer to the size of DER encoded signature in bytes.
 *
 * @retval true   raw signature successfully converted to DER encoded signature.
 * @retval false  raw signature conversion failed.
 */
bool raw_to_der_signature(const unsigned char *raw_sig, size_t raw_len,
                          unsigned char *der_sig, size_t *der_len)
{
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    size_t half_size = raw_len / 2;
    int result_len;
    bool result = false;

    if (raw_len % 2 != 0) {
        return false;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        return false;
    }

    r = BN_bin2bn(raw_sig, (int)half_size, NULL);
    s = BN_bin2bn(raw_sig + half_size, (int)half_size, NULL);

    if (r == NULL || s == NULL) {
        goto cleanup;
    }

    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        goto cleanup;
    }
    r = NULL;
    s = NULL;

    result_len = i2d_ECDSA_SIG(sig, NULL);
    if (result_len <= 0) {
        goto cleanup;
    }

    unsigned char *der_ptr = der_sig;
    if (i2d_ECDSA_SIG(sig, &der_ptr) != result_len) {
        goto cleanup;
    }

    *der_len = result_len;
    result = true;

cleanup:
    if (r != NULL) BN_free(r);
    if (s != NULL) BN_free(s);
    if (sig != NULL) ECDSA_SIG_free(sig);

    return result;
}


/**
 * Convert DER encoded signature to raw signature.
 *
 * der_sig is in the ASN.1 DER encoded format.
 * raw_sig is in the format of r || s, where r and s are fixed
 * size integers (padded with leading zeros as necessary).
 *
 * @param[in]  der_sig              Pointer to the DER encoded signature.
 * @param[in]  der_sig_len          size of the DER encoded signature in bytes
 * @param[out] out_raw              Pointer to the buffer to receive raw signature.
 * @param[in]  expected_half_size   size of r or s in bytes.
 *
 * @retval true   DER encoded signature successfully converted to raw signature.
 * @retval false  DER encoded signature conversion failed.
 */
bool der_to_raw_rs(const uint8_t *der_sig, size_t der_sig_len,
                   uint8_t *out_raw, size_t expected_half_size)
{
    const uint8_t *p = der_sig;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, der_sig_len);
    if (sig == NULL) {
        printf("Failed to decode DER signature.\n");
        return false;
    }

    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);

    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);

    if (r_len > expected_half_size || s_len > expected_half_size) {
        printf("Component longer than expected (%d vs %zu, %d vs %zu)\n", r_len, expected_half_size, s_len,
               expected_half_size);
        ECDSA_SIG_free(sig);
        return false;
    }

    memset(out_raw, 0, expected_half_size * 2);

    BN_bn2binpad(r, out_raw, expected_half_size);
    BN_bn2binpad(s, out_raw + expected_half_size, expected_half_size);

    ECDSA_SIG_free(sig);
    return true;
}

EVP_PKEY *import_peer_pubkey(const char* curve_name, const unsigned char *pub, size_t pub_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) return NULL;

    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (void *) curve_name, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          (void *)pub, pub_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void get_evp_compatible_public_key(EVP_PKEY *evp_pkey,
                                   const uint8_t *public_key, size_t public_key_size,
                                   uint8_t *compatible_key, size_t *comptable_key_size) {
    int half_size;
    /* EVP compatible public key hack
     * EVP expect public key [0] = 0x04 for uncompressed followed by key data */
    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size * 2 == public_key_size) {
        public_key_size += 1;
        compatible_key[0] = 0x04;
        memcpy(compatible_key+1, public_key, public_key_size-1);
    } else {
        memcpy(compatible_key, public_key, public_key_size);
    }
    *comptable_key_size = public_key_size;
}
