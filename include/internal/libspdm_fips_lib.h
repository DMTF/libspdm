/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#if LIBSPDM_FIPS_MODE

/**
 * HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha256(void);
/**
 * HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha384(void);
/**
 * HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha512(void);

/**
 * AES_GCM self_test
 **/
bool libspdm_fips_selftest_aes_gcm(void);

/**
 * RSA_SSA(RSASSA-PKCS1 v1.5) self_test
 **/
bool libspdm_fips_selftest_rsa_ssa(void);

#endif/*LIBSPDM_FIPS_MODE*/
