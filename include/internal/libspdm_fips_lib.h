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

/**
 * HKDF KAT test
 **/
bool libspdm_fips_selftest_hkdf(void);

/**
 * ECDH self_test
 **/
bool libspdm_fips_selftest_ecdh(void);

/**
 * SHA256 KAT: HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_sha256(void);
/**
 * SHA384 KAT: HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_sha384(void);
/**
 * SHA512 KAT: HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_sha512(void);

/**
 * SHA3_256 KAT
 **/
bool libspdm_fips_selftest_sha3_256(void);
/**
 * SHA3_384 KAT
 **/
bool libspdm_fips_selftest_sha3_384(void);
/**
 * SHA3_512 KAT
 **/
bool libspdm_fips_selftest_sha3_512(void);

/**
 * FFDH self_test
 **/
bool libspdm_fips_selftest_ffdh(void);

/**
 * ECDSA self_test
 **/
bool libspdm_fips_selftest_ecdsa(void);

#endif/*LIBSPDM_FIPS_MODE*/
