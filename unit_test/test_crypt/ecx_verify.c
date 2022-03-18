/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

/**
 * Validate Crypto MontgomeryCurve Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status libspdm_validate_crypt_ecx(void)
{
    libspdm_my_print("\n skip Crypto Montgomery Curve key Exchange Testing:\n");
//     void *ecx1;
//     void *ecx2;
//     uint8_t public1[56];
//     uintn public1_length;
//     uint8_t public2[56];
//     uintn public2_length;
//     uint8_t key1[56];
//     uintn key1_length;
//     uint8_t key2[56];
//     uintn key2_length;
//     bool Status;

//     libspdm_my_print("\nCrypto Montgomery Curve key Exchange Testing:\n");


//     /* Initialize key Length*/

//     public1_length = sizeof(public1);
//     public2_length = sizeof(public2);
//     key1_length = sizeof(key1);
//     key2_length = sizeof(key2);


//     /* Generate & Initialize EC Context*/

//     libspdm_my_print("- Context1 ... ");
//     ecx1 = libspdm_ecx_new_by_nid(LIBSPDM_CRYPTO_NID_CURVE_X25519);
//     if (ecx1 == NULL) {
//         libspdm_my_print("[Fail]");
//         goto Exit;
//     }

//     libspdm_my_print("Context2 ... ");
//     ecx2 = libspdm_ecx_new_by_nid(LIBSPDM_CRYPTO_NID_CURVE_X25519);
//     if (ecx2 == NULL) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         goto Exit;
//     }


//     /* Verify EC-DH x25519/x448*/

//     libspdm_my_print("Generate key1 ... ");
//     Status = libspdm_ecx_generate_key(ecx1, public1, &public1_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Generate key2 ... ");
//     Status = libspdm_ecx_generate_key(ecx2, public2, &public2_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Compute key1 ... ");
//     Status = libspdm_ecx_compute_key(ecx1, public2, public2_length, key1,
//                                      &key1_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Compute key2 ... ");
//     Status = libspdm_ecx_compute_key(ecx2, public1, public1_length, key2,
//                                      &key2_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Compare Keys ... ");
//     if (key1_length != key2_length) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     if (libspdm_const_compare_mem(key1, key2, key1_length) != 0) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     } else {
//         libspdm_my_print("[Pass]\n");
//     }

//     libspdm_ecx_free(ecx1);
//     libspdm_ecx_free(ecx2);


//     /* Initialize key Length*/

//     public1_length = sizeof(public1);
//     public2_length = sizeof(public2);
//     key1_length = sizeof(key1);
//     key2_length = sizeof(key2);


//     /* Generate & Initialize EC Context*/

//     libspdm_my_print("- Context1 ... ");
//     ecx1 = libspdm_ecx_new_by_nid(LIBSPDM_CRYPTO_NID_CURVE_X448);
//     if (ecx1 == NULL) {
//         libspdm_my_print("[Fail]");
//         goto Exit;
//     }

//     libspdm_my_print("Context2 ... ");
//     ecx2 = libspdm_ecx_new_by_nid(LIBSPDM_CRYPTO_NID_CURVE_X448);
//     if (ecx2 == NULL) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         goto Exit;
//     }


//     /* Verify EC-DH x25519/x448*/

//     libspdm_my_print("Generate key1 ... ");
//     Status = libspdm_ecx_generate_key(ecx1, public1, &public1_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Generate key2 ... ");
//     Status = libspdm_ecx_generate_key(ecx2, public2, &public2_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Compute key1 ... ");
//     Status = libspdm_ecx_compute_key(ecx1, public2, public2_length, key1,
//                                      &key1_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Compute key2 ... ");
//     Status = libspdm_ecx_compute_key(ecx2, public1, public1_length, key2,
//                                      &key2_length);
//     if (!Status) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     libspdm_my_print("Compare Keys ... ");
//     if (key1_length != key2_length) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     }

//     if (libspdm_const_compare_mem(key1, key2, key1_length) != 0) {
//         libspdm_my_print("[Fail]");
//         libspdm_ecx_free(ecx1);
//         libspdm_ecx_free(ecx2);
//         goto Exit;
//     } else {
//         libspdm_my_print("[Pass]\n");
//     }

//     libspdm_ecx_free(ecx1);
//     libspdm_ecx_free(ecx2);

// Exit:
    return RETURN_SUCCESS;
}
