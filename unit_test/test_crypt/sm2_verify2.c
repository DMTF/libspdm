/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#define DEFAULT_SM2_ID "1234567812345678"


/* Root CA X509 Certificate for X509 Verification Routine (Generated by OpenSSL utility).*/

GLOBAL_REMOVE_IF_UNREFERENCED const uint8_t m_sm2_test_root_cer[] = {
    0x30, 0x82, 0x01, 0x8c, 0x30, 0x82, 0x01, 0x33, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x7e, 0xe0, 0x5d, 0xef, 0x94, 0x53, 0x58, 0x7e, 0x0c,
    0x57, 0xb4, 0xd9, 0xb6, 0x2b, 0x6c, 0x61, 0x3f, 0xe0, 0x27, 0x35, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x1c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11,
    0x69, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x53,
    0x4d, 0x32, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x31, 0x30,
    0x32, 0x32, 0x32, 0x31, 0x34, 0x31, 0x37, 0x32, 0x39, 0x5a, 0x17, 0x0d,
    0x33, 0x31, 0x30, 0x32, 0x32, 0x30, 0x31, 0x34, 0x31, 0x37, 0x32, 0x39,
    0x5a, 0x30, 0x1c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x11, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x74, 0x65, 0x73, 0x74,
    0x20, 0x53, 0x4d, 0x32, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x81,
    0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x3e, 0xc4,
    0xab, 0x29, 0xb0, 0x24, 0x75, 0xe2, 0xa9, 0xcc, 0x1a, 0x55, 0x93, 0x1a,
    0x62, 0x0f, 0x97, 0xcc, 0x71, 0xc9, 0x7d, 0x24, 0xf3, 0xc4, 0x10, 0x8f,
    0x11, 0xfb, 0x20, 0xc1, 0x99, 0x64, 0x73, 0x2d, 0x3b, 0x02, 0x23, 0x79,
    0xe4, 0x48, 0x95, 0x0c, 0x0e, 0xde, 0xa5, 0x31, 0xd5, 0x3b, 0xd2, 0x56,
    0xce, 0xb8, 0x53, 0x24, 0x6a, 0x3a, 0xa0, 0x06, 0x96, 0x3e, 0x1e, 0x3d,
    0x02, 0x92, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x9a, 0x6d, 0x5e, 0xa7, 0xba, 0x09, 0x18,
    0x86, 0xc3, 0x03, 0xb9, 0x89, 0x91, 0x53, 0xdd, 0xb6, 0xdb, 0xf2, 0x83,
    0xda, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0x9a, 0x6d, 0x5e, 0xa7, 0xba, 0x09, 0x18, 0x86, 0xc3, 0x03,
    0xb9, 0x89, 0x91, 0x53, 0xdd, 0xb6, 0xdb, 0xf2, 0x83, 0xda, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x6e, 0x57,
    0xa6, 0x4f, 0x52, 0xf3, 0x72, 0xde, 0xe4, 0xc6, 0x48, 0x4d, 0x47, 0xc6,
    0xb9, 0xb8, 0x8d, 0x5f, 0x87, 0x3d, 0x4e, 0xa8, 0xff, 0xbd, 0xbb, 0xfd,
    0x91, 0x11, 0x1d, 0x70, 0xe0, 0x87, 0x02, 0x20, 0x0e, 0x21, 0x0b, 0xde,
    0x89, 0xe2, 0x0e, 0x20, 0x71, 0xe0, 0xbb, 0xf6, 0x23, 0x25, 0x4a, 0x59,
    0xa2, 0xa0, 0x20, 0x4f, 0x49, 0x07, 0x07, 0x0a, 0xd2, 0x4e, 0x7a, 0xc7,
    0x82, 0xeb, 0x17, 0xf2,
};


/* PEM key data for sm2 Private key Retrieving.
 * (Generated by OpenSSL utility).*/

GLOBAL_REMOVE_IF_UNREFERENCED const uint8_t m_sm2_test_pem_key[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45,
    0x43, 0x20, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x42, 0x67, 0x67, 0x71, 0x67, 0x52,
    0x7a, 0x50, 0x56, 0x51, 0x47, 0x43, 0x4c, 0x51, 0x3d, 0x3d, 0x0a, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50,
    0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49,
    0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
    0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x48,
    0x63, 0x43, 0x41, 0x51, 0x45, 0x45, 0x49, 0x48, 0x49, 0x47, 0x48, 0x70,
    0x6b, 0x7a, 0x4a, 0x43, 0x30, 0x6d, 0x58, 0x62, 0x66, 0x31, 0x7a, 0x52,
    0x7a, 0x54, 0x66, 0x4b, 0x2f, 0x64, 0x59, 0x4e, 0x34, 0x34, 0x49, 0x6f,
    0x4c, 0x77, 0x61, 0x6b, 0x55, 0x61, 0x68, 0x30, 0x48, 0x37, 0x79, 0x71,
    0x33, 0x6f, 0x6f, 0x41, 0x6f, 0x47, 0x43, 0x43, 0x71, 0x42, 0x48, 0x4d,
    0x39, 0x56, 0x0a, 0x41, 0x59, 0x49, 0x74, 0x6f, 0x55, 0x51, 0x44, 0x51,
    0x67, 0x41, 0x45, 0x50, 0x73, 0x53, 0x72, 0x4b, 0x62, 0x41, 0x6b, 0x64,
    0x65, 0x4b, 0x70, 0x7a, 0x42, 0x70, 0x56, 0x6b, 0x78, 0x70, 0x69, 0x44,
    0x35, 0x66, 0x4d, 0x63, 0x63, 0x6c, 0x39, 0x4a, 0x50, 0x50, 0x45, 0x45,
    0x49, 0x38, 0x52, 0x2b, 0x79, 0x44, 0x42, 0x6d, 0x57, 0x52, 0x7a, 0x4c,
    0x54, 0x73, 0x43, 0x49, 0x33, 0x6e, 0x6b, 0x0a, 0x53, 0x4a, 0x55, 0x4d,
    0x44, 0x74, 0x36, 0x6c, 0x4d, 0x64, 0x55, 0x37, 0x30, 0x6c, 0x62, 0x4f,
    0x75, 0x46, 0x4d, 0x6b, 0x61, 0x6a, 0x71, 0x67, 0x42, 0x70, 0x59, 0x2b,
    0x48, 0x6a, 0x30, 0x43, 0x6b, 0x67, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49,
    0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x0a,
};

/**
 * Validate Crypto sm2 key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_sm2_2(void)
{
    boolean status;
    void *sm2_priv_key;
    void *sm2_pub_key;
    uint8_t message[] = "Sm2Test";
    uint8_t signature[32 * 2];
    uintn sig_size;

    my_print("\nCrypto sm2 key Retrieving Testing: ");


    /* Retrieve Ed private key from PEM data.*/

    my_print("\n- Retrieve sm2 Private key for PEM ...");
    status = sm2_get_private_key_from_pem(m_sm2_test_pem_key,
                                          sizeof(m_sm2_test_pem_key), NULL,
                                          &sm2_priv_key);
    if (!status) {
        my_print("[Fail]");
        goto Exit;
    } else {
        my_print("[Pass]");
    }


    /* Retrieve sm2 public key from X509 Certificate.*/

    my_print("\n- Retrieve sm2 public key from X509 ... ");
    status = sm2_get_public_key_from_x509(
        m_sm2_test_root_cer, sizeof(m_sm2_test_root_cer), &sm2_pub_key);
    if (!status) {
        my_print("[Fail]");
        sm2_dsa_free(sm2_priv_key);
        goto Exit;
    } else {
        my_print("[Pass]");
    }


    /* Verify SM2 signing/verification*/

    sig_size = sizeof(signature);
    my_print("\n- SM2 Signing ... ");
    status =
        sm2_dsa_sign(sm2_priv_key, CRYPTO_NID_SM3_256, (uint8_t *)DEFAULT_SM2_ID,
                     sizeof(DEFAULT_SM2_ID) - 1, message,
                     sizeof(message), signature, &sig_size);
    if (!status) {
        my_print("[Fail]");
        sm2_dsa_free(sm2_priv_key);
        sm2_dsa_free(sm2_pub_key);
        goto Exit;
    } else {
        my_print("[Pass]");
    }

    my_print("\n- SM2 Verification ... ");
    status =
        sm2_dsa_verify(sm2_pub_key, CRYPTO_NID_SM3_256, (uint8_t *)DEFAULT_SM2_ID,
                       sizeof(DEFAULT_SM2_ID) - 1, message,
                       sizeof(message), signature, sig_size);
    if (!status) {
        my_print("[Fail]");
        sm2_dsa_free(sm2_priv_key);
        sm2_dsa_free(sm2_pub_key);
        goto Exit;
    } else {
        my_print("[Pass]\n");
    }

    sm2_dsa_free(sm2_priv_key);
    sm2_dsa_free(sm2_pub_key);

Exit:
    return RETURN_SUCCESS;
}
