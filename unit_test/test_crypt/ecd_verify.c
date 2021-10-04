/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "test_crypt.h"

/**
  Validate Crypto Ed Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status validate_crypt_ecd(void)
{
	void *ecd1;
	void *ecd2;
	uint8 message[] = "EdDsaTest";
	uint8 signature1[32 * 2];
	uint8 signature2[57 * 2];
	uintn sig1_size;
	uintn sig2_size;
	boolean status;

	my_print("\nCrypto Ed-DSA Signing Verification Testing:\n");

	my_print("- Context1 ... ");
	ecd1 = ecd_new_by_nid(CRYPTO_NID_EDDSA_ED25519);
	if (ecd1 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	//
	// Verify Ed-DSA
	//
	sig1_size = sizeof(signature1);
	my_print("\n- Ed-DSA Signing ... ");
	status = eddsa_sign(ecd1, CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
			    signature1, &sig1_size);
	if (!status) {
		my_print("[Fail]");
		ecd_free(ecd1);
		goto Exit;
	}

	my_print("Ed-DSA Verification ... ");
	status = eddsa_verify(ecd1, CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
			      signature1, sig1_size);
	if (!status) {
		my_print("[Fail]");
		ecd_free(ecd1);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}
	ecd_free(ecd1);

	my_print("Context2 ... ");
	ecd2 = ecd_new_by_nid(CRYPTO_NID_EDDSA_ED448);
	if (ecd2 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	sig2_size = sizeof(signature2);
	my_print("\n- Ed-DSA Signing ... ");
	status = eddsa_sign(ecd2, CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
			    signature2, &sig2_size);
	if (!status) {
		my_print("[Fail]");
		ecd_free(ecd2);
		goto Exit;
	}

	my_print("Ed-DSA Verification ... ");
	status = eddsa_verify(ecd2, CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
			      signature2, sig2_size);
	if (!status) {
		my_print("[Fail]");
		ecd_free(ecd2);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}

	ecd_free(ecd2);

Exit:
	return RETURN_SUCCESS;
}