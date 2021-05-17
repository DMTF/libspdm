/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "test_crypt.h"

/**
  Validate Crypto MontgomeryCurve Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status validate_crypt_ecx(void)
{
	void *ecx1;
	void *ecx2;
	uint8 public1[56];
	uintn public1_length;
	uint8 public2[56];
	uintn public2_length;
	uint8 key1[56];
	uintn key1_length;
	uint8 key2[56];
	uintn key2_length;
	boolean Status;

	my_print("\nCrypto Montgomery Curve key Exchange Testing:\n");

	//
	// Initialize key Length
	//
	public1_length = sizeof(public1);
	public2_length = sizeof(public2);
	key1_length = sizeof(key1);
	key2_length = sizeof(key2);

	//
	// Generate & Initialize EC Context
	//
	my_print("- Context1 ... ");
	ecx1 = ecx_new_by_nid(CRYPTO_NID_CURVE_X25519);
	if (ecx1 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	my_print("Context2 ... ");
	ecx2 = ecx_new_by_nid(CRYPTO_NID_CURVE_X25519);
	if (ecx2 == NULL) {
		my_print("[Fail]");
		ecx_free(ecx1);
		goto Exit;
	}

	//
	// Verify EC-DH x25519/x448
	//
	my_print("Generate key1 ... ");
	Status = ecx_generate_key(ecx1, public1, &public1_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Generate key2 ... ");
	Status = ecx_generate_key(ecx2, public2, &public2_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Compute key1 ... ");
	Status = ecx_compute_key(ecx1, public2, public2_length, key1,
				 &key1_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Compute key2 ... ");
	Status = ecx_compute_key(ecx2, public1, public1_length, key2,
				 &key2_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Compare Keys ... ");
	if (key1_length != key2_length) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	if (const_compare_mem(key1, key2, key1_length) != 0) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}

	ecx_free(ecx1);
	ecx_free(ecx2);

	//
	// Initialize key Length
	//
	public1_length = sizeof(public1);
	public2_length = sizeof(public2);
	key1_length = sizeof(key1);
	key2_length = sizeof(key2);

	//
	// Generate & Initialize EC Context
	//
	my_print("- Context1 ... ");
	ecx1 = ecx_new_by_nid(CRYPTO_NID_CURVE_X448);
	if (ecx1 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	my_print("Context2 ... ");
	ecx2 = ecx_new_by_nid(CRYPTO_NID_CURVE_X448);
	if (ecx2 == NULL) {
		my_print("[Fail]");
		ecx_free(ecx1);
		goto Exit;
	}

	//
	// Verify EC-DH x25519/x448
	//
	my_print("Generate key1 ... ");
	Status = ecx_generate_key(ecx1, public1, &public1_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Generate key2 ... ");
	Status = ecx_generate_key(ecx2, public2, &public2_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Compute key1 ... ");
	Status = ecx_compute_key(ecx1, public2, public2_length, key1,
				 &key1_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Compute key2 ... ");
	Status = ecx_compute_key(ecx2, public1, public1_length, key2,
				 &key2_length);
	if (!Status) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	my_print("Compare Keys ... ");
	if (key1_length != key2_length) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	}

	if (const_compare_mem(key1, key2, key1_length) != 0) {
		my_print("[Fail]");
		ecx_free(ecx1);
		ecx_free(ecx2);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}

	ecx_free(ecx1);
	ecx_free(ecx2);

Exit:
	return RETURN_SUCCESS;
}