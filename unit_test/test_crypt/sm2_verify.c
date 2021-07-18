/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "test_crypt.h"

/**
  Validate Crypto sm2 Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status validate_crypt_sm2(void)
{
	void *Sm2_1;
	void *Sm2_2;
	uint8 public1[66 * 2];
	uintn public1_length;
	uint8 public2[66 * 2];
	uintn public2_length;
	uint8 key1[66];
	uintn key1_length;
	uint8 key2[66];
	uintn key2_length;
	uint8 message[] = "Sm2Test";
	uint8 signature[66 * 2];
	uintn sig_size;
	boolean status;

	my_print("\nCrypto SM2 key Exchange Testing:\n");

	//
	// Initialize key length
	//
	public1_length = sizeof(public1);
	public2_length = sizeof(public2);
	key1_length = sizeof(key1);
	key2_length = sizeof(key2);

	//
	// Generate & Initialize SM2 context
	//
	my_print("- Context1 ... ");
	Sm2_1 = sm2_new();
	if (Sm2_1 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	my_print("Context2 ... ");
	Sm2_2 = sm2_new();
	if (Sm2_2 == NULL) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		goto Exit;
	}

	//
	// Verify SM2-DH
	//
	my_print("Generate key1 ... ");
	status = sm2_generate_key(Sm2_1, public1, &public1_length);
	if (!status || public1_length != 32 * 2) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("Generate key2 ... ");
	status = sm2_generate_key(Sm2_2, public2, &public2_length);
	if (!status || public2_length != 32 * 2) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("Compute key1 ... ");
	status = sm2_compute_key(Sm2_1, public2, public2_length, key1,
				 &key1_length);
	if (!status || key1_length != 32) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("Compute key2 ... ");
	status = sm2_compute_key(Sm2_2, public1, public1_length, key2,
				 &key2_length);
	if (!status || key2_length != 32) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("Compare Keys ... ");
	if (key1_length != key2_length) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	if (const_compare_mem(key1, key2, key1_length) != 0) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}

	sm2_free(Sm2_1);
	sm2_free(Sm2_2);

	my_print("\nCrypto sm2 Signing Verification Testing:\n");

	public1_length = sizeof(public1);

	my_print("- Context1 ... ");
	Sm2_1 = sm2_new();
	if (Sm2_1 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	my_print("Compute key1 ... ");
	status = sm2_generate_key(Sm2_1, public1, &public1_length);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		goto Exit;
	}

	//
	// Verify SM2 signing/verification
	//
	sig_size = sizeof(signature);
	my_print("\n- SM2 Signing ... ");
	status = sm2_ecdsa_sign(Sm2_1, CRYPTO_NID_SM3_256, message,
				sizeof(message), signature, &sig_size);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		goto Exit;
	}

	my_print("SM2 Verification ... ");
	status = sm2_ecdsa_verify(Sm2_1, CRYPTO_NID_SM3_256, message,
				  sizeof(message), signature, sig_size);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}
	sm2_free(Sm2_1);

	my_print("\nCrypto sm2 Signing Verification Testing with SetPubKey:\n");

	public1_length = sizeof(public1);
	public2_length = sizeof(public2);

	my_print("- Context1 ... ");
	Sm2_1 = sm2_new();
	if (Sm2_1 == NULL) {
		my_print("[Fail]");
		goto Exit;
	}

	my_print("Context2 ... ");
	Sm2_2 = sm2_new();
	if (Sm2_2 == NULL) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		goto Exit;
	}

	my_print("Compute key in Context1 ... ");
	status = sm2_generate_key(Sm2_1, public1, &public1_length);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("Export key in Context1 ... ");
	status = sm2_get_pub_key(Sm2_1, public2, &public2_length);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("Import key in Context2 ... ");
	status = sm2_set_pub_key(Sm2_2, public2, public2_length);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	//
	// Verify EC-DSA
	//
	sig_size = sizeof(signature);
	my_print("\n- sm2 Signing in Context1 ... ");
	status = sm2_ecdsa_sign(Sm2_1, CRYPTO_NID_SM3_256, message,
				sizeof(message), signature, &sig_size);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	}

	my_print("sm2 Verification in Context2 ... ");
	status = sm2_ecdsa_verify(Sm2_2, CRYPTO_NID_SM3_256, message,
				  sizeof(message), signature, sig_size);
	if (!status) {
		my_print("[Fail]");
		sm2_free(Sm2_1);
		sm2_free(Sm2_2);
		goto Exit;
	} else {
		my_print("[Pass]\n");
	}

	sm2_free(Sm2_1);
	sm2_free(Sm2_2);

Exit:
	return RETURN_SUCCESS;
}