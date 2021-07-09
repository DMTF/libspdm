/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "test_crypt.h"

//
// Max Known digest size is SHA512 output (64 bytes) by far
//
#define MAX_DIGEST_SIZE 64

//
// message string for digest validation
//
GLOBAL_REMOVE_IF_UNREFERENCED const char8 *m_hash_data = "abc";

//
// result for SHA-256("abc"). (from "B.1 SHA-256 Example" of NIST FIPS 180-2)
//
GLOBAL_REMOVE_IF_UNREFERENCED const uint8 m_sha256_digest[SHA256_DIGEST_SIZE] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
	0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
	0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

//
// result for SHA-384("abc"). (from "D.1 SHA-384 Example" of NIST FIPS 180-2)
//
GLOBAL_REMOVE_IF_UNREFERENCED const uint8 m_sha384_digest[SHA384_DIGEST_SIZE] = {
	0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
	0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
	0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
	0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
};

//
// result for SHA-512("abc"). (from "C.1 SHA-512 Example" of NIST FIPS 180-2)
//
GLOBAL_REMOVE_IF_UNREFERENCED const uint8 m_sha512_digest[SHA512_DIGEST_SIZE] = {
	0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
	0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
	0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
	0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
	0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
	0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};

GLOBAL_REMOVE_IF_UNREFERENCED const uint8
	m_sha3_256_digest[SHA3_256_DIGEST_SIZE] = {
		0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
		0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
		0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
		0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
	};

GLOBAL_REMOVE_IF_UNREFERENCED const uint8
	m_sha3_384_digest[SHA3_384_DIGEST_SIZE] = {
		0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45,
		0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d, 0xf9, 0xb4, 0x73, 0xcb,
		0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b,
		0xe4, 0xb2, 0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
		0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25
	};

GLOBAL_REMOVE_IF_UNREFERENCED const uint8
	m_sha3_512_digest[SHA3_512_DIGEST_SIZE] = {
		0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93,
		0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82,
		0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2,
		0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
		0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34,
		0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27,
		0x4e, 0xec, 0x53, 0xf0
	};

GLOBAL_REMOVE_IF_UNREFERENCED const uint8
	m_shake_256_digest[SHAKE256_DIGEST_SIZE] = {
		0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
		0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
		0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee,
		0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39
	};

GLOBAL_REMOVE_IF_UNREFERENCED const uint8
	m_sm3_256_digest[SM3_256_DIGEST_SIZE] = {
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
	};

/**
  Validate Crypto digest Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status validate_crypt_digest(void)
{
	void *hash_ctx;
	uintn data_size;
	uint8 digest[MAX_DIGEST_SIZE];
	boolean status;

	my_print(" Crypt hash Engine Testing:\n");
	data_size = ascii_str_len(m_hash_data);

	my_print("- SHA256: ");

	//
	// SHA256 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = sha256_new();
	if (hash_ctx == NULL) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("Init... ");
	status = sha256_init(hash_ctx);
	if (!status) {
		my_print("[Fail]");
		sha256_free(hash_ctx);
		return RETURN_ABORTED;
	}

	my_print("Update... ");
	status = sha256_update(hash_ctx, m_hash_data, data_size);
	if (!status) {
		my_print("[Fail]");
		sha256_free(hash_ctx);
		return RETURN_ABORTED;
	}

	my_print("Finalize... ");
	status = sha256_final(hash_ctx, digest);
	if (!status) {
		my_print("[Fail]");
		sha256_free(hash_ctx);
		return RETURN_ABORTED;
	}

	sha256_free(hash_ctx);

	my_print("Check value... ");
	if (const_compare_mem(digest, m_sha256_digest, SHA256_DIGEST_SIZE) != 0) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("HashAll... ");
	zero_mem(digest, SHA256_DIGEST_SIZE);
	status = sha256_hash_all(m_hash_data, data_size, digest);
	if (!status) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}
	if (const_compare_mem(digest, m_sha256_digest, SHA256_DIGEST_SIZE) != 0) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("[Pass]\n");

	my_print("- SHA384: ");

	//
	// SHA384 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = sha384_new();
	if (hash_ctx == NULL) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("Init... ");
	status = sha384_init(hash_ctx);
	if (!status) {
		my_print("[Fail]");
		sha384_free(hash_ctx);
		return RETURN_ABORTED;
	}

	my_print("Update... ");
	status = sha384_update(hash_ctx, m_hash_data, data_size);
	if (!status) {
		my_print("[Fail]");
		sha384_free(hash_ctx);
		return RETURN_ABORTED;
	}

	my_print("Finalize... ");
	status = sha384_final(hash_ctx, digest);
	if (!status) {
		my_print("[Fail]");
		sha384_free(hash_ctx);
		return RETURN_ABORTED;
	}

	sha384_free(hash_ctx);

	my_print("Check value... ");
	if (const_compare_mem(digest, m_sha384_digest, SHA384_DIGEST_SIZE) != 0) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("HashAll... ");
	zero_mem(digest, SHA384_DIGEST_SIZE);
	status = sha384_hash_all(m_hash_data, data_size, digest);
	if (!status) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}
	if (const_compare_mem(digest, m_sha384_digest, SHA384_DIGEST_SIZE) != 0) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("[Pass]\n");

	my_print("- SHA512: ");

	//
	// SHA512 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = sha512_new();
	if (hash_ctx == NULL) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("Init... ");
	status = sha512_init(hash_ctx);
	if (!status) {
		my_print("[Fail]");
		sha512_free(hash_ctx);
		return RETURN_ABORTED;
	}

	my_print("Update... ");
	status = sha512_update(hash_ctx, m_hash_data, data_size);
	if (!status) {
		my_print("[Fail]");
		sha512_free(hash_ctx);
		return RETURN_ABORTED;
	}

	my_print("Finalize... ");
	status = sha512_final(hash_ctx, digest);
	if (!status) {
		my_print("[Fail]");
		sha512_free(hash_ctx);
		return RETURN_ABORTED;
	}

	sha512_free(hash_ctx);

	my_print("Check value... ");
	if (const_compare_mem(digest, m_sha512_digest, SHA512_DIGEST_SIZE) != 0) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("HashAll... ");
	zero_mem(digest, SHA512_DIGEST_SIZE);
	status = sha512_hash_all(m_hash_data, data_size, digest);
	if (!status) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}
	if (const_compare_mem(digest, m_sha512_digest, SHA512_DIGEST_SIZE) != 0) {
		my_print("[Fail]");
		return RETURN_ABORTED;
	}

	my_print("[Pass]\n");

	my_print("- SHA3_256: ");
	//
	// SHA3_256 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = sha3_256_new();
	if (hash_ctx != NULL) {
		my_print("Init... ");
		status = sha3_256_init(hash_ctx);
	}

	if (status) {
		my_print("Update... ");
		status = sha3_256_update(hash_ctx, m_hash_data, data_size);
	}

	if (status) {
		my_print("Finalize... ");
		status = sha3_256_final(hash_ctx, digest);
	}

	if (status) {
		my_print("Check value... ");
		if (const_compare_mem(digest, m_sha3_256_digest,
				SHA3_256_DIGEST_SIZE) == 0) {
			status = TRUE;
		} else {
			status = FALSE;
		}
	}

	if (hash_ctx != NULL) {
		sha3_256_free(hash_ctx);
	}

	if (status) {
		my_print("HashAll... ");
		zero_mem(digest, SHA3_256_DIGEST_SIZE);
		status = sha3_256_hash_all(m_hash_data, data_size, digest);
	}
	if (status) {
		my_print("[Pass]\n");
	} else {
		my_print("[Failed]\n");
	}

	my_print("- SHA3_384: ");
	//
	// SHA3_384 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = sha3_384_new();
	if (hash_ctx != NULL) {
		my_print("Init... ");
		status = sha3_384_init(hash_ctx);
	}

	if (status) {
		my_print("Update... ");
		status = sha3_384_update(hash_ctx, m_hash_data, data_size);
	}

	if (status) {
		my_print("Finalize... ");
		status = sha3_384_final(hash_ctx, digest);
	}

	if (status) {
		my_print("Check value... ");
		if (const_compare_mem(digest, m_sha3_384_digest,
				SHA3_384_DIGEST_SIZE) == 0) {
			status = TRUE;
		} else {
			status = FALSE;
		}
	}

	if (hash_ctx != NULL) {
		sha3_384_free(hash_ctx);
	}

	if (status) {
		my_print("HashAll... ");
		zero_mem(digest, SHA3_384_DIGEST_SIZE);
		status = sha3_384_hash_all(m_hash_data, data_size, digest);
	}
	if (status) {
		my_print("[Pass]\n");
	} else {
		my_print("[Failed]\n");
	}

	my_print("- SHA3_512: ");
	//
	// SHA3_512 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = sha3_512_new();
	if (hash_ctx != NULL) {
		my_print("Init... ");
		status = sha3_512_init(hash_ctx);
	}

	if (status) {
		my_print("Update... ");
		status = sha3_512_update(hash_ctx, m_hash_data, data_size);
	}

	if (status) {
		my_print("Finalize... ");
		status = sha3_512_final(hash_ctx, digest);
	}

	if (status) {
		my_print("Check value... ");
		if (const_compare_mem(digest, m_sha3_512_digest,
				SHA3_512_DIGEST_SIZE) == 0) {
			status = TRUE;
		} else {
			status = FALSE;
		}
	}

	if (hash_ctx != NULL) {
		sha3_512_free(hash_ctx);
	}

	if (status) {
		my_print("HashAll... ");
		zero_mem(digest, SHA3_512_DIGEST_SIZE);
		status = sha3_512_hash_all(m_hash_data, data_size, digest);
	}
	if (status) {
		my_print("[Pass]\n");
	} else {
		my_print("[Failed]\n");
	}

	my_print("- SHAKE256: ");
	//
	// SHAKE256 digest Validation
	//
	zero_mem(digest, MAX_DIGEST_SIZE);
	hash_ctx = shake256_new();
	if (hash_ctx != NULL) {
		my_print("Init... ");
		status = shake256_init(hash_ctx);
	}

	if (status) {
		my_print("Update... ");
		status = shake256_update(hash_ctx, m_hash_data, data_size);
	}

	if (status) {
		my_print("Finalize... ");
		status = shake256_final(hash_ctx, digest);
	}

	if (status) {
		my_print("Check value... ");
		if (const_compare_mem(digest, m_shake_256_digest,
				SHAKE256_DIGEST_SIZE) == 0) {
			status = TRUE;
		} else {
			status = FALSE;
		}
	}

	if (hash_ctx != NULL) {
		shake256_free(hash_ctx);
	}

	if (status) {
		my_print("HashAll... ");
		zero_mem(digest, SHAKE256_DIGEST_SIZE);
		status = shake256_hash_all(m_hash_data, data_size, digest);
	}
	if (status) {
		my_print("[Pass]\n");
	} else {
		my_print("[Failed]\n");
	}

	my_print("- SM3_256: ");
	//
	// SM3_256 digest Validation
	//
	my_print("HashAll... ");
	zero_mem(digest, SM3_256_DIGEST_SIZE);
	status = sm3_256_hash_all(m_hash_data, data_size, digest);
	if (status) {
		if (const_compare_mem(digest, m_sm3_256_digest,
				SM3_256_DIGEST_SIZE) == 0) {
			status = TRUE;
		} else {
			status = FALSE;
		}
	}
	if (status) {
		my_print("[Pass]\n");
	} else {
		my_print("[Failed]\n");
	}

	return RETURN_SUCCESS;
}
