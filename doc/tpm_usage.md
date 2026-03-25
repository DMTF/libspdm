# TPM Integration Guide for libspdm

This document describes how to use TPM-backed helper APIs with libspdm for secure key handling, measurements, and platform attestation.

---

## Overview

The TPM integration layer provides:

- Private key protection (keys never leave TPM)
- Public key access for SPDM flows
- PCR reads for measurements
- NV storage access for certificates/config

These APIs are designed to plug into libspdm cryptographic and measurement flows.

---

## Initialization

Before using any TPM functionality, the TPM backend must be initialized.

```c
if (!libspdm_tpm_device_init()) {
    printf("TPM initialization failed\n");
    return -1;
}
```

### What happens internally

- Connects to TPM (hardware or simulator like `swtpm`)
- Initializes TPM context
 
**Must be called **once** during platform initialization.**

---

## Using TPM-backed Keys

### Private Key Handle

```c
void *priv_ctx = NULL;

if (!libspdm_tpm_get_pvt_key_handle(NULL, &priv_ctx)) {
    printf("Failed to get private key\n");
    return -1;
}
```

- Opaque handle
- Used for signing (SPDM CHALLENGE_AUTH)

---

### Public Key Handle

```c
void *pub_ctx = NULL;

if (!libspdm_tpm_get_pub_key_handle(NULL, &pub_ctx)) {
    printf("Failed to get public key\n");
    return -1;
}
```

Used for certificate and verification flows.

---

## Reading PCR Values

```c
uint8_t buffer[64];
size_t size = sizeof(buffer);

if (!libspdm_tpm_read_pcr(HASH_ALGO_SHA256, 0, buffer, &size)) {
    printf("Failed to read PCR\n");
    return -1;
}
```

- `hash_algo`: PCR bank
- `index`: PCR number

---

## Reading TPM NV Storage

```c
void *nv_data = NULL;
size_t nv_size = 0;

if (!libspdm_tpm_read_nv(TPM_NV_INDEX_SPDM_CERT, &nv_data, &nv_size)) {
    printf("Failed to read NV index\n");
    return -1;
}
```

Used for certificates and persistent data.

---

## SPDM Mapping

| SPDM Operation | TPM API                        |
| -------------- | ------------------------------ |
| CERTIFICATE    | libspdm_tpm_read_nv            |
| CHALLENGE_AUTH | libspdm_tpm_get_pvt_key_handle |
| MEASUREMENTS   | libspdm_tpm_read_pcr           |
| KEY_EXCHANGE   | TPM-backed keys                |

---

## Testing with spdm-emu + swtpm

You can test TPM-backed libspdm integration using the official SPDM emulator:

[SPDM-EMU DOCS](https://github.com/DMTF/spdm-emu/blob/main/doc/)
