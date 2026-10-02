# TPM Integration Guide for libspdm

This document describes how to use TPM-backed helper APIs with libspdm for secure key handling, measurements, and platform attestation.

---

## CMake Configuration

Configure TPM key handles and certificate chain NV indices at build time. The TPM sample is built
with `CRYPTO=openssl`, `DEVICE=tpm` and `LIBSPDM_TPM_SUPPORT=ON`, and the `LIBSPDM_TPM_*`
variables below have no effect with any other `DEVICE`:

```bash
cmake -B build \
    -DTOOLCHAIN=GCC \
    -DTARGET=Release \
    -DCRYPTO=openssl \
    -DDEVICE=tpm \
    -DLIBSPDM_TPM_SUPPORT=ON \
    -DLIBSPDM_TPM_REQUESTER_SLOT_IDS="0;1" \
    -DLIBSPDM_TPM_REQUESTER_HANDLES="0x81000011;0x81000011" \
    -DLIBSPDM_TPM_REQUESTER_CERTCHAINS="0x1500011;0x1500012" \
    -DLIBSPDM_TPM_RESPONDER_SLOT_IDS="0;1;4" \
    -DLIBSPDM_TPM_RESPONDER_HANDLES="0x81000021;0x81000021;0x81000021" \
    -DLIBSPDM_TPM_RESPONDER_CERTCHAINS="0x1500021;0x1500022;0x1500024"
```

### Configuration Parameters

| Parameter | Description | Format |
|-----------|-------------|--------|
| `LIBSPDM_TPM_REQUESTER_SLOT_IDS` | SPDM requester slot IDs that the following requester handles/certchains map to | Semicolon-separated decimal values, 0..7 |
| `LIBSPDM_TPM_REQUESTER_HANDLES` | TPM persistent key handles for requester | Semicolon-separated hex values |
| `LIBSPDM_TPM_REQUESTER_CERTCHAINS` | NV indices for requester certificate chains | Semicolon-separated hex values |
| `LIBSPDM_TPM_RESPONDER_SLOT_IDS` | SPDM responder slot IDs that the following responder handles/certchains map to | Semicolon-separated decimal values, 0..7 |
| `LIBSPDM_TPM_RESPONDER_HANDLES` | TPM persistent key handles for responder | Semicolon-separated hex values |
| `LIBSPDM_TPM_RESPONDER_CERTCHAINS` | NV indices for responder certificate chains | Semicolon-separated hex values |

**Note:** The `*_SLOT_IDS`, `*_HANDLES`, and `*_CERTCHAINS` lists are mapped by entry position. For example, `LIBSPDM_TPM_RESPONDER_SLOT_IDS="0;1;4"` maps the first responder handle/certchain pair to slot 0, the second pair to slot 1, and the third pair to slot 4. This supports empty/non-contiguous SPDM slots.

The sample reads each Responder slot's certificate chain from that slot's NV index, and the
Requester's chain from its slot 0 NV index. It does not select the signing key by slot: it signs
with the handle configured for the slot whose ID equals the KeyPairID that libspdm passes to the
signing functions, and with the slot 0 handle when no such slot exists. Without multiple keys
that KeyPairID is always 0, so every slot signs with the slot 0 handle and every Responder slot's
certificate chain must be for that key. This is why the example above, like the default
configuration, uses one handle for all slots.

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

if (!libspdm_tpm_get_pvt_key_handle("handle:0x81000021", &priv_ctx)) {
    printf("Failed to get private key\n");
    return -1;
}
```

- The key is named as the OpenSSL TPM provider expects, such as `"handle:0x81000021"`.
  The generated `LIBSPDM_TPM_HANDLE_*_HANDLE_SLOT_n` macros have this form.
- Opaque handle
- Used for signing (SPDM `CHALLENGE_AUTH`)

---

### Public Key Handle

```c
void *pub_ctx = NULL;

if (!libspdm_tpm_get_pub_key_handle("handle:0x81000021", &pub_ctx)) {
    printf("Failed to get public key\n");
    return -1;
}
```

The key is named the same way as for the private key handle. Used for certificate and verification
flows.

---

## Reading PCR Values

```c
uint8_t buffer[64];
size_t size = sizeof(buffer);

if (!libspdm_tpm_read_pcr(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer,
                          &size)) {
    printf("Failed to read PCR\n");
    return -1;
}
```

- `hash_algo`: the PCR bank, as an SPDM `MeasurementHashAlgo` value
- `index`: PCR number

---

## Reading TPM NV Storage

```c
void *nv_data = NULL;
size_t nv_size = 0;

if (!libspdm_tpm_read_nv(0x1500021, &nv_data, &nv_size)) {
    printf("Failed to read NV index\n");
    return -1;
}

/* Use nv_data, then release it. */
free(nv_data);
```

Used for certificates and persistent data. The function allocates the returned buffer, which the
caller frees with `free()`. The sample reads certificate chains from the NV indices that the build
generates as `LIBSPDM_TPM_HANDLE_*_CERTCHAIN_SLOT_n`.

---

## SPDM Mapping

| SPDM Operation   | TPM API                          |
| ---------------- | -------------------------------- |
| `CERTIFICATE`    | `libspdm_tpm_read_nv`            |
| `CHALLENGE_AUTH` | `libspdm_tpm_get_pvt_key_handle` |
| `MEASUREMENTS`   | `libspdm_tpm_read_pcr`           |
| `KEY_EXCHANGE`   | TPM-backed keys                  |

---

## Testing with spdm-emu + swtpm

You can test TPM-backed libspdm integration using the official SPDM emulator:

[SPDM-EMU DOCS](https://github.com/DMTF/spdm-emu/blob/main/doc/)
