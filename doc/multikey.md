# Multikey Guide

In SPDM versions 1.0 through 1.2, for a given negotiated asymmetric algorithm, leaf certificates
throughout all certificate slots needed to use the same private/public key. SPDM 1.3 relaxed this
constraint, so that different certificate chains and asymmetric keys can be used for different
purposes. For example, an endpoint can restrict a key so that it can only sign the L1/L2 transcript,
while a different key can be restricted to only sign the M1/M2 transcript. As such, when a peer
endpoint supports multikey, the local endpoint must ensure that it uses the appropriate key and
certificate slot when signing or verifying messages.

## Endpoint Support for Multikey

SPDM allows an endpoint to support multikey in one of three ways.
1. No support at all (`MULTI_KEY_CAP == 0`).
2. Strict support (`MULTI_KEY_CAP == 1`).
3. Conditional support based on the peer endpoint's preference (`MULTI_KEY_CAP == 2`).

Use `libspdm_set_data`, `LIBSPDM_DATA_OTHER_PARAMS_SUPPORT`, and the
`SPDM_ALGORITHMS_MULTI_KEY_CONN` boolean to specify how libspdm should handle the case when the peer
endpoint's multikey support is conditional (`MULTI_KEY_CAP == 2`).

### Multikey Flow for libspdm Requester

1. Call `libspdm_init_connection` and check that the call is successful.
2. Call `libspdm_get_data` with `LIBSPDM_DATA_MULTI_KEY_CONN_RSP` to determine whether the
   connection utilizes multikey (`true`) or not (`false`). If the value is `true` then continue with
   this flow, else the connection behaves in a single key manner.
3. Call `libspdm_get_digest` and check that the call is successful.
4. For each populated certificate chain slot call `libspdm_get_certificate` and check that each call
   is successful.
4. Use `libspdm_get_data` with `LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK` to query the `KeyUsageMask`
   for each populated certificate slot. Use the `SPDM_KEY_USAGE_BIT_MASK_*` macros to determine the
   legal messages for that certificate slot and key.
