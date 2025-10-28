# Multikey Guide

In SPDM versions 1.0 through 1.2, for a given negotiated asymmetric algorithm, leaf certificates
throughout all certificate slots needed to use the same private/public key. SPDM 1.3 relaxed this
constraint, so that different certificate chains and asymmetric keys can be used for different
purposes. For example, an endpoint can restrict a key so that it can only sign the L1/L2 transcript,
while a different key can be restricted to only sign the M1/M2 transcript. As such, when a peer
endpoint supports multikey, the local endpoint must ensure that it uses the appropriate key and
certificate slot when signing or verifying messages.

## libspdm Endpoint Support for Multikey

SPDM allows an endpoint to support multikey in one of three ways.
1. No support at all (`MULTI_KEY_CAP == 0`).
2. Strict support (`MULTI_KEY_CAP == 1`).
3. Conditional support based on the peer endpoint's preference (`MULTI_KEY_CAP == 2`).

Use `libspdm_set_data`, `LIBSPDM_DATA_OTHER_PARAMS_SUPPORT`, and the
`SPDM_ALGORITHMS_MULTI_KEY_CONN` boolean to specify how libspdm should handle the case when the peer
endpoint's multikey support is conditional (`MULTI_KEY_CAP == 2`).

## Multikey Flow for Requester

1. Call `libspdm_init_connection` and check that the call is successful.
2. Proceed through the "Responder Sign / Requester Verify Flow".
3. If Requester's `MULTI_KEY_CAP` is non-zero, then proceed through the
   "Requester Sign / Responder Verify Flow".

If Requester's `MULTI_KEY_CAP` is non-zero then both `ENCAP_CAP` and `CERT_CAP` must be set.

### Responder Sign / Requester Verify Flow

1. Call `libspdm_get_data` with `LIBSPDM_DATA_MULTI_KEY_CONN_RSP` to determine whether the
   connection utilizes multikey (`true`) or not (`false`). If the value is `true` then continue with
   this flow, else the connection behaves in a single key manner.
2. Call `libspdm_get_digest` and check that the call is successful.
3. For each populated certificate chain slot call `libspdm_get_certificate` and check that each call
   is successful.
4. Use `libspdm_get_data` with `LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK` to query the `KeyUsageMask`
   for each populated certificate slot. Use the `SPDM_KEY_USAGE_BIT_MASK_*` macros to determine the
   legal messages for that certificate slot and key.

### Requester Sign / Responder Verify Flow

1. If Requester's `MULTI_KEY_CAP == 1` then skip to Step 2. If `MULTI_KEY_CAP == 2` then call
   `libspdm_get_data` with `LIBSPDM_DATA_MULTI_KEY_CONN_REQ` to determine whether the connection
   utilizes multikey (`true`) or not (`false`). If it is `true` then continue to Step 2.
2. Call `libspdm_set_data` with `LIBSPDM_DATA_LOCAL_KEY_PAIR_ID` and
   `LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK` to map `KeyPairID`s with certificate slots for the
    negotiated asymmetric cryptography algorithm (`ReqBaseAsymAlg` or `ReqPqcAsymAlg`) and to
    specify the messages a key can be associated with.
    - If `MULTI_KEY_CAP == 1` and the Requester supports only one asymmetric cryptography
      algorithm for signing then this step can be performed before the connection is
      established.
3. Calls to `libspdm_requester_data_sign` then specify the `KeyPairID`.

## Multikey Flow for Responder

### Responder Sign / Requester Verify Flow

1. If Responder's `MULTI_KEY_CAP == 1` then skip to Step 2. If `MULTI_KEY_CAP == 2` then, after
   `VCA` has completed and the connection status has transitioned to
   `LIBSPDM_CONNECTION_STATE_NEGOTIATED`, call `libspdm_get_data` with
   `LIBSPDM_DATA_MULTI_KEY_CONN_RSP` to determine whether the connection utilizes multikey (`true`)
   or not (`false`). If it is `true` then continue to Step 2.
2. Call `libspdm_set_data` with `LIBSPDM_DATA_LOCAL_KEY_PAIR_ID` and
   `LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK` to map `KeyPairID`s with certificate slots for the
    negotiated asymmetric cryptography algorithm (`BaseAsymSel` or `PqcAsymSel`) and to specify
    the messages a key can be associated with.
    - If `MULTI_KEY_CAP == 1` and the Responder supports only one asymmetric cryptography
      algorithm for signing then this step can be performed before the connection is
      established.
3. Calls to `libspdm_responder_data_sign` then specify the `KeyPairID`.

### Requester Sign / Responder Verify Flow

TBD.
