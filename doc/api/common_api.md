# libspdm Common API (DRAFT)

## Introduction
This document details the public API available to Integrators when constructing an SPDM Requester
or Responder using libspdm.

## SPDM Context
libspdm's `spdm_context` stores information about an SPDM endpoint and its connection with another
SPDM endpoint. An Integrator must first populate the `spdm_context` to specify and configure the
endpoint's capabilities. This includes information such as
- The endpoint's SPDM capabilities such `PSK_CAP` or `KEY_EX_CAP`.
- The endpoint's cryptography algorithms such as `RSASSA_2048` or `ECC_NIST_P256`.

---
### libspdm_set_data
---

### Description
Populates an element of the `spdm_context` with the specified value.

### Parameters

**spdm_context**<br/>
The SPDM context.

**data_type**<br/>
An enumeration value that specifies what element of the `spdm_context` to modify.

**parameter**<br/>

**data**<br/>
A pointer to the data that is to be inserted into the `spdm_context`.

**data_size**<br/>
The size, in bytes, of the data that is to be inserted into the `spdm_context`.

### Details
TBD
<br/><br/>


---
### libspdm_get_data
---

### Description
Retrieves an element from the `spdm_context`.

### Parameters

**spdm_context**<br/>
The SPDM context.

**data_type**<br/>
An enumeration value that specifies what element of the `spdm_context` to retrieve.

**parameter**<br/>

**data**<br/>
A pointer to the data that is to be retrieved from the `spdm_context`.

**data_size**<br/>
On input, the size, in bytes, of the buffer to store the `data`.
On output, the size, in bytes, of the `data`.
<br/><br/>

### Details
TBD<br/><br/>


---
### libspdm_data_type_t
---

### Description
Enumeration value used for the `libspdm_set_data` and/or `libspdm_get_data` functions.

### Values that can be both `get` and `set`.
- `LIBSPDM_DATA_SPDM_VERSION`
    - The SPDM (DSP0274) version(s) (1.0, 1.1, or 1.2) of an endpoint. These are communicated
      through the `GET_VERSION / VERSION` messages.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The SPDM version of the peer endpoint.
        - Cannot contain multiple entries.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The SPDM version(s) of the local endpoint.
        - Can contain multiple entries.
- `LIBSPDM_DATA_SECURED_MESSAGE_VERSION`
    - The SPDM secured message (DSP0277) version(s) (1.0 or 1.1) of an endpoint. These are are
      communicated through the `KEY_EXCHANGE / KEY_EXCHANGE_RSP` or `PSK_EXCHANGE / PSK_EXCHANGE`
      messages.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The SPDM secured message version of the peer endpoint.
        - Cannot contain multiple entries.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The SPDM secured message version(s) of the local endpoint.
        - Can contain multiple entries.
- `LIBSPDM_DATA_CAPABILITY_FLAGS`
    - The SPDM capabilities of an endpoint. These are communicated through the `GET_CAPABILITIES /
      CAPABILITIES` messages. This is a bitmask whose fields are defined through the
      `SPDM_GET_CAPABILITIES_*` macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The capabilities of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The capabilities of the local endpoint.
- `LIBSPDM_DATA_CAPABILITY_CT_EXPONENT`
    - `CTExponent` is used to calculate the maximum amount of time (`CT`) an endpoint needs to
      provide a response to messages that require cryptographic processing, such as `CHALLENGE /
      CHALLENGE_AUTH`. The value of `CT` is calculated as `2^CTExponent` and has units of
      microseconds. Though `CTExponent` can range from 0 to 255, libspdm imposes a maximum value of
      `LIBSPDM_MAX_CT_EXPONENT`.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The `CTExponent` value of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The `CTExponent` value of the local endpoint.
- `LIBSPDM_DATA_CAPABILITY_RTT`
    - The SPDM specification defines this value (`RTT`) as "the worst-case round-trip transport
      timing." and is in units of microseconds. This value is only used by a Requester.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The `RTT` of the Requester endpoint.
- `LIBSPDM_DATA_MEASUREMENT_SPEC`
    - This value specifies the measurement specification(s) supported by an endpoint. These are are
      communicated through the `NEGOTIATE_ALGORITHMS / ALGORITHMS` messages. However the SPDM
      specification defines only one value, `DMTFmeasSpec`. If a Requester is not going to retrieve
      measurements from a Responder this can be `0`. This is a bitmask whose fields are defined
      through the `SPDM_MEASUREMENT_SPECIFICATION_*` macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The measurement specification of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The measurement specification of the local endpoint.
- `LIBSPDM_DATA_MEASUREMENT_HASH_ALGO`
    - The algorithm used to hash a Responder's measurements. This is communicated through the
      `ALGORITHMS` message. This is a bitmask whose fields are defined through the
      `SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*` macros. A value of
      `SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY` indicates that the Responder
      cannot provide a hash for any measurement and provides the measurement directly.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The measurement hash algorithm of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The measurement hash algorithm of the local endpoint.
- `LIBSPDM_DATA_BASE_ASYM_ALGO`
    - The asymmetric cryptography algorithm used by the Responder to sign messages. This is a
      bitmask whose fields are defined through the `SPDM_ALGORITHMS_BASE_ASYM_ALGO_*`
      macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The asymmetric cryptography algorithm of the peer endpoint.        -
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The asymmetric cryptography algorithm(s) of the local endpoint.
- `LIBSPDM_DATA_BASE_HASH_ALGO`
    - The hash algorithm used to hash transcripts. This is a bitmask whose fields are defined
      through the `SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_*` macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The hash algorithm of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The hash algorithm(s) of the local endpoint.
- `LIBSPDM_DATA_DHE_NAME_GROUP`
    - The Diffie-Hellman scheme used for key exchange. This is a bitmask whose fields are defined
      through the `SPDM_ALGORITHMS_DHE_NAMED_GROUP_*` macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The Diffie-Hellman scheme of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The Diffie-Hellman scheme(s) of the local endpoint.
- `LIBSPDM_DATA_AEAD_CIPHER_SUITE`
    - The "authenticated encryption with associated data" algorithm used for symmetric cryptography.
      This is a bitmask whose fields are defined through the `SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_*`
      macros
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The AEAD algorithm of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The AEAD algorithms(s) of the local endpoint.
- `LIBSPDM_DATA_REQ_BASE_ASYM_ALG`
    - The asymmetric algorithm used by the Requester to sign messages. This is a bitmask whose
      fields are defined through the `SPDM_ALGORITHMS_BASE_ASYM_ALGO_*` macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The asymmetric cryptography algorithm of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The asymmetric cryptography algorithm(s) of the local endpoint.
- `LIBSPDM_DATA_KEY_SCHEDULE`
    - The key schedule used for both symmetric and asymmetric key exchange. This is communicated
      through the `NEGOTIATE_ALGORITHMS / ALGORITHMS` messages. This is a bitmask whose fields are
      defined through the `SPDM_ALGORITHMS_KEY_SCHEDULE_*` macros.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The key schedule of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The key schedule of the local endpoint.
- `LIBSPDM_DATA_OTHER_PARAMS_SUPPORT`
    - This field is included in the `NEGOTIATE_ALGORITHMS / ALGORITHMS` messages to advertise
      miscellaneous capabilities. This is a bitmask whose fields are defined through the
      `SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_*` macros.
        - `SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0`
            - The format for all `OpaqueData` fields is defined by the device vendor or other
              standards body.
        - `SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1`
            - The format for all `OpaqueData` fields is defined by the SPDM specification's general
            opaque data format.
    - `LIBSPDM_DATA_LOCATION_CONNECTION`
        - The `OtherParams` value of the peer endpoint.
    - `LIBSPDM_DATA_LOCATION_LOCAL`
        - The `OtherParams` value of the local endpoint.
- `LIBSPDM_DATA_CONNECTION_STATE`
    - The connection state of the two endpoints. Since the two endpoints share the same connection
      state the `LIBSPDM_DATA_LOCATION_*` value is not checked. Its value is one of
        - `LIBSPDM_CONNECTION_STATE_NOT_STARTED`
            - The initial state after the SPDM context has been initialized or reset.
        - `LIBSPDM_CONNECTION_STATE_AFTER_VERSION`
            - The state immediately after a successful `GET_VERSION` request and `VERSION` response.
        - `LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES`
            - The state immediately after a successful `GET_CAPABILITIES` request and `CAPABILITIES`
              response.
        - `LIBSPDM_CONNECTION_STATE_NEGOTIATED`
            - The state immediately after a successful `NEGOTIATE_ALGORITHMS` request and
              `ALGORITHMS` response.
        - `LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS`
            - The state immediately after a successful `GET_DIGESTS` request and `DIGESTS` response.
        - `LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE`
            - The state immediately after a successful `GET_CERTIFICATE` request and `CERTIFICATE`
              response.
        - `LIBSPDM_CONNECTION_STATE_AUTHENTICATED`
            - The state immediately after a successful `CHALLENGE` request and `CHALLENGE_AUTH`
              response.
- `LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT`
    - Allows multiple pointers to root certificates to be stored in the `spdm_context`. These root
      certificates are then either compared against the root certificate returned by a peer
      endpoint, or appended to the partial (without root certificate) certificate chain returned by
      a peer endpoint. The root certificate(s) must be encoded as ASN.1 DER.
- `LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN`
    - Allows multiple pointers to certificate chains to be stored in slots through the
      `additional_data` field. A certificate chain can then be returned through a `CERTIFICATE`
      response message. The certificate chain(s) must be encoded as ASN.1 DER.
- `LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER`
    - Allows multiple certificates, or values derived from the certificates, to be stored in the
      `spdm_context`. If `LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT` is `1` then the provided
      certificate chain is copied into the `spdm_context`. If
      `LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT` is `0` then the provided certificate chain is hashed
      and the public key of the leaf certificate is extracted.
- `LIBSPDM_DATA_PEER_PUBLIC_KEY`
    - The raw public key of a peer endpoint. This is used when an endpoint does not support
      certificate chains and instead a public key is provisioned to its peer(s). While the SPDM
      specification does not mandate the format of the public key, libspdm implements the public key
      as described in RFC7250. It is ASN.1 DER-encoded.
- `LIBSPDM_DATA_LOCAL_PUBLIC_KEY`
    - The raw public key of the local endpoint.
- `LIBSPDM_DATA_REQUEST_RETRY_TIMES`
    - Specifies the number of times a Requester will retry a request message if the Responder
      returns a `Busy` error response.
- `LIBSPDM_DATA_REQUEST_RETRY_DELAY_TIME`
    - Specifies the amount of time to wait before resending a request due to a `Busy` error response
      from the Responder.
- `LIBSPDM_DATA_MAX_DHE_SESSION_COUNT`
    - Specifies the maximum number of secure sessions spawned through asymmetric key exchange.
- `LIBSPDM_DATA_MAX_PSK_SESSION_COUNT`
    - Specifies the maximum number of secure sessions spawned through symmetric key exchange.
- `LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY`
    - Specifies how some errors are handled. It is a bitmask whose fields are defined by the
      `LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_*` macros.
    - `LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR`
        - If set then, if the Responder is unable to verify the MAC of an AEAD message, it will not
          provide an `ERROR` response to the Requester. If not set then the Responder will provide
          a `DecryptError` response to the Requester.
- `LIBSPDM_DATA_VCA_CACHE`
    - A buffer that contains the appended `VCA` messages. It can be used to restore connections if
      the endpoints support `CACHE_CAP`.
- `LIBSPDM_DATA_IS_REQUESTER`
    - Specifies if the local endpoint is a Requester (true) or Responder (false).
- `LIBSPDM_DATA_APP_CONTEXT_DATA`
    - Is used to hold a pointer to Integrator-defined data that is tied to the `spdm_context`. Via
      this mechanism an Integrator can extend the `spdm_context`.
- `LIBSPDM_DATA_HEARTBEAT_PERIOD`
    - Specifies the Responder's `HeartbeatPeriod` in units of seconds. This value is communicated to
      the Requester in the `KEY_EXCHANGE_RSP` and `PSK_EXCHANGE_RSP` messages. The actual timeout
      limit is twice the `HeartbeatPeriod`.

### Values that can only be `get`.

- `LIBSPDM_DATA_PEER_SLOT_MASK`
    - The value of the peer's certificate chain slot mask that was returned in the most recent
      `DIGESTS` response. It is a bitmask that indicates if a certificate chain slot is populated,
      where the least significant bit corresponds to slot 0 and the most significant bit corresponds
      to slot 7.
- `LIBSPDM_DATA_PEER_TOTAL_DIGEST_BUFFER`
    - Returns a pointer to the stored hashes of certificate chains in the `spdm_context` from the
      most recent `DIGESTS` response. It also returns the size, in bytes, of the buffer.
- `LIBSPDM_DATA_SESSION_USE_PSK`
    - For a given session ID, returns whether the session was established via symmetric key
      exchange (true) or asymmetric key exchange (false).
- `LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED`
    - For a given session ID, returns whether the Responder has requested mutual authentication with
      the Requester.
- `LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES`
    - For a given session ID, returns the `END_SESSION` request attributes field. This is a bitmask
      whose fields are defined by the `SPDM_END_SESSION_REQUEST_ATTRIBUTES_*` macros.
    - `SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR`
        - If set then the Responder will clear its negotiated connection state derived from `VCA`.
          If not set then Responder will maintain its negotiated connection state.
        - Only valid if the Responder supports `VCA` caching (`CACHE_CAP` is set).
