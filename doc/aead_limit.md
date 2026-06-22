# AEAD limit

## Documents

[RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) defines AEAD algorithms.
[IETF AEAD Limits (Draft)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits)
describes how to limit the use of keys in order to bound the advantage given to an attacker.

NOTE: This is irrelevant to the plaintext bit length limitation (2^39 - 256), which is already
defined in [AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) 5.2.1.1.

## Sequence number based limitation

[DSP0277](https://www.dmtf.org/dsp/DSP0277) defines a 64-bit sequence number. The default value is
the maximum 64-bit value: 0xFFFFFFFFFFFFFFFF.

The Integrator can set `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` to override the default
value, such as 0xFFFFFFFF (32-bit) or 0xFFFFFF (24-bit).

The Integrator may query `LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_REQ_DIR` and
`LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_RSP_DIR` to get the current number of messages that have been
encrypted / decrypted in the request and response directions, and may trigger a `KEY_UPDATE`
accordingly.

If `KEY_UPDATE` is not sent before the maximum sequence number is reached, the SPDM session will be
terminated.

## Negotiated AEAD limit (DSP0277 1.3)

[DSP0277](https://www.dmtf.org/dsp/DSP0277) version 1.3 defines a Secured Message opaque data
element `AEADlimitOE` (`SMDataID` = 2) that carries a 1-byte `AeadLimitExponent`. The AEAD limit is
`2 ^ AeadLimitExponent` messages, and `AeadLimitExponent` shall not exceed 64. When the element is
absent, the default exponent is 64 (i.e. the full 64-bit sequence number space).

This element is exchanged in the opaque data of the Session-Secrets-Exchange request and response
(`KEY_EXCHANGE` / `KEY_EXCHANGE_RSP` and `PSK_EXCHANGE` / `PSK_EXCHANGE_RSP`), and both the Requester
and the Responder populate it.

Opaque data elements are not ordered, so `AEADlimitOE` is parsed regardless of where it appears
relative to the version-selection / supported-version elements. However, the element is only defined
for secured message version 1.3 and later, so it is tied to the negotiated secured message version:

* The Requester advertises `AEADlimitOE` whenever its local secured message version list includes
  1.3 (it does not yet know which version the Responder will select).
* The Responder advertises `AEADlimitOE` only when it selects secured message version 1.3 or later.
* When the negotiated secured message version is older than 1.3, a received `AEADlimitOE` is ignored
  (treated as absent, default exponent 64) even if the peer included it.

### Single source of truth

There is exactly one Integrator-settable knob for the AEAD limit:
`LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` (set with `LIBSPDM_DATA_LOCATION_LOCAL`). There is no
separate "exponent" setting; the value advertised on the wire is *derived* from this cap, so the two
can never disagree.

Because the session sequence number is checked with
`sequence_number >= max_spdm_session_sequence_number`, a cap of `2 ^ e` messages is stored as
`(2 ^ e) - 1`. The `AeadLimitExponent` this endpoint advertises is therefore the inverse:

```
AeadLimitExponent = floor(log2(max_spdm_session_sequence_number + 1))
```

* The default cap `0xFFFFFFFFFFFFFFFF` maps to exponent 64 (the spec default), and avoids computing
  `2 ^ 64` (which does not fit in a 64-bit value).
* A power-of-two-minus-one cap (e.g. `0xFFFFFFFF` -> 32, `0xFFFFFF` -> 24) maps to its exact
  exponent.
* A cap that is not of the form `2 ^ e - 1` rounds the advertised exponent *down* to the nearest
  representable AEAD limit, i.e. the advertised limit is always `<=` the configured cap (the safe
  direction).

### Establishment and enforcement

Once the session is established, each endpoint sets the session's effective maximum sequence number
to the minimum of:

* its own configured cap (`LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER`), and
* the peer's advertised AEAD limit of `2 ^ peer_AeadLimitExponent` messages (stored as
  `(2 ^ peer_AeadLimitExponent) - 1`).

So neither side's limit is ever raised by the other. When the session sequence number reaches this
effective maximum, the session is terminated unless a `KEY_UPDATE` (which resets the sequence number)
is performed first.

### Reading the negotiated value

The Integrator can read the per-session effective maximum sequence number by calling
`libspdm_get_data` with `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` and
`LIBSPDM_DATA_LOCATION_SESSION` (with the session ID in `additional_data`). The same data ID with
`LIBSPDM_DATA_LOCATION_LOCAL` returns the global Integrator-configured cap. The advertised exponent,
if needed, is `floor(log2(value + 1))`.

The per-session maximum sequence number is read-only. It is derived once, at session establishment,
from `min(configured cap, peer AEAD limit)` and is owned by the negotiation result. `libspdm_set_data`
with `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` and `LIBSPDM_DATA_LOCATION_SESSION` is rejected;
only the context-level (`LIBSPDM_DATA_LOCATION_LOCAL`) cap is settable.
