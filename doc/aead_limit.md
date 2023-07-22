# AEAD limit

## document

[RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) defines AEAD algorithm. [IETF AEAD Limits (Draft)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits) describes how to limit the use of keys in order to bound the advantage given to an attacker.

NOTE: This is irrelevant to the plaintext bit length limitation (2^39 - 256), which is already defined in [AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) 5.2.1.1.

## sequence number based limitation

[DSP0277](https://www.dmtf.org/dsp/DSP0277) defines 64bit sequence number. The default value is max number 0xFFFFFFFFFFFFFFFFull (64bit).

The Integrator can set `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` to override the default value, such as 0xFFFFFFFF (32bit) or 0xFFFFFF (24bit).

The Integrator may get `LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_REQ_DIR` and `LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_RSP_DIR` to know the current number of messages that have been encrypted / decrypted in requester and responder direction, and trigger `KEY_UPDATE` flow.

If `KEY_UPDATE` is not sent before the max sequence number is reached, the SPDM session will be terminated.
