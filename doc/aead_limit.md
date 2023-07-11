# AEAD limit

## document

https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits describes how to limit the use of keys in order to bound the advantage given to an attacker.

## sequence number based limitation

DSP0277 defines 64bit sequence number. The default value is max number 0xFFFFFFFFFFFFFFFFull (64bit).

The Integrator can use `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` to override the default value, such as 0xFFFFFFFF (32bit) or 0xFFFFFF (24bit).

If KEY_UPDATE is not sent before the max sequence number is reached, the SPDM session will be terminated.
