# libspdm 2.3 -> 3.0 Change Log

## New Features
- Support for FIPS 140-3 including known-answer-tests.
- Raw public keys are now ASN.1 DER encoded.
- Support for OpenSSL 3.0.
- Initial draft for API documentation.

## API Changes
- `/include/hal/library` libraries have been broken out into multiple headers.
- `/library/spdm_device_secret_lib.h` have been deleted.
- Configuration macros removed:
    - `LIBSPDM_MAX_SESSION_COUNT`
    - `LIBSPDM_SCRATCH_BUFFER_SIZE`
    - `LIBSPDM_MAX_SPDM_MSG_SIZE`
    - `LIBSPDM_DATA_TRANSFER_SIZE`
    - `LIBSPDM_TRANSPORT_ADDITIONAL_SIZE`
    - `LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE`
    - `LIBSPDM_MAX_CSR_SIZE`
    - define fine granularity control of crypto algo.
- Configuration macros added:
    - `LIBSPDM_FIPS_MODE`
    - `LIBSPDM_CERT_PARSE_SUPPORT`
    - `LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT`
    - `LIBSPDM_SEND_CHALLENGE_SUPPORT`
    - `LIBSPDM_RESPOND_IF_READY_SUPPORT`
    - `LIBSPDM_CHECK_SPDM_CONTEXT`
- Registered APIs with changes:
    - `libspdm_device_acquire_sender_buffer_func`
    - `libspdm_device_acquire_receiver_buffer_func`
    - `libspdm_register_transport_layer_func`
    - `libspdm_register_device_buffer_func`
- Library APIs with changes
    - All of the functions in `memlib.h`.
    - `libspdm_write_certificate_to_nvm`
    - `libspdm_challenge_ex`
    - `libspdm_get_measurement_ex`
    - `libspdm_get_csr`
    - `libspdm_set_certificate`

## Additional Changes
- Many bug fixes and further alignment with the SPDM specifications.
