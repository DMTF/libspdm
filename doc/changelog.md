# libspdm 3.8 -> 4.0 Change Log

## New Features
- Support for SPDM 1.4, aligned with DSP0274 version 1.4.1, and for secured messages version 1.3,
  aligned with DSP0277 version 1.3.0. `SLOT_MANAGEMENT` and Responder-initiated `END_SESSION` are
  not yet implemented.
- Post-quantum cryptography, with OpenSSL only: ML-DSA and SLH-DSA signatures, and ML-KEM key
  establishment, including FIPS known-answer tests.
- Redesigned Responder encapsulated request flow. The Integrator registers a single flow handler
  instead of initializing each encapsulated state individually. See the
  [encapsulated flow user guide](encapsulated_flow_user_guide.md).
- TPM support for OpenSSL builds: `LIBSPDM_TPM_SUPPORT` adds TPM helpers, and `DEVICE=tpm` selects a
  TPM-backed device secret library. See [tpm_usage.md](tpm_usage.md).

## Library API Changes
- New `/include/hal/library` headers that the Integrator must implement:
    - Post-quantum primitives:
        - `cryptlib/cryptlib_mldsa.h`
        - `cryptlib/cryptlib_mlkem.h`
        - `cryptlib/cryptlib_slhdsa.h`
    - `responder/keyexlib.h`
        - `libspdm_key_exchange_start_mut_auth`
        - `libspdm_key_exchange_rsp_opaque_data`
        - `libspdm_finish_rsp_opaque_data`
- New HAL functions in existing headers:
    - `responder/asymsignlib.h` - `libspdm_challenge_start_mut_auth`, which with
      `libspdm_key_exchange_start_mut_auth` replaces the mutual authentication data items.
    - `responder/psklib.h` - `libspdm_psk_exchange_rsp_opaque_data` and
      `libspdm_psk_finish_rsp_opaque_data`.
    - `responder/setcertlib.h` - `libspdm_update_local_cert_chain`, which replaces
      `libspdm_write_certificate_to_nvm`, and `libspdm_get_cert_chain_slot_storage_size`.
    - `eventlib.h` - `libspdm_generate_event_list`, which generates the events to send in
      `SEND_EVENT`.
    - `cryptlib/cryptlib_cert.h` - `libspdm_mldsa_get_public_key_from_x509` and
      `libspdm_slhdsa_get_public_key_from_x509`.
- HAL functions removed:
    - `libspdm_write_certificate_to_nvm` - replaced by `libspdm_update_local_cert_chain`.
    - `libspdm_gen_csr_ex` - merged into `libspdm_gen_csr`, which also takes the post-quantum
      algorithm.
    - The HMAC context functions in `cryptlib/cryptlib_mac.h`, such as `libspdm_hmac_sha256_new`,
      `libspdm_hmac_sha256_update` and `libspdm_hmac_sha256_duplicate`. Only the one-shot
      functions, such as `libspdm_hmac_sha256_all`, remain.
- The SPDM context is now always the first parameter of these HAL functions, because
  `LIBSPDM_HAL_PASS_SPDM_CONTEXT` has been removed:
    - `libspdm_challenge_opaque_data`
    - `libspdm_encap_challenge_opaque_data`
    - `libspdm_gen_csr`
    - `libspdm_generate_measurement_summary_hash`
    - `libspdm_is_in_trusted_environment`
    - `libspdm_measurement_collection`
    - `libspdm_measurement_opaque_data`
    - `libspdm_requester_data_sign`
    - `libspdm_responder_data_sign`
- The watchdog HAL functions take the SPDM context as their first parameter:
    - `libspdm_start_watchdog`
    - `libspdm_stop_watchdog`
    - `libspdm_reset_watchdog`
- These HAL functions take the session in which the request was received, or `NULL` outside a
  session:
    - `libspdm_gen_csr`
    - `libspdm_generate_device_endpoint_info`
    - `libspdm_is_in_trusted_environment`
    - `libspdm_measurement_collection`
    - `libspdm_measurement_extension_log_collection`
    - `libspdm_measurement_opaque_data`
    - `libspdm_read_key_pair_info`
    - `libspdm_write_key_pair_info`
- These HAL functions take the Context field of the request, from SPDM 1.3:
    - `libspdm_challenge_opaque_data` and `libspdm_encap_challenge_opaque_data` - in place of the
      measurement summary hash.
    - `libspdm_measurement_collection` - along with the Requester's nonce and the slot ID when a
      signature is requested.
    - `libspdm_measurement_opaque_data`
- The HAL signing functions take the key pair ID of the slot whose key is to be used, along with the
  post-quantum algorithm:
    - `libspdm_requester_data_sign`
    - `libspdm_responder_data_sign`
- Key pair functions carry the post-quantum algorithms:
    - `libspdm_get_key_pair_info` and `libspdm_set_key_pair_info`, in the Requester library.
    - `libspdm_read_key_pair_info` and `libspdm_write_key_pair_info`, in the HAL.
      `libspdm_read_key_pair_info` also returns the total number of key pairs.
- `libspdm_encap_challenge_opaque_data` is declared only when
  `LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP`, `LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP` and
  `LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP` are all enabled, the only configuration in which the library
  calls it.
- New public functions that build the encapsulated requests, for the encapsulated flow handler to
  call:
    - `libspdm_get_encap_request_challenge`
    - `libspdm_get_encap_request_get_certificate`
    - `libspdm_get_encap_request_get_digests`
    - `libspdm_get_encap_request_get_endpoint_info`
    - `libspdm_get_encap_request_key_update`
    - `libspdm_get_encap_request_send_event`
    - `libspdm_get_encap_payload_size` - the size of the payload that the last encapsulated request
      retrieved.
- `_ex` variants have been merged into their base functions, which absorb the additional parameters:
    - `libspdm_get_csr_ex` into `libspdm_get_csr`.
    - `libspdm_verify_cert_chain_data_ex` and `libspdm_verify_certificate_chain_buffer_ex` into
      `libspdm_verify_cert_chain_data` and `libspdm_verify_certificate_chain_buffer`.
    - `libspdm_x509_certificate_check_ex` and `libspdm_x509_set_cert_certificate_check_ex` into
      `libspdm_x509_certificate_check` and `libspdm_x509_set_cert_certificate_check`. These four
      certificate functions also take the SPDM version and the post-quantum algorithm.
    - `libspdm_get_certificate_choose_length_ex` into `libspdm_get_certificate_ex`, which takes the
      block length, or 0 for the default.
- `libspdm_start_session_ex` is split into `libspdm_start_session_exchange`, which sends
  `KEY_EXCHANGE` or `PSK_EXCHANGE`, and `libspdm_start_session_finish`, which sends `FINISH` or
  `PSK_FINISH`. `libspdm_start_session` is unchanged.
- Library APIs with changes:
    - `libspdm_get_peer_cert_chain_buffer`, `libspdm_get_peer_cert_chain_data`,
      `libspdm_get_local_cert_chain_buffer` and `libspdm_get_local_cert_chain_data` take the slot
      ID, and all but `libspdm_get_local_cert_chain_data` return `void`. The two peer functions
      exist only when `LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT` is enabled.
    - `libspdm_heartbeat` and `libspdm_key_update` require `LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP` or
      `LIBSPDM_ENABLE_CAPABILITY_PSK_CAP`, and `libspdm_heartbeat` also requires
      `LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP`. The `libspdm_challenge` functions require
      `LIBSPDM_SEND_CHALLENGE_SUPPORT`.
    - `libspdm_vendor_send_request_receive_response` - the request and response sizes are
      `uint32_t`, for SPDM 1.4 large payloads.
    - `libspdm_vendor_response_callback_func` - always takes the session ID, and the request and
      response sizes are `uint32_t`.
    - `libspdm_init_fips_selftest_context` - takes a buffer of the size that
      `libspdm_get_fips_selftest_buffer_size` returns.
    - `libspdm_process_event_func` - the vendor ID and event detail are `const`.
    - `libspdm_check_context` - fails for a Responder with `PUB_KEY_ID_CAP` whose SPDM versions
      include 1.0, which has no provisioned public keys. `LIBSPDM_DATA_IS_REQUESTER` should be set
      before it is called.
    - `libspdm_verify_req_info` - exists only when `LIBSPDM_CERT_PARSE_SUPPORT` is enabled.
- Library APIs removed:
    - Replaced by the registered encapsulated flow handler:
        - `libspdm_init_get_endpoint_info_encap_state`
        - `libspdm_init_key_update_encap_state`
        - `libspdm_init_key_update_encap_state_with_session`
        - `libspdm_register_get_endpoint_info_callback_func`
    - `libspdm_register_cert_chain_buffer`
    - `libspdm_register_vendor_get_id_callback_func` - `VENDOR_DEFINED_RESPONSE` uses the standard
      ID and vendor ID of the request.
    - `libspdm_secured_message_import_dhe_secret` - replaced by
      `libspdm_secured_message_import_shared_secret`.
    - `libspdm_hmac_new`, `libspdm_hmac_free`, `libspdm_hmac_init`, `libspdm_hmac_update`,
      `libspdm_hmac_final` and `libspdm_hmac_duplicate` - unused by the library, which computes
      every HMAC with `libspdm_hmac_all`.
    - `libspdm_transport_get_header_size_func` - unused by the library.
- Library APIs added:
    - `libspdm_register_encap_flow_handler` - registers the Responder encapsulated request flow.
    - `libspdm_register_meas_log_reset_callback` - notifies the Integrator when the L1/L2
      measurement transcript is reset, to support the Content Changed field of `MEASUREMENTS`.
    - `libspdm_get_slot_storage_size` - retrieves the storage size of a certificate slot.
    - `libspdm_get_supported_algorithms` - retrieves the Responder's supported algorithms from
      `CAPABILITIES`. It requires `LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP`.
    - `libspdm_send_event` - sends events to a Responder that subscribes to them.
    - `libspdm_send_receive_spdm_data` - sends an SPDM message and receives the response, handling
      chunking.
    - `libspdm_terminate_session` - lets the Responder terminate a session, for example when the
      watchdog fires.
    - `libspdm_contains_hardware_id_oid` - checks a certificate for the SPDM hardware identity OID.
    - `libspdm_get_fips_selftest_buffer_size` - the size of the buffer that
      `libspdm_init_fips_selftest_context` takes.
    - Cryptography functions in `spdm_crypt_lib.h` for post-quantum signatures (`libspdm_pqc_asym_*`
      and `libspdm_req_pqc_asym_*`) and KEM (`libspdm_kem_*`), and size functions such as
      `libspdm_get_kem_cipher_text_size` and `libspdm_get_dhe_shared_secret_size`.
    - `libspdm_generate_handshake_key` and `libspdm_generate_data_key` - the SPDM key schedule.
- Library macros:
    - `LISBPDM_STORAGE_SECURED_MESSAGE_DESCRIPTOR_MIN_SIZE` is renamed to
      `LIBSPDM_STORAGE_SECURED_MESSAGE_DESCRIPTOR_MIN_SIZE`.
    - `LIBSPDM_TCP_TRANSPORT_HEADER_SIZE` and `LIBSPDM_TCP_TRANSPORT_TAIL_SIZE` are added.
    - `LIBSPDM_MAX_ASYM_KEY_SIZE` is removed.
- Data Set/Get removed:
    - The Responder now starts mutual authentication through the HAL:
        - `LIBSPDM_DATA_MUT_AUTH_REQUESTED`
        - `LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED`
        - `LIBSPDM_DATA_MANDATORY_MUT_AUTH`
    - `LIBSPDM_DATA_PEER_TOTAL_DIGEST_BUFFER` - the Requester gets the digests through the
      `total_digest_buffer` parameter of `libspdm_get_digest`.
    - `LIBSPDM_DATA_TOTAL_KEY_PAIRS` - the Responder obtains the key pair count through
      `libspdm_read_key_pair_info`.
- Data Set/Get added:
    - Post-quantum algorithm selection:
        - `LIBSPDM_DATA_PQC_ASYM_ALGO`
        - `LIBSPDM_DATA_REQ_PQC_ASYM_ALG`
        - `LIBSPDM_DATA_KEM_ALG`
    - `LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST` - the Responder selects post-quantum algorithms over
      traditional ones when both endpoints support both.
    - `LIBSPDM_DATA_CAPABILITY_EXT_FLAGS` - extended capability flags.
    - `LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID` - the Requester's certificate slot for mutual
      authentication within a session, sent in the final `ENCAPSULATED_RESPONSE_ACK`.
    - `LIBSPDM_DATA_SESSION_SECURED_MESSAGE_VERSION` - secured message version of a session.
- Data Set/Get changed:
    - `LIBSPDM_DATA_SECURED_MESSAGE_VERSION` can only be set, at `LIBSPDM_DATA_LOCATION_LOCAL`. The
      negotiated version is per session, and `LIBSPDM_DATA_SESSION_SECURED_MESSAGE_VERSION` reads
      it.
    - `LIBSPDM_DATA_CAPABILITY_FLAGS` asserts that a flag is clear when its
      `LIBSPDM_ENABLE_CAPABILITY_*_CAP` switch is disabled, for every switch. 3.8 checked only
      `CERT_CAP`, `CHAL_CAP`, `MEAS_CAP`, `MEL_CAP`, `KEY_EX_CAP`, `PSK_CAP` and `EP_INFO_CAP`.
    - `LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT` is available only when `LIBSPDM_CERT_PARSE_SUPPORT` is
      enabled.

## Industry Standard Header Changes
- The `/include/industry_standard` headers add the definitions of SPDM 1.4, DSP0277 1.3, PCIe 6.5
  (DOE, IDE_KM and TDISP) and CXL 4.0 (TSP).
- Macros renamed:
    - `SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY`,
      `SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS` and
      `SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY` are renamed to
      `SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY`, `SPDM_KEY_UPDATE_OPERATIONS_UPDATE_ALL_KEYS` and
      `SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY`.
    - `SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH` is renamed to `SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM`.
- Macro values changed:
    - `SPDM_MAX_VERSION_COUNT` is incremented from 4 to 5 to accommodate SPDM 1.4.
    - `SECURED_SPDM_MAX_VERSION_COUNT` is incremented from 3 to 4 to accommodate DSP0277 1.3.
    - `SPDM_REGISTRY_ID_MAX` is incremented from 0xA to 0xB for `SPDM_REGISTRY_ID_DMTF_DSP`.
    - `SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK` is 0x3, for the `OpaqueDataFmt0` and
      `OpaqueDataFmt1` bits. It was 0xF.
    - `SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK` is 0x7F, for
      `DMTFSpecMeasurementValueType[6:0]`. It was 0x7.
    - `SPDM_MAX_VENDOR_ID_LENGTH` is 9, the size of the longest `VendorID`, an encoded CBOR tag
      number. It was 255.
    - `PCI_IDE_KM_KEY_SUB_STREAM_MASK` is 0x70, for the 3-bit Key Sub-Stream field. It was 0xF0.
    - `CXL_TSP_SET_CKID_SPECIFIC_KEY_CKID_TYPE_TVM_CKID` and
      `CXL_TSP_SET_CKID_SPECIFIC_KEY_CKID_TYPE_OS_CKID` are 0 and 1, as CXL 4.0 defines them. They
      were 1 and 2.
- Structures changed:
    - `spdm_cert_chain_t` has a single `uint32_t length`, as DSP0274 1.4 defines, in place of
      `uint16_t length` and `uint16_t reserved`. A chain of at most 0xFFFF bytes is encoded as
      before, but code that sets `reserved` must drop it.
    - Reserved fields that SPDM 1.4 defines are renamed. `reserved2` is `ext_flags` in
      `spdm_get_capabilities_request_t` and `spdm_capabilities_response_t`. The first four bytes of
      `reserved2` are `pqc_asym_algo` in `spdm_negotiate_algorithms_request_t` and `pqc_asym_sel` in
      `spdm_algorithms_response_t`.
    - `pci_ide_km_query_resp_t` - `reserved` is renamed to `caps`.
    - `pci_tdisp_bind_p2p_stream_request_t` - the new `stream_config` field makes the request one
      byte longer.
    - `cxl_tsp_get_target_capabilities_rsp_t` - `uint16_t reserved2` is split into
      `uint8_t additional_capabilities` and `uint8_t reserved2`.

## Configuration Macro Changes
- Configuration macros removed:
    - `LIBSPDM_HAL_PASS_SPDM_CONTEXT` - the SPDM context is always passed to the HAL functions
      listed above.
    - `LIBSPDM_PASS_SESSION_ID` - the session ID is always passed to
      `libspdm_vendor_response_callback_func`.
    - `LIBSPDM_SET_CERT_CSR_PARAMS` - the `SET_CERTIFICATE` and CSR parameters are always passed.
    - `LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX` - `libspdm_get_csr_ex` and the HAL's
      `libspdm_gen_csr_ex` are merged into `libspdm_get_csr` and `libspdm_gen_csr`.
    - `LIBSPDM_ADDITIONAL_CHECK_CERT` - the additional certificate checks are no longer optional, so
      a cryptography library must implement `libspdm_x509_get_signature_algorithm`.
    - `LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN` - the Requester passes the `GET_CERTIFICATE` block length
      to `libspdm_get_certificate_ex`, and by default it is the largest that fits in the maximum
      SPDM message size. The `CERTIFICATE` portions that an endpoint sends, and the length that the
      Responder requests in an encapsulated `GET_CERTIFICATE`, are limited only by the message size.
    - `LIBSPDM_MAX_MEL_BLOCK_LEN` - the `GET_MEASUREMENT_EXTENSION_LOG` block length is the largest
      that fits in the maximum SPDM message size.
    - `LIBSPDM_OPENSSL_STDINT_WORKAROUND` - `hal/base.h` no longer undefines `_WIN32` and `_WIN64`.
- Configuration macros added:
    - ML-DSA parameter sets:
        - `LIBSPDM_ML_DSA_44_SUPPORT`
        - `LIBSPDM_ML_DSA_65_SUPPORT`
        - `LIBSPDM_ML_DSA_87_SUPPORT`
    - ML-KEM parameter sets:
        - `LIBSPDM_ML_KEM_512_SUPPORT`
        - `LIBSPDM_ML_KEM_768_SUPPORT`
        - `LIBSPDM_ML_KEM_1024_SUPPORT`
    - SLH-DSA parameter sets:
        - `LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT`
        - `LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT`
- Configuration macros changed:
    - `LIBSPDM_MAX_CERT_CHAIN_SIZE` and `LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE` are defined only when
      `LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT` is enabled.
    - `LIBSPDM_MAX_CERT_CHAIN_SIZE` defaults to 0x28000 when an SLH-DSA parameter set is enabled, as
      they all are by default, and to 0x8000 when only ML-DSA is. It was 0x1000, which remains the
      default otherwise.
    - `LIBSPDM_MAX_ROOT_CERT_SUPPORT` is defined only when `LIBSPDM_CERT_PARSE_SUPPORT` is enabled.
    - `LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP` gates `libspdm_heartbeat` and the Responder's
      `HEARTBEAT` handling, not only the watchdog. When it is disabled, the Responder sends a
      `HeartbeatPeriod` of 0.
- New configuration requirements, which `libspdm_macro_check.h` checks when `LIBSPDM_CHECK_MACRO` is
  enabled:
    - Any DHE or ML-KEM algorithm requires `LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP`.
    - Any signature algorithm requires `LIBSPDM_ENABLE_CAPABILITY_CERT_CAP`,
      `LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP` or `LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP`.
    - `LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP` requires
      `LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP`.
    - `LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT` requires `LIBSPDM_CERT_PARSE_SUPPORT`.

## Build Changes
- VS2015 is no longer supported, and `TOOLCHAIN=VS` replaces `VS2019` and `VS2022`. MSVC builds use
  `/std:c11`, which needs Visual Studio 2019 version 16.8 or later.
- New `LOONGARCH64_GNU` toolchain.
- libspdm builds on macOS with `TOOLCHAIN=CLANG`.
- libspdm builds on Windows on Arm with `ARCH=aarch64` and `TOOLCHAIN=VS` or `CLANG`. Without
  `ARCH`, MSVC and clang-cl builds take the architecture that the compiler targets, not the host's.
- `os_stub` implementations of the debug and random number libraries, and of `libspdm_sleep`, for
  Zephyr.
- New `X509_IGNORE_TIME` option, which makes the provided cryptography libraries ignore the validity
  period of certificates.
- Mbed TLS is updated from 3.6.2 to 3.6.7, OpenSSL from 3.5.1 to 3.5.9, and cmocka, which the unit
  tests use, from 1.1.7 to 1.1.8.
- OpenSSL is built by its own `Configure` script, which needs Perl, as a shared `libcrypto`, or a
  static one when `TOOLCHAIN=NONE`.
- `ENABLE_BINARY_BUILD=1` no longer disables EdDSA.
- CMake 3.16 or later is required, and 3.19 or later for `ARM_DS2022`. `TOOLCHAIN` selects a
  toolchain file from `cmake/toolchain`, unless `CMAKE_TOOLCHAIN_FILE` is given.
- libspdm's own targets build as C99, except that MSVC, which has no C99 mode, uses C11, and the
  sample device secret library is C11. Their warning options and configuration definitions no longer
  apply to Mbed TLS, OpenSSL or cmocka.
- The Windows build instructions for MinGW and ARM DS2022 use the MSYS2 UCRT64 environment instead
  of MINGW64.
- The KLEE and CBMC toolchains are removed.
- The VS toolchains build with CMake's default runtime library, `/MD` or `/MDd`.
- The GCC and Clang toolchains no longer pass `-fshort-wchar`, `-fpie` or `-no-pie`, and Windows
  ia32 Mbed TLS builds no longer define `EFI32`.
- The `os_stub` headers `cryptlib_ext.h`, `spdm_crypt_ext_lib.h` and
  `spdm_device_secret_lib_internal.h` move to `os_stub/include`, as `hal/library/cryptlib_ext.h`,
  `library/spdm_crypt_ext_lib.h` and `internal/libspdm_device_secret_lib.h`.
- `os_stub/openssllib` no longer has `include/crt_support.h`, `buildinf.h`, `process_files.pl`,
  `rand_pool.c` or `timer_wrapper.c`.
- 14 core library source files are renamed after the message that they send, such as
  `libspdm_rsp_finish.c` to `libspdm_rsp_finish_rsp.c`, and 17 are added. An Integrator that lists
  the files in its own build must update the list.

## Additional Changes
- Certificate chain verification in the provided cryptography libraries validates the whole path, as
  RFC 5280 describes. Both libraries enforce `pathLenConstraint`, and OpenSSL also evaluates
  `nameConstraints`, which Mbed TLS does not (Mbed-TLS/mbedtls#8759). It can therefore reject chains
  that 3.8 accepted.
- The TCP transport sets `PayloadLen` to the size of the SPDM message, as DSP0287 requires, where
  3.8 added 2.
- Many bug fixes and further alignment with the SPDM specifications.
