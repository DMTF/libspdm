# SPDM requester and responder user guide

This document provides the general information on how to write an SPDM requester or an SPDM responder.

## SPDM requester user guide

Please refer to spdm_client_init() in [spdm_requester.c](https://github.com/DMTF/SPDM-Emu/blob/main/spdm_emu/spdm_emu/spdm_requester_emu/spdm_requester.c)

0. Choose proper SPDM libraries.

   0.1, implement a proper [spdm_device_secret_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_device_secret_lib.h).

   If the requester supports mutual authentication, implement spdm_requester_data_sign().

   If the requester supports measurement, implement spdm_measurement_collection().

   If the requester supports PSK exchange, implement spdm_psk_handshake_secret_hkdf_expand() and spdm_psk_master_secret_hkdf_expand().

   spdm_device_secret_lib must be in a secure environment.

   0.2, choose a proper [spdm_secured_message_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_secured_message_lib.h).

   If SPDM session key requires confidentiality, implement spdm_secured_message_lib in a secure environment.

   0.3, choose a proper crypto engine [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h).

   0.4, choose required SPDM transport libs, such as [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h)

   0.5, implement required SPDM device IO functions - spdm_device_send_message_func and spdm_device_receive_message_func. 

1. Initialize SPDM context

   1.1, allocate buffer for the spdm_context and initialize it.

   ```
   spdm_context = (void *)malloc (spdm_get_context_size());
   spdm_init_context (spdm_context);
   ```

   1.2, register the device io functions and transport layer functions.
   The libspdm provides the default [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h).
   The SPDM device driver need provide device IO send/receive function.

   ```
   spdm_register_device_io_func (spdm_context, spdm_device_send_message, spdm_device_receive_message);
   spdm_register_transport_layer_func (spdm_context, spdm_transport_mctp_encode_message, spdm_transport_mctp_decode_message);
   ```

   1.3, set capabilities and choose algorithms, based upon need.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   spdm_set_data (spdm_context, SPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &ct_exponent, sizeof(ct_exponent));
   spdm_set_data (spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &parameter, &cap_flags, sizeof(cap_flags));

   spdm_set_data (spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &parameter, &measurement_spec, sizeof(measurement_spec));
   spdm_set_data (spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter, &base_asym_algo, sizeof(base_asym_algo));
   spdm_set_data (spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter, &base_hash_algo, sizeof(base_hash_algo));
   spdm_set_data (spdm_context, SPDM_DATA_DHE_NAME_GROUP, &parameter, &dhe_named_group, sizeof(dhe_named_group));
   spdm_set_data (spdm_context, SPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &aead_cipher_suite, sizeof(aead_cipher_suite));
   spdm_set_data (spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &req_base_asym_alg, sizeof(req_base_asym_alg));
   spdm_set_data (spdm_context, SPDM_DATA_KEY_SCHEDULE, &parameter, &key_schedule, sizeof(key_schedule));
   ```

   1.4, if responder verification is required, deploy the peer public root hash or peer public certificate chain.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   if (!DeployCertChain) {
     spdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert, peer_root_cert_size);
   } else {
     spdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_CERT_CHAIN, &parameter, peer_cert_chain, peer_cert_chain_size);
   }
   ```

   1.5, if mutual authentication is supported, deploy slot number, public certificate chain.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   spdm_set_data (spdm_context, SPDM_DATA_LOCAL_SLOT_COUNT, &parameter, &SlotNumber, sizeof(SlotNumber));

   parameter.additional_data[0] = slot_id;
   spdm_set_data (spdm_context, SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, my_public_cert_chains, my_public_cert_chains_size);
   ```

   1.6, if PSK is required, optionally deploy PSK Hint.
   ```
   spdm_set_data (spdm_context, SPDM_DATA_PSK_HINT, NULL, psk_hint, psk_hint_size);
   ```

2. Create connection with the responder

   Send GET_VERSION, GET_CAPABILITIES and NEGOTIATE_ALGORITHM.
   ```
   spdm_init_connection (spdm_context, FALSE);
   ```

3. Authentication the responder

   Send GET_DIGESTES, GET_CERTIFICATES and CHALLENGE.
   ```
   spdm_get_digest (spdm_context, slot_mask, total_digest_buffer);
   spdm_get_certificate (spdm_context, slot_id, cert_chain_size, cert_chain);
   spdm_challenge (spdm_context, slot_id, measurement_hash_type, measurement_hash);
   ```

4. Get the measurement from the responder

   4.1, Send GET_MEASUREMENT to query the total number of measurements available.
   ```
   spdm_get_measurement (
       spdm_context,
       NULL,
       request_attribute,
       SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
       slot_id,
       &number_of_blocks,
       NULL,
       NULL
       );
   ```

   4.2, Send GET_MEASUREMENT to get measurement one by one.
   ```
   for (index = 1; index <= number_of_blocks; index++) {
     if (index == number_of_blocks) {
       request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
     }
     spdm_get_measurement (
       spdm_context,
       NULL,
       request_attribute,
       index,
       slot_id,
       &number_of_block,
       &measurement_record_length,
       measurement_record
       );
   }
   ```

5. Manage an SPDM session

   5.1, Without PSK, send KEY_EXCHANGE/FINISH to create a session.
   ```
   spdm_start_session (
       spdm_context,
       FALSE, // KeyExchange
       SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
       slot_id,
       &session_id,
       &heartbeat_period,
       measurement_hash
       );
   ```

   Or with PSK, send PSK_EXCHANGE/PSK_FINISH to create a session.
   ```
   spdm_start_session (
       spdm_context,
       TRUE, // KeyExchange
       SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
       slot_id,
       &session_id,
       &heartbeat_period,
       measurement_hash
       );
   ```

   5.2, Send END_SESSION to close the session.
   ```
   spdm_stop_session (spdm_context, session_id, end_session_attributes);
   ```

   5.3, Send HEARTBEAT, when it is required.
   ```
   spdm_heartbeat (spdm_context, session_id);
   ```

   5.4, Send KEY_UPDATE, when it is required.
   ```
   spdm_key_update (spdm_context, session_id, single_direction);
   ```

6. Send and receive message in an SPDM session

   6.1, Use the SPDM vendor defined message.
        (SPDM vendor defined message + transport layer header (SPDM) => application message)
   ```
   spdm_send_receive_data (spdm_context, &session_id, FALSE, &request, request_size, &response, &response_size);
   ```

   6.2, Use the transport layer application message.
   ```
   spdm_send_receive_data (spdm_context, &session_id, TRUE, &request, request_size, &response, &response_size);
   ```

## SPDM responder user guide

Please refer to spdm_server_init() in [spdm_responder.c](https://github.com/DMTF/SPDM-Emu/blob/main/spdm_emu/spdm_emu/spdm_responder_emu/spdm_responder.c)

0. Choose proper SPDM libraries.

   0.1, implement a proper [spdm_device_secret_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_device_secret_lib.h).

   If the responder supports signing, implement spdm_responder_data_sign().

   If the responder supports measurement, implement spdm_measurement_collection().

   If the responder supports PSK exchange, implement spdm_psk_handshake_secret_hkdf_expand() and spdm_psk_master_secret_hkdf_expand().

   spdm_device_secret_lib must be in a secure environment.

   0.2, choose a proper [spdm_secured_message_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_secured_message_lib.h).

   If SPDM session key requires confidentiality, implement spdm_secured_message_lib in a secure environment.

   0.3, choose a proper crypto engine [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h).

   0.4, choose required SPDM transport libs, such as [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h)

   0.5, implement required SPDM device IO functions - spdm_device_send_message_func and spdm_device_receive_message_func. 

0. Implement a proper spdm_device_secret_lib.

1. Initialize SPDM context (similar to SPDM requester)

   1.1, allocate buffer for the spdm_context and initialize it.

   ```
   spdm_context = (void *)malloc (spdm_get_context_size());
   spdm_init_context (spdm_context);
   ```

   1.2, register the device io functions and transport layer functions.
   The libspdm provides the default [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h).
   The SPDM device driver need provide device IO send/receive function.

   ```
   spdm_register_device_io_func (spdm_context, spdm_device_send_message, spdm_device_receive_message);
   spdm_register_transport_layer_func (spdm_context, spdm_transport_mctp_encode_message, spdm_transport_mctp_decode_message);
   ```

   1.3, set capabilities and choose algorithms, based upon need.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   spdm_set_data (spdm_context, SPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &ct_exponent, sizeof(ct_exponent));
   spdm_set_data (spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &parameter, &cap_flags, sizeof(cap_flags));

   spdm_set_data (spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &parameter, &measurement_spec, sizeof(measurement_spec));
   spdm_set_data (spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &measurement_hash_algo, sizeof(measurement_hash_algo));
   spdm_set_data (spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter, &base_asym_algo, sizeof(base_asym_algo));
   spdm_set_data (spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter, &base_hash_algo, sizeof(base_hash_algo));
   spdm_set_data (spdm_context, SPDM_DATA_DHE_NAME_GROUP, &parameter, &dhe_named_group, sizeof(dhe_named_group));
   spdm_set_data (spdm_context, SPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &aead_cipher_suite, sizeof(aead_cipher_suite));
   spdm_set_data (spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &req_base_asym_alg, sizeof(req_base_asym_alg));
   spdm_set_data (spdm_context, SPDM_DATA_KEY_SCHEDULE, &parameter, &key_schedule, sizeof(key_schedule));
   ```

   1.4, deploy slot number, public certificate chain.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   spdm_set_data (spdm_context, SPDM_DATA_LOCAL_SLOT_COUNT, &parameter, &SlotNumber, sizeof(SlotNumber));

   parameter.additional_data[0] = slot_id;
   spdm_set_data (spdm_context, SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, my_public_cert_chains, my_public_cert_chains_size);
   ```

   1.5, if mutual authentication (requester verification) is required, deploy the peer public root hash or peer public certificate chain.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   if (!DeployCertChain) {
     spdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert, peer_root_cert_size);
   } else {
     spdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_CERT_CHAIN, &parameter, peer_cert_chain, peer_cert_chain_size);
   }
   ```

   1.7, if PSK is required, optionally deploy PSK Hint.
   ```
   spdm_set_data (spdm_context, SPDM_DATA_PSK_HINT, NULL, psk_hint, psk_hint_size);
   ```

2. Dispatch SPDM messages.

   ```
   while (TRUE) {
     status = spdm_responder_dispatch_message (m_spdm_context);
     if (status != RETURN_UNSUPPORTED) {
       continue;
     }
     // handle non SPDM message
     ......
   }
   ```

3. Register message process callback

   This callback need handle both SPDM vendor defined message and transport layer application message.

   ```
   return_status
   spdm_get_response_vendor_defined_request (
     IN     void                *spdm_context,
     IN     uint32               *session_id,
     IN     boolean              is_app_message,
     IN     uintn                request_size,
     IN     void                 *request,
     IN OUT uintn                *response_size,
        OUT void                 *response
     )
   {
     if (is_app_message) {
       // this is a transport layer application message
     } else {
       // this is a SPDM vendor defined message (without transport layer header)
     }
   }

   spdm_register_get_response_func (spdm_context, spdm_get_response_vendor_defined_request);
   ```
