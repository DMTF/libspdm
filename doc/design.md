# libspdm library design.

1. Use static linking (Library) when there is one instance that can be linked to the device.
   For example, crypto engine.

2. Use dynamic linking (function registration) when there are multiple instances that can be linked to the device.
   For example, transport layer.

## SPDM library layer

   ```
        +================+               +================+
        | SPDM Requester |               | SPDM Responder |        // PCI Component Measurement and Authentication (CMA)
        | Device Driver  |               | Device Driver  |        // PCI Integrity and Data Encryption (IDE)
        +================+               +================+
               | spdm_send_receive_data            ^ spdm_get_response_func
   =============================================================
               V                                   |
   +------------------+  +---------------+  +------------------+
   |spdm_requester_lib|->|spdm_common_lib|<-|spdm_responder_lib|   // DSP0274 - SPDM
   +------------------+  +---------------+  +------------------+
         | | |            |         V                | | |
         | | |            | +----------------------+ | | |
         | | |            | |spdm_device_secret_lib| | | |         // Device Secret handling (PrivateKey)
         | | |            | +----------------------+ | | |
         | | |            V         ^                | | |
         | | |      +------------------------+       | | |
         | |  ----->|spdm_secured_message_lib|<------  | |         // DSP0277 - Secured Message in SPDM session
         | |        +------------------------+         | |
         | |                     ^                     | |
   =============================================================
         | |                     |                     | |
         | |         +----------------------+          | |
         |  -------->|spdm_transport_xxx_lib|<---------  |         // DSP0275/DSP0276 - SPDM/SecuredMessage over MCTP
         |           | (XXX = mctp, pcidoe) |            |         // PCI Data Object Exchange (DOE) message
         |           +----------------------+            |
         |   spdm_transport_encode/decode_message_func   |
         |                                               |
   =============================================================
         |                                               |
         |     spdm_device_send/receive_message_func     |
         |              +----------------+               |
          ------------->| SPDM Device IO |<--------------          // DSP0237 - MCTP over SMBus
                        | (SMBus, PciDoe)|                         // DSP0238 - MCTP over PCIeVDM
                        +----------------+                         // PCI DOE - PCI DOE message over PCI DOE mailbox.
   ```

1) [spdm_requester_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_requester_lib.h) (follows DSP0274)

   This library is linked for an SPDM requester.

2) [spdm_responder_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_responder_lib.h) (follows DSP0274)

   This library is linked for an SPDM responder.

3) [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h) (follows DSP0274)

   This library provides common services for spdm_requester_lib and spdm_responder_lib.

4) [spdm_secured_message_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_secured_message_lib.h) (follows DSP0277)

   This library handles the session key generation and secured messages encryption and decryption.

   This can be implemented in a secure environment if the session keys are considered a secret.

5) [spdm_device_secret_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_device_secret_lib.h)

   This library handles the private key signing, PSK HMAC operation, and measurement collection.

   This must be implemented in a secure environment because the private key and PSK are secret.

6) [spdm_crypt_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_crypt_lib.h)

   This library provides SPDM related crypto function. It is based upon [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h).

7) transport layer encode/decode

7.1) [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) (follows DSP0275 and DSP0276)

   This library encodes and decodes MCTP message header.

   SPDM requester/responder need to register libspdm_transport_encode_message_func,
   libspdm_transport_decode_message_func and libspdm_transport_get_header_size_func
   to the spdm_requester_lib/spdm_responder_lib.

   These APIs encode and decode transport layer messages to or from a SPDM device.

7.2) [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h) (follows PCI DOE)

   This library encodes and decodes PCI DOE message header.

   SPDM requester/responder need to register libspdm_transport_encode_message_func,
   libspdm_transport_decode_message_func and libspdm_transport_get_header_size_func
   to the spdm_requester_lib/spdm_responder_lib.

   These APIs encode and decode transport layer messages to or from a SPDM device.

8) device IO

   SPDM requester/responder need to register libspdm_device_send_message_func
   and libspdm_device_receive_message_func to the spdm_requester_lib/spdm_responder_lib.

   SPDM requester/responder need to register libspdm_device_acquire_sender_buffer_func,
   libspdm_device_release_sender_buffer_func, libspdm_device_acquire_receiver_buffer_func,
   and libspdm_device_release_receiver_buffer_func to the spdm_requester_lib/spdm_responder_lib.

   These APIs send and receive transport layer messages to or from a SPDM device.

   The size of sender/receiver buffer is `LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE`.
   The size of scratch buffer is `LIBSPDM_SCRATCH_BUFFER_SIZE`.
   Please refer to [spdm_lib_config.h](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h).

   ```
   The sender flow is:
   {
     libspdm_device_acquire_sender_buffer_func (&sender_buffer, &sender_buffer_size);
     max_header_size = libspdm_transport_get_header_size_func();
     spdm_message_buffer = sender_buffer + max_header_size;
     /* build SPDM request/response in spdm_message_buffer */
     libspdm_transport_encode_message_func (spdm_message_buffer, spdm_message_buffer_size,
         &transport_message_buffer, &transport_message_buffer_size);
     libspdm_device_send_message_func (transport_message_buffer, transport_message_buffer_size);
     libspdm_device_release_sender_buffer_func (sender_buffer);
   }

   The buffer usage of sender buffer is:

     ===== : SPDM message (max_header_size must be reserved before message)

     |<---                       sender_buffer_size                      --->|
        |<---                transport_message_buffer_size            --->|
        |<-max_header_size->|<-spdm_message_buffer_size->|
     +--+-------------------+============================+----------------+--+
     |  | transport header  |         SPDM message       | transport tail |  |
     +--+-------------------+============================+----------------+--+
     ^  ^                   ^
     |  |                   | spdm_message_buffer
     |  | transport_message_buffer
     | sender_buffer

   For secured message, the scratch_buffer is used to store plain text, the final cipher text will be in sender_buffer.

   libspdm_transport_encode_message_func(spdm_message_buffer, &transport_message_buffer)
   {
     /* spdm_message_buffer is inside of scratch_buffer.
      * transport_message_buffer is inside of sender_buffer. */

     xxx_encode_spdm_message_to_app (spdm_message_buffer, spdm_message_buffer_size,
         &app_message_buffer, &app_message_buffer_size);
     max_header_size = libspdm_transport_get_header_size_func();
     secured_message_buffer = transport_message_buffer + max_header_size;
     libspdm_encode_secured_message (app_message_buffer, app_message_buffer_size,
         secured_message_buffer, &secured_message_buffer_size);
     xxx_encode_secured_message_to_transport (secured_message_buffer, secured_message_buffer_size,
         &transport_message_buffer, &transport_message_buffer_size);
   }

   The buffer usage of sender_buffer and scratch_buffer is:

     ===== : SPDM message (max_header_size must be reserved before message, for sender_buffer and scratch_buffer)
     ***** : encrypted data
     $$$$$ : additional authenticated data (AAD)
     &&&&& : message authentication code (MAC) / TAG

     |<---                            sender_buffer_size                           --->|
        |<---                     transport_message_buffer_size                 --->|
        |<-max_hdr_s->|<---       secured_message_buffer_size          --->|
     +--+-------------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+--+
     |  |  TransHdr   |      EncryptionHeader     |AppHdr| SPDM |Random|MAC|AlignPad|  |
     |  |             |SessionId|SeqNum|Len|AppLen|      |      |      |   |        |  |
     +--+-------------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+--+
     ^  ^             ^
     |  |             | secured_message_buffer
     |  | transport_message_buffer
     | sender_buffer

     |<---                            scratch_buffer_size                          --->|
                                           |<---  plain text size  --->|
                                                  |<-app_msg_s->|
                                           |<-max_hdr_s->|<spdm>|
     +-------------------------------------+-------------+======+------+---------------+
     |                                     |EncHdr|AppHdr| SPDM |Random|               |
     |                                     |AppLen|      |      |      |               |
     +-------------------------------------+-------------+======+------+---------------+
     ^                                     ^      ^      ^
     |                                     |      |      | spdm_message_buffer
     |                                     |      | app_message_buffer
     |                                     | plain text
     | scratch_buffer

   ```

   ```
   The receiver flow is:
   {
     libspdm_device_acquire_receiver_buffer_func (&receiver_buffer, &receiver_buffer_size);
     transport_message_buffer = receiver_buffer;
     libspdm_device_receive_message_func (&transport_message_buffer, &transport_message_buffer_size);
     libspdm_transport_decode_message_func (transport_message_buffer, transport_message_buffer_size,
         &spdm_message_buffer, &spdm_message_buffer_size);
     /* process SPDM request/response in spdm_message_buffer */
     libspdm_device_release_receiver_buffer_func (receiver_buffer);
   }

   The buffer usage of sender buffer is:

     ===== : SPDM message

     |<---                       receiver_buffer_size                    --->|
        |<---                transport_message_buffer_size            --->|
                            |<-spdm_message_buffer_size->|
     +--+-------------------+============================+----------------+--+
     |  | transport header  |         SPDM message       | transport tail |  |
     +--+-------------------+============================+----------------+--+
     ^  ^                   ^
     |  |                   | spdm_message_buffer
     |  | transport_message_buffer
     | receiver_buffer

   For secured message, the scratch_buffer will be used to store plain text, the cipher text is in receiver_buffer.

   libspdm_transport_decode_message_func(transport_message_buffer, &spdm_message_buffer)
   {
     /* transport_message_buffer is inside of receiver_buffer.
      * spdm_message_buffer is inside of scratch_buffer. */

     xxx_decode_secured_message_from_transport (transport_message_buffer, transport_message_buffer_size,
         &secured_message_buffer, &secured_message_buffer_size);
     app_message_buffer = spdm_message_buffer
     libspdm_decode_secured_message (secured_message_buffer, secured_message_buffer_size,
         &app_message_buffer, &app_message_buffer_size);
     xxx_decode_spdm_message_from_app (app_message_buffer, app_message_buffer_size,
         &spdm_message_buffer, &spdm_message_buffer_size);
   }

   The buffer usage of receiver_buffer and scratch_buffer is:

     ===== : SPDM message
     ***** : encrypted data
     $$$$$ : additional authenticated data (AAD)
     &&&&& : message authentication code (MAC) / TAG

     |<---                            receiver_buffer_size                         --->|
        |<---                     transport_message_buffer_size                 --->|
                      |<---       secured_message_buffer_size          --->|
     +--+-------------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+--+
     |  |  TransHdr   |      EncryptionHeader     |AppHdr| SPDM |Random|MAC|AlignPad|  |
     |  |             |SessionId|SeqNum|Len|AppLen|      |      |      |   |        |  |
     +--+-------------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+--+
     ^  ^             ^
     |  |             | secured_message_buffer
     |  | transport_message_buffer
     | receiver_buffer

     |<---                            scratch_buffer_size                          --->|
                                           |<---  plain text size  --->|
                                                  |<-app_msg_s->|
                                                         |<spdm>|
     +-------------------------------------+-------------+======+------+---------------+
     |                                     |EncHdr|AppHdr| SPDM |Random|               |
     |                                     |AppLen|      |      |      |               |
     +-------------------------------------+-------------+======+------+---------------+
     ^                                     ^      ^      ^
     |                                     |      |      | spdm_message_buffer
     |                                     |      | app_message_buffer
     |                                     | plain text
     | scratch_buffer

   ```

9) [spdm_lib_config.h](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h) provides the configuration to the libspdm library.

10) SPDM library depends upon the [HAL library](https://github.com/DMTF/libspdm/tree/main/include/hal).

   The sample implementation can be found at [os_stub](https://github.com/DMTF/libspdm/tree/main/os_stub)

   10.1) [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h) provides crypto functions.

   10.2) [memlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/memlib.h) provides memory operation.

   10.3) [debuglib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/debuglib.h) provides debug functions.

   10.4) [platform_lib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/platform_lib.h) provides sleep function and watchdog function.

   10.4.1) sleep function.

   The sleep function delays the execution of a message flow instance for a defined period of time.

   10.4.2) watchdog function.

   The wathdog function supports multiple software watchdogs for multiple sessions with one hardware watchdog.
