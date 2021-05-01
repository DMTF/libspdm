# openspdm library design.

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

1) [spdm_requester_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_requester_lib.h) (follows DSP0274)

   This library is linked for an SPDM requester.

2) [spdm_responder_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_responder_lib.h) (follows DSP0274)

   This library is linked for an SPDM responder.

3) [spdm_common_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_common_lib.h) (follows DSP0274)

   This library provides common services for spdm_requester_lib and spdm_responder_lib.

4) [spdm_secured_message_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_secured_message_lib.h) (follows DSP0277)

   This library handles the session key generation and secured messages encryption and decryption.

   This can be implemented in a secure environment if the session keys are considered a secret.

5) [spdm_device_secret_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_device_secret_lib.h)

   This library handles the private key signing, PSK HMAC operation, and measurement collection.

   This must be implemented in a secure environment because the private key and PSK are secret.

6) [spdm_crypt_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_crypt_lib.h)

   This library provides SPDM related crypto function. It is based upon [cryptlib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/hal/library/cryptlib.h).

7) SpdmTransportLib

7.1) [spdm_transport_mctp_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_transport_mctp_lib.h) (follows DSP0275 and DSP0276)

   This library encodes and decodes MCTP message header.

   SPDM requester/responder need to register spdm_transport_encode_message_func
   and spdm_transport_decode_message_func to the spdm_requester_lib/spdm_responder_lib.

   These two APIs encode and decode transport layer messages to or from a SPDM device.

7.2) [spdm_transport_pcidoe_lib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_transport_pcidoe_lib.h) (follows PCI DOE)

   This library encodes and decodes PCI DOE message header.

   SPDM requester/responder need to register spdm_transport_encode_message_func
   and spdm_transport_decode_message_func to the spdm_requester_lib/spdm_responder_lib.

   These two APIs encode and decode transport layer messages to or from a SPDM device.

8) spdm_device_send_message_func and spdm_device_receive_message_func

   SPDM requester/responder need to register spdm_device_send_message_func
   and spdm_device_receive_message_func to the spdm_requester_lib/spdm_responder_lib.

   These APIs send and receive transport layer messages to or from a SPDM device.

9) [spdm_lib_config.h](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/library/spdm_lib_config.h) provides the configuration to the openspdm library.

10) SPDM library depends upon the [HAL library](https://github.com/DMTF/Libspdm/tree/main/libspdm/include/hal).

   The sample implementation can be found at [os_stub](https://github.com/DMTF/Libspdm/tree/main/libspdm/os_stub)

   10.1) [cryptlib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/hal/library/cryptlib.h) provides crypto functions.

   10.2) [memlib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/hal/library/memlib.h) provides memory operation.

   10.3) [debuglib](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/hal/library/debuglib.h) provides debug functions.
