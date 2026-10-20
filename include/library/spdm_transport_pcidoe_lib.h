/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PCI_DOE_TRANSPORT_LIB_H
#define PCI_DOE_TRANSPORT_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"
#include "industry_standard/pcidoe.h"

#define LIBSPDM_PCI_DOE_ALIGNMENT 4
#define LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT 0
#define LIBSPDM_PCI_DOE_MAX_RANDOM_NUMBER_COUNT 0

/* Required sender/receiver buffer in device io.
 * +-------+--------+---------------------------+------+--+------+---+--------+-----+
 * | TYPE  |TransHdr|      EncryptionHeader     |AppHdr|  |Random|MAC|AlignPad|FINAL|
 * |       |        |SessionId|SeqNum|Len|AppLen|      |  |      |   |        |     |
 * +-------+--------+---------------------------+------+  +------+---+--------+-----+
 * |PCI_DOE|    8   |    4    |   0  | 2 |   2  |   0  |  |   0  | 16|   3    |  35 |
 * +-------+--------+---------------------------+------+--+------+---+--------+-----+
 */
#define LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE  (8 + 8 + \
                                                LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT)

#define LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE    (LIBSPDM_PCI_DOE_MAX_RANDOM_NUMBER_COUNT + \
                                                LIBSPDM_MAX_AEAD_TAG_SIZE + \
                                                (LIBSPDM_PCI_DOE_ALIGNMENT - 1))

/**
 * Encode an SPDM message to a transport layer message.
 *
 * For normal SPDM message, it adds the transport layer wrapper.
 * For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
 *
 * PCI DOE does not support APP messages, so LIBSPDM_STATUS_UNSUPPORTED_CAP is returned if
 * is_app_message is true.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 *                                      For normal message, it shall point to the acquired sender buffer.
 *                                      For secured message, it shall point to the scratch buffer in spdm_context.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *                                      On input, it shall be msg_buf_ptr from sender buffer.
 *                                      On output, it will point to acquired sender buffer.
 **/
libspdm_return_t libspdm_transport_pci_doe_encode_message(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    bool is_requester, size_t message_size, void *message,
    size_t *transport_message_size, void **transport_message);

/**
 * Encode a DOE discovery message.
 *
 * The PCI DOE header is added in place before message, so the transport message buffer must
 * start sizeof(pci_doe_data_object_header_t) bytes before message.
 *
 * @param  message_size                         Size in bytes of the message data buffer.
 * @param  message                              A pointer to a source buffer to store the message.
 * @param  transport_message_size               On input, the size in bytes of the buffer.
 *                                              On output, the size of the transport message.
 * @param  transport_message                    On output, a pointer to the transport message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is encoded successfully.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL      transport_message_size is too small.
 * @retval LIBSPDM_STATUS_BUFFER_FULL           The message is too large for PCI DOE.
 **/
libspdm_return_t libspdm_pci_doe_encode_discovery(size_t message_size, void *message,
                                                  size_t *transport_message_size,
                                                  void **transport_message);

/**
 * Decode an SPDM message from a transport layer message.
 *
 * For normal SPDM message, it removes the transport layer wrapper,
 * For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 *
 * PCI DOE does not support APP messages, so is_app_message is always set to false.
 *
 * A decoded normal message, or a message from a MAC-only session, is inside the receiver buffer.
 * An encrypted message is decrypted into the scratch buffer that message points to on input.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                      For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                      On input, it shall point to the scratch buffer in spdm_context.
 *                                      On output, a pointer to the decoded message.
 **/
libspdm_return_t libspdm_transport_pci_doe_decode_message(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_requester,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message);

/**
 * Decode a DOE discovery request message.
 *
 * @param  transport_message_size               Size in bytes of the transport message data buffer.
 * @param  transport_message                    A pointer to a source buffer to store the transport message.
 * @param  index                                A pointer to a destination to store the index.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE      The transport message size is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD     The transport message contains an invalid field.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is not a DOE discovery message.
 **/
libspdm_return_t libspdm_pci_doe_decode_discovery_request(size_t transport_message_size,
                                                          const void *transport_message,
                                                          uint8_t *index);

/**
 * Decode a DOE discovery request message to get the DOE Discovery Version field.
 * DOE Discovery Version is introduced in PCIe Spec 6.1 Section 6.30.1.1.
 *
 * @param  transport_message_size               Size in bytes of the transport message data buffer.
 * @param  transport_message                    A pointer to a source buffer to store the transport message.
 * @param  version                              A pointer to a destination to store the DOE Discovery Version.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE      The transport message size is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD     The transport message contains an invalid field.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is not a DOE discovery message.
 **/
libspdm_return_t libspdm_pci_doe_decode_discovery_request_version(size_t transport_message_size,
                                                                  const void *transport_message,
                                                                  uint8_t *version);

/**
 * Decode a DOE discovery response message.
 *
 * @param  transport_message_size               Size in bytes of the transport message data buffer.
 * @param  transport_message                    A pointer to a source buffer to store the transport message.
 * @param  vendor_id                            A pointer to a destination to store the vendor_id.
 * @param  protocol                             A pointer to a destination to store the protocol.
 * @param  next_index                           A pointer to a destination to store the next_index.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE      The transport message size is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD     The transport message contains an invalid field.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is not a DOE discovery message.
 **/
libspdm_return_t libspdm_pci_doe_decode_discovery_response(size_t transport_message_size,
                                                           void *transport_message,
                                                           uint16_t *vendor_id,
                                                           uint8_t *protocol,
                                                           uint8_t *next_index);

/**
 * Return the maximum transport layer message header size.
 *   Transport Message Header Size + sizeof(spdm_secured_message_cipher_header_t))
 *
 *   For PCI_DOE, Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return size of maximum transport layer message header size
 **/
uint32_t libspdm_transport_pci_doe_get_header_size(
    void *spdm_context);

/**
 * Get sequence number in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @param sequence_number        The current sequence number used to encode or decode message.
 * @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
 *                             The size in byte of the output buffer shall be 8.
 *
 * @return size in byte of the sequence_number_buffer.
 *        It shall be no greater than 8.
 *        0 means no sequence number is required.
 **/
uint8_t libspdm_pci_doe_get_sequence_number(uint64_t sequence_number,
                                            uint8_t *sequence_number_buffer);

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no random number is required.
 **/
uint32_t libspdm_pci_doe_get_max_random_number_count(void);

/**
 * This function translates the negotiated secured_message_version to a DSP0277 version.
 *
 * @param  secured_message_version  The version specified in binding specification and
 *                                  negotiated in KEY_EXCHANGE/KEY_EXCHANGE_RSP.
 *
 * @return The DSP0277 version specified in binding specification,
 *         which is bound to secured_message_version.
 */
spdm_version_number_t libspdm_pci_doe_get_secured_spdm_version(
    spdm_version_number_t secured_message_version);

#ifdef __cplusplus
}
#endif

#endif /* PCI_DOE_TRANSPORT_LIB_H */
