/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <library/spdm_transport_pcidoe_lib.h>
#include <industry_standard/pcidoe.h>

#define PCI_DOE_ALIGNMENT 4
#define PCI_DOE_SEQUENCE_NUMBER_COUNT 0
#define PCI_DOE_MAX_RANDOM_NUMBER_COUNT 0

/**
  Get sequence number in an SPDM secure message.

  This value is transport layer specific.

  @param sequence_number        The current sequence number used to encode or decode message.
  @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
                               The size in byte of the output buffer shall be 8.

  @return size in byte of the sequence_number_buffer.
          It shall be no greater than 8.
          0 means no sequence number is required.
**/
uint8_t spdm_pci_doe_get_sequence_number(IN uint64_t sequence_number,
                       IN OUT uint8_t *sequence_number_buffer)
{
    copy_mem(sequence_number_buffer, &sequence_number,
         PCI_DOE_SEQUENCE_NUMBER_COUNT);
    return PCI_DOE_SEQUENCE_NUMBER_COUNT;
}

/**
  Return max random number count in an SPDM secure message.

  This value is transport layer specific.

  @return Max random number count in an SPDM secured message.
          0 means no randum number is required.
**/
uint32_t spdm_pci_doe_get_max_random_number_count(void)
{
    return PCI_DOE_MAX_RANDOM_NUMBER_COUNT;
}

/**
  Encode a normal message or secured message to a transport message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status pci_doe_encode_message(IN uint32_t *session_id,
                     IN uintn message_size, IN void *message,
                     IN OUT uintn *transport_message_size,
                     OUT void *transport_message)
{
    uintn aligned_message_size;
    uintn alignment;
    pci_doe_data_object_header_t *pci_doe_header;

    alignment = PCI_DOE_ALIGNMENT;
    aligned_message_size =
        (message_size + (alignment - 1)) & ~(alignment - 1);

    ASSERT(*transport_message_size >=
           aligned_message_size + sizeof(pci_doe_data_object_header_t));
    if (*transport_message_size <
        aligned_message_size + sizeof(pci_doe_data_object_header_t)) {
        *transport_message_size = aligned_message_size +
                      sizeof(pci_doe_data_object_header_t);
        return RETURN_BUFFER_TOO_SMALL;
    }
    *transport_message_size =
        aligned_message_size + sizeof(pci_doe_data_object_header_t);
    pci_doe_header = transport_message;
    pci_doe_header->vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    if (session_id != NULL) {
        pci_doe_header->data_object_type =
            PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
        ASSERT(*session_id == *(uint32_t *)(message));
        if (*session_id != *(uint32_t *)(message)) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        pci_doe_header->data_object_type =
            PCI_DOE_DATA_OBJECT_TYPE_SPDM;
    }
    pci_doe_header->reserved = 0;
    if (*transport_message_size > PCI_DOE_MAX_SIZE_IN_BYTE) {
        return RETURN_OUT_OF_RESOURCES;
    } else if (*transport_message_size == PCI_DOE_MAX_SIZE_IN_BYTE) {
        pci_doe_header->length = 0;
    } else {
        pci_doe_header->length =
            (uint32_t)*transport_message_size / sizeof(uint32_t);
    }

    copy_mem((uint8_t *)transport_message +
             sizeof(pci_doe_data_object_header_t),
         message, message_size);
    zero_mem((uint8_t *)transport_message +
             sizeof(pci_doe_data_object_header_t) + message_size,
         *transport_message_size -
             sizeof(pci_doe_data_object_header_t) - message_size);
    return RETURN_SUCCESS;
}

/**
  Decode a transport message to a normal message or secured message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status pci_doe_decode_message(OUT uint32_t **session_id,
                     IN uintn transport_message_size,
                     IN void *transport_message,
                     IN OUT uintn *message_size,
                     OUT void *message)
{
    uintn alignment;
    pci_doe_data_object_header_t *pci_doe_header;
    uint32_t length;

    alignment = PCI_DOE_ALIGNMENT;

    ASSERT(transport_message_size > sizeof(pci_doe_data_object_header_t));
    if (transport_message_size <= sizeof(pci_doe_data_object_header_t)) {
        return RETURN_UNSUPPORTED;
    }

    pci_doe_header = transport_message;
    if (pci_doe_header->vendor_id != PCI_DOE_VENDOR_ID_PCISIG) {
        return RETURN_UNSUPPORTED;
    }

    switch (pci_doe_header->data_object_type) {
    case PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM:
        ASSERT(session_id != NULL);
        if (session_id == NULL) {
            return RETURN_UNSUPPORTED;
        }
        if (transport_message_size <=
            sizeof(pci_doe_data_object_header_t) + sizeof(uint32_t)) {
            return RETURN_UNSUPPORTED;
        }
        *session_id = (uint32_t *)((uint8_t *)transport_message +
                     sizeof(pci_doe_data_object_header_t));
        break;
    case PCI_DOE_DATA_OBJECT_TYPE_SPDM:
        if (session_id != NULL) {
            *session_id = NULL;
        }
        break;
    default:
        return RETURN_UNSUPPORTED;
    }

    if (pci_doe_header->reserved != 0) {
        return RETURN_UNSUPPORTED;
    }
    if (pci_doe_header->length >= PCI_DOE_MAX_SIZE_IN_DW) {
        return RETURN_UNSUPPORTED;
    } else if (pci_doe_header->length == 0) {
        length = PCI_DOE_MAX_SIZE_IN_BYTE;
    } else {
        length = pci_doe_header->length * sizeof(uint32_t);
    }
    if (length != transport_message_size) {
        return RETURN_UNSUPPORTED;
    }

    ASSERT(((transport_message_size - sizeof(pci_doe_data_object_header_t)) &
        (alignment - 1)) == 0);

    if (*message_size <
        transport_message_size - sizeof(pci_doe_data_object_header_t)) {
        //
        // Handle special case for the side effect of alignment
        // Caller may allocate a good enough buffer without considering alignment.
        // Here we will not copy all the message and ignore the the last padding bytes.
        //
        if (*message_size + alignment - 1 >=
            transport_message_size -
                sizeof(pci_doe_data_object_header_t)) {
            copy_mem(message,
                 (uint8_t *)transport_message +
                     sizeof(pci_doe_data_object_header_t),
                 *message_size);
            return RETURN_SUCCESS;
        }
        ASSERT(*message_size >=
               transport_message_size -
                   sizeof(pci_doe_data_object_header_t));
        *message_size = transport_message_size -
                sizeof(pci_doe_data_object_header_t);
        return RETURN_BUFFER_TOO_SMALL;
    }
    *message_size =
        transport_message_size - sizeof(pci_doe_data_object_header_t);
    copy_mem(message,
         (uint8_t *)transport_message +
             sizeof(pci_doe_data_object_header_t),
         *message_size);
    return RETURN_SUCCESS;
}
