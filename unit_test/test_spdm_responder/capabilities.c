/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_CAPABILITIES,
    },
};
/* version 1.0 message consists of only header (size 0x04).
 * However, spdm_get_capabilities_request_t has a size of 0x0c.
 * Therefore, sending a v1.0 request with this structure results in a wrong size request.
 * size information was corrected to reflect the actual size of a get_capabilities 1.0 message.*/
size_t m_libspdm_get_capabilities_request1_size = sizeof(spdm_message_header_t);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request2 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_CAPABILITIES,
    },
};
size_t m_libspdm_get_capabilities_request2_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request4 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request4_size =
    sizeof(m_libspdm_get_capabilities_request4) -
    sizeof(m_libspdm_get_capabilities_request4.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request4.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request5 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (0x01 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request5_size =
    sizeof(m_libspdm_get_capabilities_request5) -
    sizeof(m_libspdm_get_capabilities_request5.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request5.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request6 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request6_size =
    sizeof(m_libspdm_get_capabilities_request6) -
    sizeof(m_libspdm_get_capabilities_request6.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request6.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request7 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    LIBSPDM_MAX_CT_EXPONENT + 1, /*Illegal ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (0x100000 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request7_size =
    sizeof(m_libspdm_get_capabilities_request7) -
    sizeof(m_libspdm_get_capabilities_request7.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request7.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request8 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (0x100000 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request8_size =
    sizeof(m_libspdm_get_capabilities_request8) -
    sizeof(m_libspdm_get_capabilities_request8.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request8.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request9 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request9_size =
    sizeof(m_libspdm_get_capabilities_request9) -
    sizeof(m_libspdm_get_capabilities_request9.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request9.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request10 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request10_size =
    sizeof(m_libspdm_get_capabilities_request10) -
    sizeof(m_libspdm_get_capabilities_request10.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request10.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request11 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request11_size =
    sizeof(m_libspdm_get_capabilities_request11) -
    sizeof(m_libspdm_get_capabilities_request11.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request11.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request12 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP

    )
};
size_t m_libspdm_get_capabilities_request12_size =
    sizeof(m_libspdm_get_capabilities_request12) -
    sizeof(m_libspdm_get_capabilities_request12.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request12.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request13 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP

    )
};
size_t m_libspdm_get_capabilities_request13_size =
    sizeof(m_libspdm_get_capabilities_request13) -
    sizeof(m_libspdm_get_capabilities_request13.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request13.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request14 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request14_size =
    sizeof(m_libspdm_get_capabilities_request14) -
    sizeof(m_libspdm_get_capabilities_request14.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request14.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request15 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
};
size_t m_libspdm_get_capabilities_request15_size =
    sizeof(m_libspdm_get_capabilities_request15) -
    sizeof(m_libspdm_get_capabilities_request15.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request15.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request16 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request16_size =
    sizeof(m_libspdm_get_capabilities_request16) -
    sizeof(m_libspdm_get_capabilities_request16.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request16.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request17 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request17_size =
    sizeof(m_libspdm_get_capabilities_request17) -
    sizeof(m_libspdm_get_capabilities_request17.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request17.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request18 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    ( /*flags*/
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
};
size_t m_libspdm_get_capabilities_request18_size =
    sizeof(m_libspdm_get_capabilities_request18) -
    sizeof(m_libspdm_get_capabilities_request18.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request18.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request19 = {
    {
        SPDM_MESSAGE_VERSION_12,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP|
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP),
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request19_size = sizeof(m_libspdm_get_capabilities_request19);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request25 = {
    {
        SPDM_MESSAGE_VERSION_12,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    0,
    LIBSPDM_DATA_TRANSFER_SIZE - 1,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request25_size = sizeof(m_libspdm_get_capabilities_request25);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request26 = {
    {
        SPDM_MESSAGE_VERSION_12,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP|
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP),
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_DATA_TRANSFER_SIZE - 1,
};
size_t m_libspdm_get_capabilities_request26_size = sizeof(m_libspdm_get_capabilities_request26);


spdm_get_capabilities_request_t m_libspdm_get_capabilities_request27 = {
    {
        SPDM_MESSAGE_VERSION_13,
        SPDM_GET_CAPABILITIES,
    },
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY,
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request27_size = sizeof(m_libspdm_get_capabilities_request27);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request28 = {
    {
        SPDM_MESSAGE_VERSION_13,
        SPDM_GET_CAPABILITIES,
        0x01,
    },
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP |
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY,
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request28_size = sizeof(m_libspdm_get_capabilities_request28);

static void rsp_capabilities_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

static void rsp_capabilities_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request2_size,
        &m_libspdm_get_capabilities_request2, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request2.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

static void rsp_capabilities_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_BUSY);
}

static void rsp_capabilities_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
}

static void rsp_capabilities_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 7: Requester sets a CTExponent value that is larger than LIBSPDM_MAX_CT_EXPONENT.
 * Expected behavior: returns with error code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void rsp_capabilities_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request7_size,
        &m_libspdm_get_capabilities_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request7.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request4_size,
        &m_libspdm_get_capabilities_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request4.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
}

static void rsp_capabilities_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request5_size,
        &m_libspdm_get_capabilities_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request4.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
}

/**
 * Test 10: receiving a GET_CAPABILITIES request with an SPDM version that the responder does
 * not support.
 * Expected behavior: the responder refuses the GET_CAPABILITIES message and produces an ERROR
 * message indicating the VersionMismatch.
 **/
static void rsp_capabilities_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = 0x99;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, sizeof(spdm_message_header_t), &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 11: receiving a GET_CAPABILITIES request in SPDM version 1.2 that is smaller than the
 * minimum allowed size for that version.
 * Expected behavior: the responder refuses the GET_CAPABILITIES message and produces an ERROR
 * message indicating the InvalidRequest.
 **/
static void rsp_capabilities_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, sizeof(spdm_get_capabilities_request_t) - 1, &request, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 12: receiving a GET_CAPABILITIES request in SPDM version 1.1 that is smaller than the
 * minimum allowed size for that version.
 * Expected behavior: the responder refuses the GET_CAPABILITIES message and produces an ERROR
 * message indicating the InvalidRequest.
 **/
static void rsp_capabilities_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;
    size_t v11_min_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;

    v11_min_size = sizeof(spdm_get_capabilities_request_t) -
                   sizeof(request.data_transfer_size) - sizeof(request.max_spdm_msg_size);

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, v11_min_size - 1, &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xd;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request9_size,
        &m_libspdm_get_capabilities_request9, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request9.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xe;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request10_size,
        &m_libspdm_get_capabilities_request10, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request10.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xf;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request11_size,
        &m_libspdm_get_capabilities_request11, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request11.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request12_size,
        &m_libspdm_get_capabilities_request12, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request12.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request13_size,
        &m_libspdm_get_capabilities_request13, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request13.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request14_size,
        &m_libspdm_get_capabilities_request14, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request14.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request15_size,
        &m_libspdm_get_capabilities_request15, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request15.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request16_size,
        &m_libspdm_get_capabilities_request16, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request16.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 21: receiving a correct GET_CAPABILITIES from the requester. Buffer A already has
 * arbitrary data (e.g. the transcript of the prior GET_VERSION/VERSION exchange).
 * Expected behavior: the responder accepts the request, produces a valid CAPABILITIES
 * response message, and buffer A is extended (not reset) with the exchanged GET_CAPABILITIES
 * and CAPABILITIES messages appended after the pre-existing data.
 **/
static void rsp_capabilities_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;
    size_t prior_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    /*filling buffer A with arbitrary data, simulating a prior GET_VERSION/VERSION exchange*/
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, 10, (uint8_t)0xFF);
    spdm_context->transcript.message_a.buffer_size = 10;
    prior_buffer_size = spdm_context->transcript.message_a.buffer_size;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);

    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     prior_buffer_size + m_libspdm_get_capabilities_request1_size +
                     response_size);
    assert_memory_equal(
        spdm_context->transcript.message_a.buffer + prior_buffer_size,
        &m_libspdm_get_capabilities_request1, m_libspdm_get_capabilities_request1_size);
    assert_memory_equal(
        spdm_context->transcript.message_a.buffer + prior_buffer_size +
        m_libspdm_get_capabilities_request1_size,
        response, response_size);
}

static void rsp_capabilities_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request18_size,
        &m_libspdm_get_capabilities_request18, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request18.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
}

static void rsp_capabilities_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;
    size_t arbitrary_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    /*filling A with arbitrary data*/
    arbitrary_size = 10;
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = arbitrary_size;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request4_size,
        &m_libspdm_get_capabilities_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request4.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);

    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     arbitrary_size + m_libspdm_get_capabilities_request4_size + response_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size,
                        &m_libspdm_get_capabilities_request4,
                        m_libspdm_get_capabilities_request4_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size +
                        m_libspdm_get_capabilities_request4_size,
                        response, response_size);
}

static void rsp_capabilities_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request19_size,
        &m_libspdm_get_capabilities_request19, &response_size, response);
    assert_int_equal(spdm_context->connection_info.capability.max_spdm_msg_size,
                     m_libspdm_get_capabilities_request19.max_spdm_msg_size);
    assert_int_equal(spdm_context->connection_info.capability.data_transfer_size,
                     m_libspdm_get_capabilities_request19.data_transfer_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
    assert_int_equal(spdm_response->data_transfer_size, LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_response->max_spdm_msg_size, LIBSPDM_MAX_SPDM_MSG_SIZE);
}

static void rsp_capabilities_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request25_size,
        &m_libspdm_get_capabilities_request25, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request25.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request26_size,
        &m_libspdm_get_capabilities_request26, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request26.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

static void rsp_capabilities_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request27_size,
        &m_libspdm_get_capabilities_request27, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
    assert_int_equal(spdm_response->data_transfer_size, LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_response->max_spdm_msg_size, LIBSPDM_MAX_SPDM_MSG_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY);
}

static void rsp_capabilities_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request28_size,
        &m_libspdm_get_capabilities_request28, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) +
                     sizeof(spdm_supported_algorithms_block_t) +
                     4 * sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
    assert_int_equal(spdm_response->data_transfer_size, LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_response->max_spdm_msg_size, LIBSPDM_MAX_SPDM_MSG_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP |
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY);
}

/**
 * Test 29: receiving an SPDM 1.0 GET_CAPABILITIES request that is smaller than
 * the fixed message header.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(spdm_message_header_t) - 1,
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 30: receiving an SPDM 1.1 GET_CAPABILITIES request with reserved PSK_CAP bits.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;
    size_t v11_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = (2u << 10);
    v11_size = sizeof(request) - sizeof(request.data_transfer_size) -
               sizeof(request.max_spdm_msg_size);

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, v11_size,
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 31: receiving an SPDM 1.3 request with EVENT_CAP but no session capability.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case31(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 32: receiving an SPDM 1.1 request with CERT_CAP but no CHAL_CAP or KEY_EX_CAP.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case32(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;
    size_t v11_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    v11_size = sizeof(request) - sizeof(request.data_transfer_size) -
               sizeof(request.max_spdm_msg_size);

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, v11_size,
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 33: receiving an SPDM 1.3 request with CERT_CAP but no usable follow-on capability.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case33(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 34: receiving an SPDM 1.3 request without certificates but with CHAL_CAP.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case34(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 35: receiving an SPDM 1.3 request without certificates but with EP_INFO_CAP.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case35(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 36: receiving an SPDM 1.3 request with MUT_AUTH_CAP but neither CHAL_CAP nor KEY_EX_CAP.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case36(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x24;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 37: receiving an SPDM 1.3 request with reserved EP_INFO_CAP value.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case37(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x25;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                    (3u << 22) |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 38: receiving an SPDM 1.3 request with MULTI_KEY_CAP but no CERT_CAP.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case38(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x26;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 39: receiving an SPDM 1.3 request that asks for SupportedAlgorithms without CHUNK_CAP.
 * Expected behavior: the responder refuses the request with InvalidRequest.
 **/
static void rsp_capabilities_case39(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_get_capabilities_request_t request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x27;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.header.param1 = SPDM_GET_CAPABILITIES_REQUEST_PARAM1_SUPPORTED_ALGORITHMS;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    request.data_transfer_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

/**
 * Test 40: receiving a valid SPDM 1.4 request for SupportedAlgorithms including PQC/KEM data.
 * Expected behavior: the responder returns CAPABILITIES with the extended algorithm block.
 **/
static void rsp_capabilities_case40(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;
    spdm_get_capabilities_request_t request;
    spdm_supported_algorithms_block_t *supported_algorithms;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x28;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request.header.request_response_code = SPDM_GET_CAPABILITIES;
    request.header.param1 = SPDM_GET_CAPABILITIES_REQUEST_PARAM1_SUPPORTED_ALGORITHMS;
    request.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG |
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;
    request.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    request.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
    request.ext_flags = 0;

    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.pqc_asym_algo =
        SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.req_pqc_asym_alg =
        SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
    spdm_context->local_context.algorithm.kem_alg = SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP |
                                                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY |
                                                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP |
                                                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                                                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->local_context.capability.ext_flags = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(spdm_context, sizeof(request),
                                               &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size > sizeof(spdm_capabilities_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS);
    assert_int_equal(spdm_context->connection_info.capability.ext_flags, 0);
    supported_algorithms = (void *)(response + sizeof(spdm_capabilities_response_t));
    assert_int_equal(supported_algorithms->param1, 6);
}

/**
 * Test 41: message A is already full before processing a valid request.
 * Expected behavior: the responder returns an ERROR response with code Unspecified.
 **/
static void rsp_capabilities_case41(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x29;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->transcript.message_a.buffer_size =
        spdm_context->transcript.message_a.max_buffer_size;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);

    spdm_context->transcript.message_a.buffer_size = 0;
}

/**
 * Test 42: message A has room for the request but not the response.
 * Expected behavior: the responder returns an ERROR response with code Unspecified.
 **/
static void rsp_capabilities_case42(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2A;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->transcript.message_a.buffer_size =
        spdm_context->transcript.message_a.max_buffer_size -
        m_libspdm_get_capabilities_request1_size;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);

    spdm_context->transcript.message_a.buffer_size = 0;
}

int libspdm_rsp_capabilities_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success Case*/
        cmocka_unit_test(rsp_capabilities_case1),
        /* Success case where request size is larger than actual message. */
        cmocka_unit_test(rsp_capabilities_case2),
        /* response_state: LIBSPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(rsp_capabilities_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(rsp_capabilities_case4),
        /* connection_state Check*/
        cmocka_unit_test(rsp_capabilities_case6),
        /* Invalid requester capabilities flag (random flag)*/
        cmocka_unit_test(rsp_capabilities_case7),
        /* V1.1 Success case, all possible flags set*/
        cmocka_unit_test(rsp_capabilities_case8),
        /* Requester capabilities flag bit 0 is set. reserved value should ne ignored*/
        cmocka_unit_test(rsp_capabilities_case9),
        /* Can be populated with new test. */
        cmocka_unit_test(rsp_capabilities_case10),
        /* Can be populated with new test. */
        cmocka_unit_test(rsp_capabilities_case11),
        /* Can be populated with new test. */
        cmocka_unit_test(rsp_capabilities_case12),
        /* pub_key_id_cap and cert_cap set (flags are mutually exclusive)*/
        cmocka_unit_test(rsp_capabilities_case13),
        /* encrypt_cap set and key_ex_cap and psk_cap cleared (encrypt_cap demands key_ex_cap or psk_cap to be set)*/
        cmocka_unit_test(rsp_capabilities_case14),
        /* mac_cap set and key_ex_cap and psk_cap cleared (mac_cap demands key_ex_cap or psk_cap to be set)*/
        cmocka_unit_test(rsp_capabilities_case15),
        /* key_ex_cap set and encrypt_cap and mac_cap cleared (key_ex_cap demands encrypt_cap or mac_cap to be set)*/
        cmocka_unit_test(rsp_capabilities_case16),
        /* psk_cap set and encrypt_cap and mac_cap cleared (psk_cap demands encrypt_cap or mac_cap to be set)*/
        cmocka_unit_test(rsp_capabilities_case17),
        /* encap_cap cleared and MUT_AUTH set (MUT_AUTH demands encap_cap to be set)*/
        cmocka_unit_test(rsp_capabilities_case18),
        /* cert_cap set and pub_key_id_cap set (pub_key_id_cap demands cert_cap to be cleared)*/
        cmocka_unit_test(rsp_capabilities_case19),
        /* key_ex_cap cleared and handshake_in_the_clear_cap set (handshake_in_the_clear_cap demands key_ex_cap to be set)*/
        cmocka_unit_test(rsp_capabilities_case20),
        /* Open test case */
        cmocka_unit_test(rsp_capabilities_case21),
        /* cert_cap cleared and pub_key_id_cap set (pub_key_id_cap demands cert_cap to be cleared)*/
        cmocka_unit_test(rsp_capabilities_case22),
        /* Buffer verification*/
        cmocka_unit_test(rsp_capabilities_case23),
        /* V1.2 Success case, all possible flags set*/
        cmocka_unit_test(rsp_capabilities_case24),
        /* CHUNK_CAP == 0 and data_transfer_size != max_spdm_msg_size should result in error. */
        cmocka_unit_test(rsp_capabilities_case25),
        /* MaxSPDMmsgSize is less than DataTransferSize, then should result in error. */
        cmocka_unit_test(rsp_capabilities_case26),
        /* Success Case , capability supports MULTI_KEY_CAP */
        cmocka_unit_test(rsp_capabilities_case27),
        /* Success Case, GET_CAPABILITIES with param1[0] set and CHUNK_CAP enabled */
        cmocka_unit_test(rsp_capabilities_case28),
        cmocka_unit_test(rsp_capabilities_case29),
        cmocka_unit_test(rsp_capabilities_case30),
        cmocka_unit_test(rsp_capabilities_case31),
        cmocka_unit_test(rsp_capabilities_case32),
        cmocka_unit_test(rsp_capabilities_case33),
        cmocka_unit_test(rsp_capabilities_case34),
        cmocka_unit_test(rsp_capabilities_case35),
        cmocka_unit_test(rsp_capabilities_case36),
        cmocka_unit_test(rsp_capabilities_case37),
        cmocka_unit_test(rsp_capabilities_case38),
        cmocka_unit_test(rsp_capabilities_case39),
        cmocka_unit_test(rsp_capabilities_case40),
        cmocka_unit_test(rsp_capabilities_case41),
        cmocka_unit_test(rsp_capabilities_case42),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
