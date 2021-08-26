/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

#pragma pack(1)
typedef struct {
  spdm_negotiate_algorithms_request_t spdm_request_version10;
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[4];
} spdm_negotiate_algorithms_request_spdm11_t;

typedef struct {
  spdm_negotiate_algorithms_request_t spdm_request_version10;
  uint32 extra[21];
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[4];
} spdm_negotiate_algorithms_request_spdm11_oversized_t;

typedef struct {
  spdm_negotiate_algorithms_request_t spdm_request_version10;
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[12];
} spdm_negotiate_algorithms_request_spdm11_multiple_tables_t;

typedef struct {
  spdm_message_header_t  header;
  uint16               length;
  uint8                measurement_specification_sel;
  uint8                reserved;
  uint32               measurement_hash_algo;
  uint32               base_asym_sel;
  uint32               base_hash_sel;
  uint8                reserved2[12];
  uint8                ext_asym_sel_count;
  uint8                ext_hash_sel_count;
  uint16               reserved3;
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[4];
} spdm_algorithms_response_mine_t;
#pragma pack()

spdm_negotiate_algorithms_request_t m_spdm_negotiate_algorithms_request1 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
	sizeof(spdm_negotiate_algorithms_request_t),
	SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
uintn m_spdm_negotiate_algorithms_request1_size =
	sizeof(m_spdm_negotiate_algorithms_request1);

spdm_negotiate_algorithms_request_t m_spdm_negotiate_algorithms_request2 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
	sizeof(spdm_negotiate_algorithms_request_t),
	SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
uintn m_spdm_negotiate_algorithms_request2_size = sizeof(spdm_message_header_t);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request3 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request3_size = sizeof(m_spdm_negotiate_algorithm_request3);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request4 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request4_size = sizeof(m_spdm_negotiate_algorithm_request4);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request5 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request5_size = sizeof(m_spdm_negotiate_algorithm_request5);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request6 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request6_size = sizeof(m_spdm_negotiate_algorithm_request6);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request7 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request7_size = sizeof(m_spdm_negotiate_algorithm_request7);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request8 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request8_size = sizeof(m_spdm_negotiate_algorithm_request8);

spdm_negotiate_algorithms_request_spdm11_t    m_spdm_negotiate_algorithm_request9 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      BIT5
    }
  }
};
uintn m_spdm_negotiate_algorithm_request9_size = sizeof(m_spdm_negotiate_algorithm_request9);

spdm_negotiate_algorithms_request_t    m_spdm_negotiate_algorithm_request10 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_NEGOTIATE_ALGORITHMS,
    0,
    0
  },
  0x44,
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
uintn m_spdm_negotiate_algorithm_request10_size = 0x44;

spdm_negotiate_algorithms_request_spdm11_oversized_t    m_spdm_negotiate_algorithm_request11 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_oversized_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {0},
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request11_size = sizeof(m_spdm_negotiate_algorithm_request11);

spdm_negotiate_algorithms_request_spdm11_multiple_tables_t    m_spdm_negotiate_algorithm_request12 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      12,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_multiple_tables_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request12_size = sizeof(m_spdm_negotiate_algorithm_request12);

spdm_negotiate_algorithms_request_spdm11_multiple_tables_t    m_spdm_negotiate_algorithm_request13 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      11,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_multiple_tables_t)-sizeof(spdm_negotiate_algorithms_common_struct_table_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request13_size = sizeof(m_spdm_negotiate_algorithm_request13)-sizeof(spdm_negotiate_algorithms_common_struct_table_t);

spdm_negotiate_algorithms_request_spdm11_multiple_tables_t    m_spdm_negotiate_algorithm_request14 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      13,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_multiple_tables_t)+sizeof(spdm_negotiate_algorithms_common_struct_table_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request14_size = sizeof(m_spdm_negotiate_algorithm_request14)+sizeof(spdm_negotiate_algorithms_common_struct_table_t);

spdm_negotiate_algorithms_request_spdm11_multiple_tables_t    m_spdm_negotiate_algorithm_request15 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      12,
      0
    },
    sizeof(spdm_negotiate_algorithms_request_spdm11_multiple_tables_t),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      1,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
uintn m_spdm_negotiate_algorithm_request15_size = sizeof(m_spdm_negotiate_algorithm_request15);

void test_spdm_responder_algorithms_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ALGORITHMS);
}

void test_spdm_responder_algorithms_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request2_size,
		&m_spdm_negotiate_algorithms_request2, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_BUSY);
}

void test_spdm_responder_algorithms_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_REQUEST_RESYNCH);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NEED_RESYNC);
}

void test_spdm_responder_algorithms_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
	error_data =
		(spdm_error_data_response_not_ready_t *)(&spdm_response->length);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_RESPONSE_NOT_READY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NOT_READY);
	assert_int_equal(error_data->request_code, SPDM_NEGOTIATE_ALGORITHMS);
}

void test_spdm_responder_algorithms_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case7(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_mine_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x7;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request12_size, &m_spdm_negotiate_algorithm_request12, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_algorithms_response_t)+4*sizeof(spdm_negotiate_algorithms_common_struct_table_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
  assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (spdm_response->struct_table[0].alg_supported, spdm_context->local_context.algorithm.dhe_named_group);
  assert_int_equal (spdm_response->struct_table[1].alg_supported, spdm_context->local_context.algorithm.aead_cipher_suite);
  assert_int_equal (spdm_response->struct_table[2].alg_supported, spdm_context->local_context.algorithm.req_base_asym_alg);
  assert_int_equal (spdm_response->struct_table[3].alg_supported, spdm_context->local_context.algorithm.key_schedule);
}

void test_spdm_responder_algorithms_case8(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x8;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request4_size, &m_spdm_negotiate_algorithm_request4, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case9(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x9;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request5_size, &m_spdm_negotiate_algorithm_request5, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case10(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xA;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request6_size, &m_spdm_negotiate_algorithm_request6, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case11(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xB;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request7_size, &m_spdm_negotiate_algorithm_request7, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case12(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xC;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request8_size, &m_spdm_negotiate_algorithm_request8, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case13(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xD;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request9_size, &m_spdm_negotiate_algorithm_request9, &response_size, response);
  assert_int_equal (status, RETURN_SECURITY_VIOLATION);
}

void test_spdm_responder_algorithms_case14(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xE;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 0;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request10_size, &m_spdm_negotiate_algorithm_request10, &response_size, response);
  assert_int_equal (status, RETURN_DEVICE_ERROR);
}

void test_spdm_responder_algorithms_case15(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xF;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request11_size, &m_spdm_negotiate_algorithm_request11, &response_size, response);
  assert_int_equal (status, RETURN_DEVICE_ERROR);
}

void test_spdm_responder_algorithms_case16(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_mine_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x10;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request12_size, &m_spdm_negotiate_algorithm_request12, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_algorithms_response_t)+4*sizeof(spdm_negotiate_algorithms_common_struct_table_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
  assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (spdm_response->struct_table[0].alg_supported, spdm_context->local_context.algorithm.dhe_named_group);
  assert_int_equal (spdm_response->struct_table[1].alg_supported, spdm_context->local_context.algorithm.aead_cipher_suite);
  assert_int_equal (spdm_response->struct_table[2].alg_supported, spdm_context->local_context.algorithm.req_base_asym_alg);
  assert_int_equal (spdm_response->struct_table[3].alg_supported, spdm_context->local_context.algorithm.key_schedule);
}

void test_spdm_responder_algorithms_case17(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_mine_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x11;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request13_size, &m_spdm_negotiate_algorithm_request13, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_algorithms_response_t)+4*sizeof(spdm_negotiate_algorithms_common_struct_table_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
  assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (spdm_response->struct_table[0].alg_supported, spdm_context->local_context.algorithm.dhe_named_group);
  assert_int_equal (spdm_response->struct_table[1].alg_supported, spdm_context->local_context.algorithm.aead_cipher_suite);
  assert_int_equal (spdm_response->struct_table[2].alg_supported, spdm_context->local_context.algorithm.req_base_asym_alg);
  assert_int_equal (spdm_response->struct_table[3].alg_supported, spdm_context->local_context.algorithm.key_schedule);
}

void test_spdm_responder_algorithms_case18(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_mine_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x12;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request14_size, &m_spdm_negotiate_algorithm_request14, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case19(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_algorithms_response_mine_t *spdm_response;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x13;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
  spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

  spdm_context->transcript.message_a.buffer_size = 0;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  response_size = sizeof(response);
  status = spdm_get_response_algorithms (spdm_context, m_spdm_negotiate_algorithm_request12_size, &m_spdm_negotiate_algorithm_request12, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_algorithms_response_t)+4*sizeof(spdm_negotiate_algorithms_common_struct_table_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
  assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (spdm_response->struct_table[0].alg_supported, spdm_context->local_context.algorithm.dhe_named_group);
  assert_int_equal (spdm_response->struct_table[1].alg_supported, spdm_context->local_context.algorithm.aead_cipher_suite);
  assert_int_equal (spdm_response->struct_table[2].alg_supported, spdm_context->local_context.algorithm.req_base_asym_alg);
  assert_int_equal (spdm_response->struct_table[3].alg_supported, spdm_context->local_context.algorithm.key_schedule);
}

spdm_test_context_t m_spdm_responder_algorithms_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_algorithms_test_main(void)
{
	const struct CMUnitTest spdm_responder_algorithms_tests[] = {
		// Success Case
		cmocka_unit_test(test_spdm_responder_algorithms_case1),
		// Bad request size
		cmocka_unit_test(test_spdm_responder_algorithms_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_algorithms_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_algorithms_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_algorithms_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_algorithms_case6),
		// Success case V1.1
		cmocka_unit_test(test_spdm_responder_algorithms_case7),
		// No match for base_asym_algo
		cmocka_unit_test(test_spdm_responder_algorithms_case8),
		// No match for base_hash_algo
		cmocka_unit_test(test_spdm_responder_algorithms_case9),
		// No match for dhe_named_group
		cmocka_unit_test(test_spdm_responder_algorithms_case10),
		// No match for aead_cipher_suite
		cmocka_unit_test(test_spdm_responder_algorithms_case11),
		// No match for req_base_asym_alg
		cmocka_unit_test(test_spdm_responder_algorithms_case12),
		// No match for key_schedule
		cmocka_unit_test(test_spdm_responder_algorithms_case13),
		// Spdm length greater than 64 bytes for V1.0
		cmocka_unit_test(test_spdm_responder_algorithms_case14),
		// Spdm length greater than 128 bytes for V1.1
		cmocka_unit_test(test_spdm_responder_algorithms_case15),
		// Multiple repeated Alg structs for V1.1
		cmocka_unit_test(test_spdm_responder_algorithms_case16),
		// param1 is smaller than the number of Alg structs for V1.1
		cmocka_unit_test(test_spdm_responder_algorithms_case17),
		// param1 is bigger than the number of  Alg structs for V1.1
		cmocka_unit_test(test_spdm_responder_algorithms_case18),
		// Invalid  Alg structs + valid Alg Structs for V1.1
		cmocka_unit_test(test_spdm_responder_algorithms_case19),
	};

	m_spdm_negotiate_algorithms_request1.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithms_request1.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithms_request2.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithms_request2.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request3.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request3.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request4.spdm_request_version10.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
	m_spdm_negotiate_algorithm_request4.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request5.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request5.spdm_request_version10.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
	m_spdm_negotiate_algorithm_request6.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request6.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request7.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request7.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request8.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request8.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request9.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request9.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request10.ext_asym_count = 0x09;
	m_spdm_negotiate_algorithm_request11.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request11.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request11.spdm_request_version10.ext_asym_count = 0x15;
	m_spdm_negotiate_algorithm_request12.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request12.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request13.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request13.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request14.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request14.spdm_request_version10.base_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithm_request15.spdm_request_version10.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithm_request15.spdm_request_version10.base_hash_algo = m_use_hash_algo;

	setup_spdm_test_context(&m_spdm_responder_algorithms_test_context);

	return cmocka_run_group_tests(spdm_responder_algorithms_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
