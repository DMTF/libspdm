/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_COMMON_LIB_INTERNAL_H__
#define __SPDM_COMMON_LIB_INTERNAL_H__

#include "library/spdm_common_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "library/spdm_return_status.h"

#define INVALID_SESSION_ID 0

typedef struct {
    uint8_t spdm_version_count;
    spdm_version_number_t spdm_version[SPDM_MAX_VERSION_COUNT];
} libspdm_device_version_t;

typedef struct {
    uint8_t ct_exponent;
    uint8_t rtt;
    uint32_t st1;
    uint32_t flags;
    uint32_t data_transfer_size;
    uint32_t max_spdm_msg_size;
} libspdm_device_capability_t;

typedef struct {
    uint8_t measurement_spec;
    uint8_t other_params_support;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint16_t dhe_named_group;
    uint16_t aead_cipher_suite;
    uint16_t req_base_asym_alg;
    uint16_t key_schedule;
} libspdm_device_algorithm_t;

typedef struct {

    /* Local device info*/

    libspdm_device_version_t version;
    libspdm_device_capability_t capability;
    libspdm_device_algorithm_t algorithm;
    libspdm_device_version_t secured_message_version;

    /* My Certificate*/

    const void *local_cert_chain_provision[SPDM_MAX_SLOT_COUNT];
    size_t local_cert_chain_provision_size[SPDM_MAX_SLOT_COUNT];
    uint8_t slot_count;
    /* My provisioned certificate (for slot_id - 0xFF, default 0)*/
    uint8_t provisioned_slot_id;

    /* Peer Root Certificate*/

    const void *peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT];
    size_t peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT];

    /* Peer CertificateChain
     * Whether it contains the root certificate or not,
     * it should be equal to the one returned from peer by get_certificate*/

    const void *peer_cert_chain_provision;
    size_t peer_cert_chain_provision_size;
    /* Peer Cert verify*/
    libspdm_verify_spdm_cert_chain_func verify_peer_spdm_cert_chain;

    /* PSK provision locally*/

    size_t psk_hint_size;
    const void *psk_hint;

    /* opaque_data provision locally*/

    size_t opaque_challenge_auth_rsp_size;
    uint8_t *opaque_challenge_auth_rsp;
    size_t opaque_measurement_rsp_size;
    uint8_t *opaque_measurement_rsp;

    /* Responder policy*/

    bool basic_mut_auth_requested;
    uint8_t mut_auth_requested;
    uint8_t heartbeat_period;
} libspdm_local_context_t;

typedef struct {

    /* Connection State*/

    libspdm_connection_state_t connection_state;

    /* Peer device info (negotiated)*/

    spdm_version_number_t version;
    libspdm_device_capability_t capability;
    libspdm_device_algorithm_t algorithm;
    spdm_version_number_t secured_message_version;

    /* Peer digests buffer */
    uint8_t peer_digest_slot_mask;
    uint8_t peer_total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];

    /* Peer CertificateChain */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t peer_used_cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t peer_used_cert_chain_buffer_size;
#else
    uint8_t peer_used_cert_chain_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t peer_used_cert_chain_buffer_hash_size;
    /* leaf cert public key of the peer */
    void *peer_used_leaf_cert_public_key;
#endif

    /* Local Used CertificateChain (for responder, or requester in mut auth)*/

    const uint8_t *local_used_cert_chain_buffer;
    size_t local_used_cert_chain_buffer_size;
} libspdm_connection_info_t;

typedef struct {
    size_t max_buffer_size;
    size_t buffer_size;
    /*uint8_t   buffer[max_buffer_size];*/
} libspdm_managed_buffer_t;

typedef struct {
    size_t max_buffer_size;
    size_t buffer_size;
    uint8_t buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
} libspdm_large_managed_buffer_t;

typedef struct {
    size_t max_buffer_size;
    size_t buffer_size;
    uint8_t buffer[LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE];
} libspdm_medium_managed_buffer_t;

typedef struct {
    size_t max_buffer_size;
    size_t buffer_size;
    uint8_t buffer[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];
} libspdm_small_managed_buffer_t;


/* signature = Sign(SK, hash(M1))
 * Verify(PK, hash(M2), signature)*/

/* M1/M2 = Concatenate (A, B, C)
 * A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
 * B = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
 * C = Concatenate (CHALLENGE, CHALLENGE_AUTH\signature)*/

/* Mut M1/M2 = Concatenate (MutB, MutC)
 * MutB = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
 * MutC = Concatenate (CHALLENGE, CHALLENGE_AUTH\signature)*/

/* signature = Sign(SK, hash(L1))
 * Verify(PK, hash(L2), signature)*/

/* L1/L2 = Concatenate (M)
 * M = Concatenate (GET_MEASUREMENT, MEASUREMENT\signature)*/

typedef struct {
    /* the message_a must be plan text because we do not know the algorithm yet.*/
    libspdm_small_managed_buffer_t message_a;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_large_managed_buffer_t message_b;
    libspdm_small_managed_buffer_t message_c;
    libspdm_large_managed_buffer_t message_mut_b;
    libspdm_small_managed_buffer_t message_mut_c;
    libspdm_large_managed_buffer_t message_m;
#else
    void                   *digest_context_m1m2;
    void                   *digest_context_mut_m1m2;
    void                   *digest_context_l1l2;
#endif
} libspdm_transcript_t;


/* TH for KEY_EXCHANGE response signature: Concatenate (A, Ct, K)
 * Ct = certificate chain
 * K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\signature+verify_data)*/

/* TH for KEY_EXCHANGE response HMAC: Concatenate (A, Ct, K)
 * Ct = certificate chain
 * K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\verify_data)*/

/* TH for FINISH request signature: Concatenate (A, Ct, K, CM, F)
 * Ct = certificate chain
 * K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)*/
/* CM = mutual certificate chain *
 * F  = Concatenate (FINISH request\signature+verify_data)*/

/* TH for FINISH response HMAC: Concatenate (A, Ct, K, CM, F)
 * Ct = certificate chain
 * K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)*/
/* CM = mutual certificate chain *
 * F = Concatenate (FINISH request\verify_data)*/

/* th1: Concatenate (A, Ct, K)
 * Ct = certificate chain
 * K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)*/

/* th2: Concatenate (A, Ct, K, CM, F)
 * Ct = certificate chain
 * K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)*/
/* CM = mutual certificate chain *
 * F  = Concatenate (FINISH request, FINISH response)*/


/* TH for PSK_EXCHANGE response HMAC: Concatenate (A, K)
 * K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response\verify_data)*/

/* TH for PSK_FINISH response HMAC: Concatenate (A, K, F)
 * K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
 * F  = Concatenate (PSK_FINISH request\verify_data)*/

/* TH1_PSK1: Concatenate (A, K)
 * K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response\verify_data)*/

/* TH1_PSK2: Concatenate (A, K, F)
 * K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
 * F  = Concatenate (PSK_FINISH request\verify_data)*/

/* TH2_PSK: Concatenate (A, K, F)
 * K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
 * F  = Concatenate (PSK_FINISH request, PSK_FINISH response)*/

typedef struct {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_large_managed_buffer_t message_k;
    libspdm_large_managed_buffer_t message_f;
    libspdm_large_managed_buffer_t message_m;
#else
    /* the message_k must be plan text because we do not know the finished_key yet.*/
    libspdm_medium_managed_buffer_t temp_message_k;
    bool message_f_initialized;
    bool finished_key_ready;
    void                   *digest_context_th;
    void                   *digest_context_l1l2;
    void                   *hmac_rsp_context_th;
    void                   *hmac_req_context_th;
    /* this is back up for message F reset.*/
    void                   *digest_context_th_backup;
    void                   *hmac_rsp_context_th_backup;
    void                   *hmac_req_context_th_backup;
#endif
} libspdm_session_transcript_t;

typedef struct {
    uint32_t session_id;
    bool use_psk;
    uint8_t mut_auth_requested;
    uint8_t end_session_attributes;
    uint8_t session_policy;
    libspdm_session_transcript_t session_transcript;
    void *secured_message_context;
} libspdm_session_info_t;

#define LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT 3
typedef struct {
    /* Valid OpCode: GET_DIEGST/GET_CERTIFICATE/CHALLENGE/KEY_UPDATE
     * The last one is 0x00, as terminator.*/
    uint8_t request_op_code_sequence[LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT +
                                     1];
    uint8_t request_op_code_count;
    uint8_t current_request_op_code;
    uint8_t request_id;
    uint8_t req_slot_id;
    spdm_message_header_t last_encap_request_header;
    size_t last_encap_request_size;
    uint16_t cert_chain_total_len;
    libspdm_large_managed_buffer_t certificate_chain_buffer;
} libspdm_encap_context_t;

#define libspdm_context_struct_version 0x2

typedef struct {
    uint32_t version;

    /* IO information*/

    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;

    /*
     * reserved for request and response in the main dispatch function in SPDM responder.
     * this buffer is the transport message recived from spdm_context->receive_message()
     * or sent to spdm_context->send_message().
     * This message may be SPDM transport message or secured SPDM transport message.
     **/
    libspdm_device_acquire_sender_buffer_func acquire_sender_buffer;
    libspdm_device_release_sender_buffer_func release_sender_buffer;
    libspdm_device_acquire_receiver_buffer_func acquire_receiver_buffer;
    libspdm_device_release_receiver_buffer_func release_receiver_buffer;

    /* Transport Layer infomration*/

    libspdm_transport_encode_message_func transport_encode_message;
    libspdm_transport_decode_message_func transport_decode_message;
    libspdm_transport_get_header_size_func transport_get_header_size;

    /* Cached plain text command
     * If the command is cipher text, decrypt then cache it.*/

    uint8_t last_spdm_request[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t last_spdm_request_size;

    /* scratch buffer */
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    /* sender buffer */
    uint8_t *sender_buffer;
    size_t sender_buffer_size;
    /* receiver buffer */
    uint8_t *receiver_buffer;
    size_t receiver_buffer_size;

    /* Cache session_id in this spdm_message, only valid for secured message.*/

    uint32_t last_spdm_request_session_id;
    bool last_spdm_request_session_id_valid;

    /* Cache the error in libspdm_process_request. It is handled in libspdm_build_response.*/

    libspdm_error_struct_t last_spdm_error;


    /* Register GetResponse function (responder only)*/

    size_t get_response_func;

    /* Register GetEncapResponse function (requester only)*/

    size_t get_encap_response_func;
    libspdm_encap_context_t encap_context;

    /* Register spdm_session_state_callback function (responder only)
     * Register can know the state after StartSession / EndSession.*/

    size_t spdm_session_state_callback[LIBSPDM_MAX_SESSION_STATE_CALLBACK_NUM];

    /* Register spdm_connection_state_callback function (responder only)
     * Register can know the connection state such as negotiated.*/

    size_t spdm_connection_state_callback
    [LIBSPDM_MAX_CONNECTION_STATE_CALLBACK_NUM];

    libspdm_local_context_t local_context;

    libspdm_connection_info_t connection_info;
    libspdm_transcript_t transcript;

    libspdm_session_info_t session_info[LIBSPDM_MAX_SESSION_COUNT];

    /* Cache lastest session ID for HANDSHAKE_IN_THE_CLEAR*/

    uint32_t latest_session_id;

    /* Register for Responder state, be initial to Normal (responder only)*/

    libspdm_response_state_t response_state;

    /* Cached data for SPDM_ERROR_CODE_RESPONSE_NOT_READY/SPDM_RESPOND_IF_READY*/

    spdm_error_data_response_not_ready_t error_data;
    uint8_t cache_spdm_request[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t cache_spdm_request_size;
    uint8_t current_token;

    /* Register for the retry times when receive "BUSY" Error response (requester only)*/

    uint8_t retry_times;
    bool crypto_request;


    /* App context data for use by application*/

    void *app_context_data_ptr;


    /* Register for the last KEY_UPDATE token and operation (responder only)*/

    uint8_t last_update_request[4];

    /* See LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_*. */

    uint8_t handle_error_return_policy;
} libspdm_context_t;

/**
 * This function dump raw data.
 *
 * @param  data  raw data
 * @param  size  raw data size
 **/
void libspdm_internal_dump_hex_str(const uint8_t *data, size_t size);

/**
 * This function dump raw data.
 *
 * @param  data  raw data
 * @param  size  raw data size
 **/
void libspdm_internal_dump_data(const uint8_t *data, size_t size);

/**
 * This function dump raw data with colume format.
 *
 * @param  data  raw data
 * @param  size  raw data size
 **/
void libspdm_internal_dump_hex(const uint8_t *data, size_t size);

/**
 * Append a new data buffer to the managed buffer.
 *
 * @param  managed_buffer                The managed buffer to be appended.
 * @param  buffer                       The address of the data buffer to be appended to the managed buffer.
 * @param  buffer_size                   The size in bytes of the data buffer to be appended to the managed buffer.
 *
 * @retval RETURN_SUCCESS               The new data buffer is appended to the managed buffer.
 * @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be appended.
 **/
libspdm_return_t libspdm_append_managed_buffer(void *managed_buffer,
                                               const void *buffer, size_t buffer_size);

/**
 * Reset the managed buffer.
 * The buffer_size is reset to 0.
 * The max_buffer_size is unchanged.
 * The buffer is not freed.
 *
 * @param  managed_buffer                The managed buffer to be shrinked.
 **/
void libspdm_reset_managed_buffer(void *managed_buffer);

/**
 * Return the size of managed buffer.
 *
 * @param  managed_buffer                The managed buffer.
 *
 * @return the size of managed buffer.
 **/
size_t libspdm_get_managed_buffer_size(void *managed_buffer);

/**
 * Return the address of managed buffer.
 *
 * @param  managed_buffer                The managed buffer.
 *
 * @return the address of managed buffer.
 **/
void *libspdm_get_managed_buffer(void *managed_buffer);

/**
 * Init the managed buffer.
 *
 * @param  managed_buffer                The managed buffer.
 * @param  max_buffer_size                The maximum size in bytes of the managed buffer.
 **/
void libspdm_init_managed_buffer(void *managed_buffer,
                                 size_t max_buffer_size);

/**
 * Reset message buffer in SPDM context according to request code.
 *
 * @param  spdm_context                   A pointer to the SPDM context.
 * @param  spdm_session_info             A pointer to the SPDM session context.
 * @param  spdm_request                   The SPDM request code.
 */
void libspdm_reset_message_buffer_via_request_code(void *context, void *session_info,
                                                   uint8_t request_code);

/**
 * This function initializes the session info.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 **/
void libspdm_session_info_init(libspdm_context_t *spdm_context,
                               libspdm_session_info_t *session_info,
                               uint32_t session_id, bool use_psk);

/**
 * This function allocates half of session ID for a requester.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return half of session ID for a requester.
 **/
uint16_t libspdm_allocate_req_session_id(libspdm_context_t *spdm_context);

/**
 * This function allocates half of session ID for a responder.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return half of session ID for a responder.
 **/
uint16_t libspdm_allocate_rsp_session_id(const libspdm_context_t *spdm_context);

/**
 * This function returns if a given version is supported based upon the GET_VERSION/VERSION.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  version                      The SPDM version.
 *
 * @retval true  the version is supported.
 * @retval false the version is not supported.
 **/
bool libspdm_is_version_supported(const libspdm_context_t *spdm_context,
                                  uint8_t version);

/**
 * This function returns connection version negotiated by GET_VERSION/VERSION.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return the connection version.
 **/
uint8_t libspdm_get_connection_version(const libspdm_context_t *spdm_context);

/**
 * This function returns if a capablities flag is supported in current SPDM connection.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Is the function called from a requester.
 * @param  requester_capabilities_flag    The requester capabilities flag to be checked
 * @param  responder_capabilities_flag    The responder capabilities flag to be checked
 *
 * @retval true  the capablities flag is supported.
 * @retval false the capablities flag is not supported.
 **/
bool
libspdm_is_capabilities_flag_supported(const libspdm_context_t *spdm_context,
                                       bool is_requester,
                                       uint32_t requester_capabilities_flag,
                                       uint32_t responder_capabilities_flag);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates m1m2.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_mut                        Indicate if this is from mutual authentication.
 * @param  m1m2_buffer_size               size in bytes of the m1m2
 * @param  m1m2_buffer                   The buffer to store the m1m2
 *
 * @retval RETURN_SUCCESS  m1m2 is calculated.
 */
bool libspdm_calculate_m1m2(void *context, bool is_mut,
                            size_t *m1m2_buffer_size,
                            void *m1m2_buffer);
#else
/*
 * This function calculates m1m2 hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_mut                        Indicate if this is from mutual authentication.
 * @param  m1m2_hash_size               size in bytes of the m1m2 hash
 * @param  m1m2_hash                   The buffer to store the m1m2 hash
 *
 * @retval RETURN_SUCCESS  m1m2 is calculated.
 */
bool libspdm_calculate_m1m2_hash(void *context, bool is_mut,
                                 size_t *m1m2_hash_size,
                                 void *m1m2_hash);
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  l1l2_buffer_size               size in bytes of the l1l2
 * @param  l1l2_buffer                   The buffer to store the l1l2
 *
 * @retval RETURN_SUCCESS  l1l2 is calculated.
 */
bool libspdm_calculate_l1l2(void *context, void *session_info,
                            size_t *l1l2_buffer_size, void *l1l2_buffer);
#else
/*
 * This function calculates l1l2 hash.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  l1l2_hash_size               size in bytes of the l1l2 hash
 * @param  l1l2_hash                   The buffer to store the l1l2 hash
 *
 * @retval RETURN_SUCCESS  l1l2 is calculated.
 */
bool libspdm_calculate_l1l2_hash(void *context, void *session_info,
                                 size_t *l1l2_hash_size, void *l1l2_hash);
#endif

/**
 * This function generates the certificate chain hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_id                    The slot index of the certificate chain.
 * @param  signature                    The buffer to store the certificate chain hash.
 *
 * @retval true  certificate chain hash is generated.
 * @retval false certificate chain hash is not generated.
 **/
bool libspdm_generate_cert_chain_hash(libspdm_context_t *spdm_context,
                                      size_t slot_id, uint8_t *hash);

/**
 * This function verifies the digest.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  digest                       The digest data buffer.
 * @param  digest_count                   size of the digest data buffer.
 *
 * @retval true  digest verification pass.
 * @retval false digest verification fail.
 **/
bool libspdm_verify_peer_digests(libspdm_context_t *spdm_context,
                                 const void *digest, size_t digest_count);

/**
 * This function verifies peer certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.
 * @param  trust_anchor                  A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
 * @param  trust_anchor_size             A buffer to hold the trust_anchor_size, if not NULL.
 * @param  is_requester                   Indicates if it is a requester message.
 *
 * @retval true  Peer certificate chain buffer verification passed.
 * @retval false Peer certificate chain buffer verification failed.
 **/
bool libspdm_verify_peer_cert_chain_buffer(libspdm_context_t *spdm_context,
                                           const void *cert_chain_buffer,
                                           size_t cert_chain_buffer_size,
                                           const void **trust_anchor,
                                           size_t *trust_anchor_size,
                                           bool is_requester);

/**
 * This function generates the challenge signature based upon m1m2 for authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Indicate of the signature generation for a requester or a responder.
 * @param  signature                    The buffer to store the challenge signature.
 *
 * @retval true  challenge signature is generated.
 * @retval false challenge signature is not generated.
 **/
bool libspdm_generate_challenge_auth_signature(libspdm_context_t *spdm_context,
                                               bool is_requester,
                                               uint8_t *signature);

/**
 * This function verifies the certificate chain hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  certificate_chain_hash         The certificate chain hash data buffer.
 * @param  certificate_chain_hash_size     size in bytes of the certificate chain hash data buffer.
 *
 * @retval true  hash verification pass.
 * @retval false hash verification fail.
 **/
bool
libspdm_verify_certificate_chain_hash(libspdm_context_t *spdm_context,
                                      const void *certificate_chain_hash,
                                      size_t certificate_chain_hash_size);

/**
 * This function verifies the challenge signature based upon m1m2.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Indicate of the signature verification for a requester or a responder.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool libspdm_verify_challenge_auth_signature(libspdm_context_t *spdm_context,
                                             bool is_requester,
                                             const void *sign_data,
                                             size_t sign_data_size);

/**
 * This function calculate the measurement summary hash size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Is the function called from a requester.
 * @param  measurement_summary_hash_type   The type of the measurement summary hash.
 *
 * @return 0 measurement summary hash type is invalid, NO_MEAS hash type or no MEAS capabilities.
 * @return measurement summary hash size according to type.
 **/
uint32_t
libspdm_get_measurement_summary_hash_size(libspdm_context_t *spdm_context,
                                          bool is_requester,
                                          uint8_t measurement_summary_hash_type);

/**
 * This function generates the measurement signature to response message based upon l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  signature                    The buffer to store the signature.
 *
 * @retval true  measurement signature is generated.
 * @retval false measurement signature is not generated.
 **/
bool libspdm_generate_measurement_signature(libspdm_context_t *spdm_context,
                                            libspdm_session_info_t *session_info,
                                            uint8_t *signature);

/**
 * This function verifies the measurement signature based upon l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool libspdm_verify_measurement_signature(libspdm_context_t *spdm_context,
                                          libspdm_session_info_t *session_info,
                                          const void *sign_data,
                                          size_t sign_data_size);

/**
 * This function generates the key exchange signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  signature                    The buffer to store the key exchange signature.
 *
 * @retval true  key exchange signature is generated.
 * @retval false key exchange signature is not generated.
 **/
bool
libspdm_generate_key_exchange_rsp_signature(libspdm_context_t *spdm_context,
                                            libspdm_session_info_t *session_info,
                                            uint8_t *signature);

/**
 * This function generates the key exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the key exchange HMAC.
 *
 * @retval true  key exchange HMAC is generated.
 * @retval false key exchange HMAC is not generated.
 **/
bool
libspdm_generate_key_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                       libspdm_session_info_t *session_info,
                                       uint8_t *hmac);

/**
 * This function verifies the key exchange signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool libspdm_verify_key_exchange_rsp_signature(
    libspdm_context_t *spdm_context, libspdm_session_info_t *session_info,
    const void *sign_data, const size_t sign_data_size);

/**
 * This function verifies the key exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_key_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                          libspdm_session_info_t *session_info,
                                          const void *hmac_data,
                                          size_t hmac_data_size);

/**
 * This function generates the finish signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  signature                    The buffer to store the finish signature.
 *
 * @retval true  finish signature is generated.
 * @retval false finish signature is not generated.
 **/
bool libspdm_generate_finish_req_signature(libspdm_context_t *spdm_context,
                                           libspdm_session_info_t *session_info,
                                           uint8_t *signature);

/**
 * This function generates the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  finish HMAC is generated.
 * @retval false finish HMAC is not generated.
 **/
bool libspdm_generate_finish_req_hmac(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t *session_info,
                                      void *hmac);

/**
 * This function verifies the finish signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool libspdm_verify_finish_req_signature(libspdm_context_t *spdm_context,
                                         libspdm_session_info_t *session_info,
                                         const void *sign_data,
                                         const size_t sign_data_size);

/**
 * This function verifies the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_finish_req_hmac(libspdm_context_t *spdm_context,
                                    libspdm_session_info_t *session_info,
                                    const uint8_t *hmac, size_t hmac_size);

/**
 * This function generates the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  finish HMAC is generated.
 * @retval false finish HMAC is not generated.
 **/
bool libspdm_generate_finish_rsp_hmac(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t *session_info,
                                      uint8_t *hmac);

/**
 * This function verifies the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_finish_rsp_hmac(libspdm_context_t *spdm_context,
                                    libspdm_session_info_t *session_info,
                                    const void *hmac_data,
                                    size_t hmac_data_size);

/**
 * This function generates the PSK exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the PSK exchange HMAC.
 *
 * @retval true  PSK exchange HMAC is generated.
 * @retval false PSK exchange HMAC is not generated.
 **/
bool
libspdm_generate_psk_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                       libspdm_session_info_t *session_info,
                                       uint8_t *hmac);

/**
 * This function verifies the PSK exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_psk_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                          libspdm_session_info_t *session_info,
                                          const void *hmac_data,
                                          size_t hmac_data_size);

/**
 * This function generates the PSK finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  PSK finish HMAC is generated.
 * @retval false PSK finish HMAC is not generated.
 **/
bool
libspdm_generate_psk_exchange_req_hmac(libspdm_context_t *spdm_context,
                                       libspdm_session_info_t *session_info,
                                       void *hmac);

/**
 * This function verifies the PSK finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_psk_finish_req_hmac(libspdm_context_t *spdm_context,
                                        libspdm_session_info_t *session_info,
                                        const uint8_t *hmac, size_t hmac_size);

/**
 * Return the size in bytes of opaque data supproted version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.
 *
 * @return the size in bytes of opaque data supproted version.
 **/
size_t libspdm_get_opaque_data_supported_version_data_size(
    libspdm_context_t *spdm_context);

/**
 * Build opaque data supported version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.
 *
 * @param  data_out_size                  size in bytes of the data_out.
 *                                     On input, it means the size in bytes of data_out buffer.
 *                                     On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out                      A pointer to the desination buffer to store the opaque data supported version.
 *
 * @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
libspdm_return_t
libspdm_build_opaque_data_supported_version_data(libspdm_context_t *spdm_context,
                                                 size_t *data_out_size,
                                                 void *data_out);

/**
 * Process opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.
 *
 * @param  data_in_size                   size in bytes of the data_in.
 * @param  data_in                       A pointer to the buffer to store the opaque data version selection.
 *
 * @retval RETURN_SUCCESS               The opaque data version selection is processed successfully.
 * @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data version selection.
 **/
libspdm_return_t
libspdm_process_opaque_data_version_selection_data(libspdm_context_t *spdm_context,
                                                   size_t data_in_size,
                                                   void *data_in);

/**
 * Return the size in bytes of opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.
 *
 * @return the size in bytes of opaque data version selection.
 **/
size_t libspdm_get_opaque_data_version_selection_data_size(
    const libspdm_context_t *spdm_context);

/**
 * Build opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.
 *
 * @param  data_out_size                  size in bytes of the data_out.
 *                                     On input, it means the size in bytes of data_out buffer.
 *                                     On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out                      A pointer to the desination buffer to store the opaque data version selection.
 *
 * @retval RETURN_SUCCESS               The opaque data version selection is built successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
libspdm_return_t
libspdm_build_opaque_data_version_selection_data(const libspdm_context_t *spdm_context,
                                                 size_t *data_out_size,
                                                 void *data_out);

/**
 * Process opaque data supported version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request parsing in responder.
 *
 * @param  data_in_size                   size in bytes of the data_in.
 * @param  data_in                       A pointer to the buffer to store the opaque data supported version.
 *
 * @retval RETURN_SUCCESS               The opaque data supported version is processed successfully.
 * @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data supported version.
 **/
libspdm_return_t
libspdm_process_opaque_data_supported_version_data(libspdm_context_t *spdm_context,
                                                   size_t data_in_size,
                                                   const void *data_in);

/**
 * Return the SPDMversion field of the version number struct.
 *
 * @param  ver                Spdm version number struct.
 *
 * @return the SPDMversion of the version number struct.
 **/
uint8_t libspdm_get_version_from_version_number(const spdm_version_number_t ver);

/**
 * Sort SPDMversion in descending order.
 *
 * @param  spdm_context                A pointer to the SPDM context.
 * @param  ver_set                    A pointer to the version set.
 * @param  ver_num                    Version number.
 */
void libspdm_version_number_sort(spdm_version_number_t *ver_set, size_t ver_num);

/**
 * Negotiate SPDMversion for connection.
 * ver_set is the local version set of requester, res_ver_set is the version set of responder.
 *
 * @param  common_version             A pointer to store the common version.
 * @param  req_ver_set                A pointer to the requester version set.
 * @param  req_ver_num                Version number of requester.
 * @param  res_ver_set                A pointer to the responder version set.
 * @param  res_ver_num                Version number of responder.
 *
 * @retval true                       Negotiation successfully, connect version be saved to common_version.
 * @retval false                      Negotiation failed.
 */
bool libspdm_negotiate_connection_version(spdm_version_number_t *common_version,
                                          spdm_version_number_t *req_ver_set,
                                          size_t req_ver_num,
                                          const spdm_version_number_t *res_ver_set,
                                          size_t res_ver_num);

/**
 * Acquire a device sender buffer for transport layer message.
 *
 * @param  context                       A pointer to the SPDM context.
 * @param  max_msg_size                  size in bytes of the maximum size of sender buffer.
 * @param  msg_buf_ptr                   A pointer to a sender buffer.
 *
 * @retval RETURN_SUCCESS               The sender buffer is acquired.
 **/
libspdm_return_t libspdm_acquire_sender_buffer (
    libspdm_context_t *spdm_context, size_t *max_msg_size, void **msg_buf_ptr);

/**
 * Release a device sender buffer for transport layer message.
 *
 * @param  context                       A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS               The sender buffer is Released.
 **/
void libspdm_release_sender_buffer (
    libspdm_context_t *spdm_context);

/**
 * Get the sender buffer.
 *
 * @param  context                  A pointer to the SPDM context.
 * @param  sender_buffer            Buffer address of the sender buffer.
 * @param  sender_buffer_size       Size of the sender buffer.
 *
 **/
void libspdm_get_sender_buffer (
    libspdm_context_t *spdm_context,
    void **sender_buffer,
    size_t *sender_buffer_size);

/**
 * Acquire a device receiver buffer for transport layer message.
 *
 * @param  context                       A pointer to the SPDM context.
 * @param  max_msg_size                  size in bytes of the maximum size of receiver buffer.
 * @param  msg_buf_pt                    A pointer to a receiver buffer.
 *
 * @retval RETURN_SUCCESS               The receiver buffer is acquired.
 **/
libspdm_return_t libspdm_acquire_receiver_buffer (
    libspdm_context_t *spdm_context, size_t *max_msg_size, void **msg_buf_ptr);

/**
 * Release a device receiver buffer for transport layer message.
 *
 * @param  context                       A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS               The receiver buffer is Released.
 **/
void libspdm_release_receiver_buffer (
    libspdm_context_t *spdm_context);

/**
 * Get the receiver buffer.
 *
 * @param  context                  A pointer to the SPDM context.
 * @param  receiver_buffer            Buffer address of the receiver buffer.
 * @param  receiver_buffer_size       Size of the receiver buffer.
 *
 **/
void libspdm_get_receiver_buffer (
    libspdm_context_t *spdm_context,
    void **receiver_buffer,
    size_t *receiver_buffer_size);

#endif
