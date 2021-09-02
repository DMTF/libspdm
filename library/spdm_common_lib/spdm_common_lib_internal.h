/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_COMMON_LIB_INTERNAL_H__
#define __SPDM_COMMON_LIB_INTERNAL_H__

#include <library/spdm_common_lib.h>
#include <library/spdm_secured_message_lib.h>

#define INVALID_SESSION_ID 0

typedef struct {
	uint8 spdm_version_count;
	spdm_version_number_t spdm_version[MAX_SPDM_VERSION_COUNT];
} spdm_device_version_t;

typedef struct {
	uint8 ct_exponent;
	uint32 flags;
} spdm_device_capability_t;

typedef struct {
	uint8 measurement_spec;
	uint32 measurement_hash_algo;
	uint32 base_asym_algo;
	uint32 base_hash_algo;
	uint16 dhe_named_group;
	uint16 aead_cipher_suite;
	uint16 req_base_asym_alg;
	uint16 key_schedule;
} spdm_device_algorithm_t;

typedef struct {
	//
	// Local device info
	//
	spdm_device_version_t version;
	spdm_device_capability_t capability;
	spdm_device_algorithm_t algorithm;
	spdm_device_version_t secured_message_version;
	//
	// My Certificate
	//
	void *local_cert_chain_provision[MAX_SPDM_SLOT_COUNT];
	uintn local_cert_chain_provision_size[MAX_SPDM_SLOT_COUNT];
	uint8 slot_count;
	// My provisioned certificate (for slot_id - 0xFF, default 0)
	uint8 provisioned_slot_id;
	//
	// Peer Root Certificate
	//
	void *peer_root_cert_provision;
	uintn peer_root_cert_provision_size;
	//
	// Peer CertificateChain
	// Whether it contains the root certificate or not,
	// it should be equal to the one returned from peer by get_certificate
	//
	void *peer_cert_chain_provision;
	uintn peer_cert_chain_provision_size;
	//
	// PSK provision locally
	//
	uintn psk_hint_size;
	void *psk_hint;
	//
	// opaque_data provision locally
	//
	uintn opaque_challenge_auth_rsp_size;
	uint8 *opaque_challenge_auth_rsp;
	uintn opaque_measurement_rsp_size;
	uint8 *opaque_measurement_rsp;
	//
	// Responder policy
	//
	boolean basic_mut_auth_requested;
	uint8 mut_auth_requested;
} spdm_local_context_t;

typedef struct {
	//
	// Connection State
	//
	spdm_connection_state_t connection_state;
	//
	// Peer device info (negotiated)
	//
	spdm_device_version_t version;
	spdm_device_capability_t capability;
	spdm_device_algorithm_t algorithm;
	spdm_device_version_t secured_message_version;
	//
	// Peer CertificateChain
	//
	uint8 peer_used_cert_chain_buffer[MAX_SPDM_CERT_CHAIN_SIZE];
	uintn peer_used_cert_chain_buffer_size;
	//
	// Local Used CertificateChain (for responder, or requester in mut auth)
	//
	uint8 *local_used_cert_chain_buffer;
	uintn local_used_cert_chain_buffer_size;
} spdm_connection_info_t;

typedef struct {
	uintn max_buffer_size;
	uintn buffer_size;
	//uint8   buffer[max_buffer_size];
} managed_buffer_t;

typedef struct {
	uintn max_buffer_size;
	uintn buffer_size;
	uint8 buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
} large_managed_buffer_t;

typedef struct {
	uintn max_buffer_size;
	uintn buffer_size;
	uint8 buffer[MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE];
} small_managed_buffer_t;

typedef struct {
	//
	// signature = Sign(SK, hash(M1))
	// Verify(PK, hash(M2), signature)
	//
	// M1/M2 = Concatenate (A, B, C)
	// A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
	// B = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
	// C = Concatenate (CHALLENGE, CHALLENGE_AUTH\signature)
	//
	// Mut M1/M2 = Concatenate (MutB, MutC)
	// MutB = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
	// MutC = Concatenate (CHALLENGE, CHALLENGE_AUTH\signature)
	//
	small_managed_buffer_t message_a;
	large_managed_buffer_t message_b;
	small_managed_buffer_t message_c;
	large_managed_buffer_t message_mut_b;
	small_managed_buffer_t message_mut_c;
	//
	// signature = Sign(SK, hash(L1))
	// Verify(PK, hash(L2), signature)
	//
	// L1/L2 = Concatenate (M)
	// M = Concatenate (GET_MEASUREMENT, MEASUREMENT\signature)
	//
	large_managed_buffer_t message_m;
} spdm_transcript_t;

typedef struct {
	//
	// TH for KEY_EXCHANGE response signature: Concatenate (A, Ct, K)
	// Ct = certificate chain
	// K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\signature+verify_data)
	//
	// TH for KEY_EXCHANGE response HMAC: Concatenate (A, Ct, K)
	// Ct = certificate chain
	// K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\verify_data)
	//
	// TH for FINISH request signature: Concatenate (A, Ct, K, CM, F)
	// Ct = certificate chain
	// K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
	// CM = mutual certificate chain *
	// F  = Concatenate (FINISH request\signature+verify_data)
	//
	// TH for FINISH response HMAC: Concatenate (A, Ct, K, CM, F)
	// Ct = certificate chain
	// K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
	// CM = mutual certificate chain *
	// F = Concatenate (FINISH request\verify_data)
	//
	// th1: Concatenate (A, Ct, K)
	// Ct = certificate chain
	// K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
	//
	// th2: Concatenate (A, Ct, K, CM, F)
	// Ct = certificate chain
	// K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
	// CM = mutual certificate chain *
	// F  = Concatenate (FINISH request, FINISH response)
	//
	large_managed_buffer_t message_k;
	large_managed_buffer_t message_f;
	//
	// TH for PSK_EXCHANGE response HMAC: Concatenate (A, K)
	// K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response\verify_data)
	//
	// TH for PSK_FINISH response HMAC: Concatenate (A, K, PF)
	// K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
	// F  = Concatenate (PSK_FINISH request\verify_data)
	//
	// TH1_PSK1: Concatenate (A, K)
	// K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response\verify_data)
	//
	// TH1_PSK2: Concatenate (A, K, F)
	// K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
	// F  = Concatenate (PSK_FINISH request\verify_data)
	//
	// TH2_PSK: Concatenate (A, K, F)
	// K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
	// F  = Concatenate (PSK_FINISH request, PSK_FINISH response)
	//
} spdm_session_transcript_t;

typedef struct {
	uint32 session_id;
	boolean use_psk;
	uint8 mut_auth_requested;
	uint8 end_session_attributes;
	spdm_session_transcript_t session_transcript;
	void *secured_message_context;
} spdm_session_info_t;

#define MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT 3
typedef struct {
	uint32 error_state;
	// Valid OpCode: GET_DIEGST/GET_CERTIFICATE/CHALLENGE/KEY_UPDATE
	// The last one is 0x00, as terminator.
	uint8 request_op_code_sequence[MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT +
				       1];
	uint8 request_op_code_count;
	uint8 current_request_op_code;
	uint8 request_id;
	uint8 req_slot_id;
	spdm_message_header_t last_encap_request_header;
	uintn last_encap_request_size;
	large_managed_buffer_t certificate_chain_buffer;
} spdm_encap_context_t;

#define spdm_context_struct_VERSION 0x1

typedef struct {
	uint32 version;
	//
	// IO information
	//
	spdm_device_send_message_func send_message;
	spdm_device_receive_message_func receive_message;
	//
	// Transport Layer infomration
	//
	spdm_transport_encode_message_func transport_encode_message;
	spdm_transport_decode_message_func transport_decode_message;

	//
	// command status
	//
	uint32 error_state;
	//
	// Cached plain text command
	// If the command is cipher text, decrypt then cache it.
	//
	uint8 last_spdm_request[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn last_spdm_request_size;
	//
	// Cache session_id in this spdm_message, only valid for secured message.
	//
	uint32 last_spdm_request_session_id;
	boolean last_spdm_request_session_id_valid;
	//
	// Cache the error in spdm_process_request. It is handled in spdm_build_response.
	//
	spdm_error_struct_t last_spdm_error;

	//
	// Register GetResponse function (responder only)
	//
	uintn get_response_func;
	//
	// Register GetEncapResponse function (requester only)
	//
	uintn get_encap_response_func;
	spdm_encap_context_t encap_context;
	//
	// Register spdm_session_state_callback function (responder only)
	// Register can know the state after StartSession / EndSession.
	//
	uintn spdm_session_state_callback[MAX_SPDM_SESSION_STATE_CALLBACK_NUM];
	//
	// Register spdm_connection_state_callback function (responder only)
	// Register can know the connection state such as negotiated.
	//
	uintn spdm_connection_state_callback
		[MAX_SPDM_CONNECTION_STATE_CALLBACK_NUM];

	spdm_local_context_t local_context;

	spdm_connection_info_t connection_info;
	spdm_transcript_t transcript;

	spdm_session_info_t session_info[MAX_SPDM_SESSION_COUNT];
	//
	// Cache lastest session ID for HANDSHAKE_IN_THE_CLEAR
	//
	uint32 latest_session_id;
	//
	// Register for Responder state, be initial to Normal (responder only)
	//
	spdm_response_state_t response_state;
	//
	// Cached data for SPDM_ERROR_CODE_RESPONSE_NOT_READY/SPDM_RESPOND_IF_READY
	//
	spdm_error_data_response_not_ready_t error_data;
	uint8 cache_spdm_request[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn cache_spdm_request_size;
	uint8 current_token;
	//
	// Register for the retry times when receive "BUSY" Error response (requester only)
	//
	uint8 retry_times;
} spdm_context_t;

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex_str(IN uint8 *data, IN uintn size);

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_data(IN uint8 *data, IN uintn size);

/**
  This function dump raw data with colume format.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex(IN uint8 *data, IN uintn size);

/**
  Append a new data buffer to the managed buffer.

  @param  managed_buffer_t                The managed buffer to be appended.
  @param  buffer                       The address of the data buffer to be appended to the managed buffer.
  @param  buffer_size                   The size in bytes of the data buffer to be appended to the managed buffer.

  @retval RETURN_SUCCESS               The new data buffer is appended to the managed buffer.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be appended.
**/
return_status append_managed_buffer(IN OUT void *managed_buffer_t,
				    IN void *buffer, IN uintn buffer_size);

/**
  Shrink the size of the managed buffer.

  @param  managed_buffer_t                The managed buffer to be shrinked.
  @param  buffer_size                   The size in bytes of the size of the buffer to be shrinked.

  @retval RETURN_SUCCESS               The managed buffer is shrinked.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be shrinked.
**/
return_status shrink_managed_buffer(IN OUT void *managed_buffer_t,
				    IN uintn buffer_size);

/**
  Reset the managed buffer.
  The buffer_size is reset to 0.
  The max_buffer_size is unchanged.
  The buffer is not freed.

  @param  managed_buffer_t                The managed buffer to be shrinked.
**/
void reset_managed_buffer(IN OUT void *managed_buffer_t);

/**
  Return the size of managed buffer.

  @param  managed_buffer_t                The managed buffer.

  @return the size of managed buffer.
**/
uintn get_managed_buffer_size(IN void *managed_buffer_t);

/**
  Return the address of managed buffer.

  @param  managed_buffer_t                The managed buffer.

  @return the address of managed buffer.
**/
void *get_managed_buffer(IN void *managed_buffer_t);

/**
  Init the managed buffer.

  @param  managed_buffer_t                The managed buffer.
  @param  max_buffer_size                The maximum size in bytes of the managed buffer.
**/
void init_managed_buffer(IN OUT void *managed_buffer_t,
			 IN uintn max_buffer_size);

/**
  This function initializes the session info.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The SPDM session ID.
**/
void spdm_session_info_init(IN spdm_context_t *spdm_context,
			    IN spdm_session_info_t *session_info,
			    IN uint32 session_id, IN boolean use_psk);

/**
  This function allocates half of session ID for a requester.

  @param  spdm_context                  A pointer to the SPDM context.

  @return half of session ID for a requester.
**/
uint16 spdm_allocate_req_session_id(IN spdm_context_t *spdm_context);

/**
  This function allocates half of session ID for a responder.

  @param  spdm_context                  A pointer to the SPDM context.

  @return half of session ID for a responder.
**/
uint16 spdm_allocate_rsp_session_id(IN spdm_context_t *spdm_context);

/**
  This function returns if a given version is supported based upon the GET_VERSION/VERSION.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  version                      The SPDM version.

  @retval TRUE  the version is supported.
  @retval FALSE the version is not supported.
**/
boolean spdm_is_version_supported(IN spdm_context_t *spdm_context,
				  IN uint8 version);

/**
  This function returns if a capablities flag is supported in current SPDM connection.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Is the function called from a requester.
  @param  requester_capabilities_flag    The requester capabilities flag to be checked
  @param  responder_capabilities_flag    The responder capabilities flag to be checked

  @retval TRUE  the capablities flag is supported.
  @retval FALSE the capablities flag is not supported.
**/
boolean
spdm_is_capabilities_flag_supported(IN spdm_context_t *spdm_context,
				    IN boolean is_requester,
				    IN uint32 requester_capabilities_flag,
				    IN uint32 responder_capabilities_flag);

/*
  This function calculates m1m2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_mut                        Indicate if this is from mutual authentication.
  @param  m1m2_buffer_size               size in bytes of the m1m2
  @param  m1m2_buffer                   The buffer to store the m1m2

  @retval RETURN_SUCCESS  m1m2 is calculated.
*/
boolean spdm_calculate_m1m2(IN void *context, IN boolean is_mut,
			    IN OUT uintn *m1m2_buffer_size,
			    OUT void *m1m2_buffer);

/*
  This function calculates l1l2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  l1l2_buffer_size               size in bytes of the l1l2
  @param  l1l2_buffer                   The buffer to store the l1l2

  @retval RETURN_SUCCESS  l1l2 is calculated.
*/
boolean spdm_calculate_l1l2(IN void *context, IN OUT uintn *l1l2_buffer_size,
			    OUT void *l1l2_buffer);

/**
  This function generates the certificate chain hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                    The slot index of the certificate chain.
  @param  signature                    The buffer to store the certificate chain hash.

  @retval TRUE  certificate chain hash is generated.
  @retval FALSE certificate chain hash is not generated.
**/
boolean spdm_generate_cert_chain_hash(IN spdm_context_t *spdm_context,
				      IN uintn slot_id, OUT uint8 *hash);

/**
  This function verifies the digest.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  digest                       The digest data buffer.
  @param  digest_count                   size of the digest data buffer.

  @retval TRUE  digest verification pass.
  @retval FALSE digest verification fail.
**/
boolean spdm_verify_peer_digests(IN spdm_context_t *spdm_context,
				 IN void *digest, IN uintn digest_count);

/**
  This function verifies peer certificate chain buffer including spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer verification passed.
  @retval FALSE Peer certificate chain buffer verification failed.
**/
boolean spdm_verify_peer_cert_chain_buffer(IN spdm_context_t *spdm_context,
					   IN void *cert_chain_buffer,
					   IN uintn cert_chain_buffer_size);

/**
  This function generates the challenge signature based upon m1m2 for authentication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Indicate of the signature generation for a requester or a responder.
  @param  signature                    The buffer to store the challenge signature.

  @retval TRUE  challenge signature is generated.
  @retval FALSE challenge signature is not generated.
**/
boolean spdm_generate_challenge_auth_signature(IN spdm_context_t *spdm_context,
					       IN boolean is_requester,
					       OUT uint8 *signature);

/**
  This function verifies the certificate chain hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  certificate_chain_hash         The certificate chain hash data buffer.
  @param  certificate_chain_hash_size     size in bytes of the certificate chain hash data buffer.

  @retval TRUE  hash verification pass.
  @retval FALSE hash verification fail.
**/
boolean
spdm_verify_certificate_chain_hash(IN spdm_context_t *spdm_context,
				   IN void *certificate_chain_hash,
				   IN uintn certificate_chain_hash_size);

/**
  This function verifies the challenge signature based upon m1m2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Indicate of the signature verification for a requester or a responder.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_challenge_auth_signature(IN spdm_context_t *spdm_context,
					     IN boolean is_requester,
					     IN void *sign_data,
					     IN uintn sign_data_size);

/**
  This function calculate the measurement summary hash size.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Is the function called from a requester.
  @param  measurement_summary_hash_type   The type of the measurement summary hash.

  @return 0 measurement summary hash type is invalid, NO_MEAS hash type or no MEAS capabilities.
  @return measurement summary hash size according to type.
**/
uint32
spdm_get_measurement_summary_hash_size(IN spdm_context_t *spdm_context,
				       IN boolean is_requester,
				       IN uint8 measurement_summary_hash_type);

/**
  This function calculate the measurement summary hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Is the function called from a requester.
  @param  measurement_summary_hash_type   The type of the measurement summary hash.
  @param  measurement_summary_hash       The buffer to store the measurement summary hash.

  @retval TRUE  measurement summary hash is generated or skipped.
  @retval FALSE measurement summary hash is not generated.
**/
boolean
spdm_generate_measurement_summary_hash(IN spdm_context_t *spdm_context,
				       IN boolean is_requester,
				       IN uint8 measurement_summary_hash_type,
				       OUT uint8 *measurement_summary_hash);

/**
  This function generates the measurement signature to response message based upon l1l2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  signature                    The buffer to store the signature.

  @retval TRUE  measurement signature is created.
  @retval FALSE measurement signature is not created.
**/
boolean spdm_generate_measurement_signature(IN spdm_context_t *spdm_context,
					    OUT uint8 *signature);

/**
  This function verifies the measurement signature based upon l1l2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_measurement_signature(IN spdm_context_t *spdm_context,
					  IN void *sign_data,
					  IN uintn sign_data_size);

/**
  This function generates the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the key exchange signature.

  @retval TRUE  key exchange signature is generated.
  @retval FALSE key exchange signature is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_signature(IN spdm_context_t *spdm_context,
					 IN spdm_session_info_t *session_info,
					 OUT uint8 *signature);

/**
  This function generates the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the key exchange HMAC.

  @retval TRUE  key exchange HMAC is generated.
  @retval FALSE key exchange HMAC is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    OUT uint8 *hmac);

/**
  This function verifies the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_key_exchange_rsp_signature(
	IN spdm_context_t *spdm_context, IN spdm_session_info_t *session_info,
	IN void *sign_data, IN intn sign_data_size);

/**
  This function verifies the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_key_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
					  IN spdm_session_info_t *session_info,
					  IN void *hmac_data,
					  IN uintn hmac_data_size);

/**
  This function generates the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
boolean spdm_generate_finish_req_signature(IN spdm_context_t *spdm_context,
					   IN spdm_session_info_t *session_info,
					   OUT uint8 *signature);

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean spdm_generate_finish_req_hmac(IN spdm_context_t *spdm_context,
				      IN spdm_session_info_t *session_info,
				      OUT void *hmac);

/**
  This function verifies the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_finish_req_signature(IN spdm_context_t *spdm_context,
					 IN spdm_session_info_t *session_info,
					 IN void *sign_data,
					 IN intn sign_data_size);

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_finish_req_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    IN uint8 *hmac, IN uintn hmac_size);

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean spdm_generate_finish_rsp_hmac(IN spdm_context_t *spdm_context,
				      IN spdm_session_info_t *session_info,
				      OUT uint8 *hmac);

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_finish_rsp_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    IN void *hmac_data,
				    IN uintn hmac_data_size);

/**
  This function generates the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the PSK exchange HMAC.

  @retval TRUE  PSK exchange HMAC is generated.
  @retval FALSE PSK exchange HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    OUT uint8 *hmac);

/**
  This function verifies the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_psk_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
					  IN spdm_session_info_t *session_info,
					  IN void *hmac_data,
					  IN uintn hmac_data_size);

/**
  This function generates the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  PSK finish HMAC is generated.
  @retval FALSE PSK finish HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_req_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    OUT void *hmac);

/**
  This function verifies the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_psk_finish_req_hmac(IN spdm_context_t *spdm_context,
					IN spdm_session_info_t *session_info,
					IN uint8 *hmac, IN uintn hmac_size);

/**
  Return the size in bytes of opaque data supproted version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @return the size in bytes of opaque data supproted version.
**/
uintn spdm_get_opaque_data_supported_version_data_size(
	IN spdm_context_t *spdm_context);

/**
  Build opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @param  data_out_size                  size in bytes of the data_out.
                                       On input, it means the size in bytes of data_out buffer.
                                       On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  data_out                      A pointer to the desination buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_build_opaque_data_supported_version_data(IN spdm_context_t *spdm_context,
					      IN OUT uintn *data_out_size,
					      OUT void *data_out);

/**
  Process opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.

  @param  data_in_size                   size in bytes of the data_in.
  @param  data_in                       A pointer to the buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is processed successfully.
  @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data version selection.
**/
return_status
spdm_process_opaque_data_version_selection_data(IN spdm_context_t *spdm_context,
						IN uintn data_in_size,
						IN void *data_in);

/**
  Return the size in bytes of opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @return the size in bytes of opaque data version selection.
**/
uintn spdm_get_opaque_data_version_selection_data_size(
	IN spdm_context_t *spdm_context);

/**
  Build opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @param  data_out_size                  size in bytes of the data_out.
                                       On input, it means the size in bytes of data_out buffer.
                                       On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  data_out                      A pointer to the desination buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_build_opaque_data_version_selection_data(IN spdm_context_t *spdm_context,
					      IN OUT uintn *data_out_size,
					      OUT void *data_out);

/**
  Process opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request parsing in responder.

  @param  data_in_size                   size in bytes of the data_in.
  @param  data_in                       A pointer to the buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is processed successfully.
  @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data supported version.
**/
return_status
spdm_process_opaque_data_supported_version_data(IN spdm_context_t *spdm_context,
						IN uintn data_in_size,
						IN void *data_in);

#endif
