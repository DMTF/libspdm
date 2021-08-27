/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_COMMON_LIB_H__
#define __SPDM_COMMON_LIB_H__

#include "spdm_lib_config.h"

#include <base.h>
#include <industry_standard/spdm.h>
#include <library/debuglib.h>
#include <library/memlib.h>
#include <library/cryptlib.h>
#include <library/spdm_crypt_lib.h>
#include <library/spdm_secured_message_lib.h>
#include <library/spdm_device_secret_lib.h>

//
// Connection: When a host sends messgages to a device, they create a connection.
//             The host can and only can create one connection with one device.
//             The host may create multiple connections with multiple devices at same time.
//             A connection can be unique identified by the connected device.
//             The message exchange in a connection is plain text.
//
// Session: In one connection with one device, a host may create multiple sessions.
//          The session starts with via KEY_EXCHANGE or PSK_EXCHANGE, and step with END_SESSION.
//          A session can be unique identified by a session ID, returned from the device.
//          The message exchange in a session is cipher text.
//

#define MAX_SPDM_VERSION_COUNT 5
#define MAX_SPDM_SLOT_COUNT 8
#define MAX_SPDM_OPAQUE_DATA_SIZE 1024

#define SPDM_NONCE_SIZE 32
#define SPDM_RANDOM_DATA_SIZE 32

#define SPDM_STATUS_SUCCESS 0
#define SPDM_STATUS_ERROR BIT31
#define SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES (SPDM_STATUS_ERROR + 0x10)
#define SPDM_STATUS_ERROR_DEVICE_ERROR (SPDM_STATUS_ERROR + 0x11)
#define SPDM_STATUS_ERROR_TCG_EXTEND_TPM_PCR (SPDM_STATUS_ERROR + 0x20)
#define SPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE (SPDM_STATUS_ERROR + 0x21)
#define SPDM_STATUS_ERROR_CHALLENGE_FAILURE (SPDM_STATUS_ERROR + 0x30)
#define SPDM_STATUS_ERROR_CERTIFICATE_FAILURE (SPDM_STATUS_ERROR + 0x31)
#define SPDM_STATUS_ERROR_NO_CERT_PROVISION (SPDM_STATUS_ERROR + 0x32)
#define SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE (SPDM_STATUS_ERROR + 0x40)
#define SPDM_STATUS_ERROR_NO_MUTUAL_AUTH (SPDM_STATUS_ERROR + 0x41)

typedef enum {
	//
	// SPDM parameter
	//
	SPDM_DATA_SPDM_VERSION,
	SPDM_DATA_SECURED_MESSAGE_VERSION,
	//
	// SPDM capability
	//
	SPDM_DATA_CAPABILITY_FLAGS,
	SPDM_DATA_CAPABILITY_CT_EXPONENT,
	//
	// SPDM algorithm setting
	//
	SPDM_DATA_MEASUREMENT_SPEC,
	SPDM_DATA_MEASUREMENT_HASH_ALGO,
	SPDM_DATA_BASE_ASYM_ALGO,
	SPDM_DATA_BASE_HASH_ALGO,
	SPDM_DATA_DHE_NAME_GROUP,
	SPDM_DATA_AEAD_CIPHER_SUITE,
	SPDM_DATA_REQ_BASE_ASYM_ALG,
	SPDM_DATA_KEY_SCHEDULE,
	//
	// Connection State
	//
	SPDM_DATA_CONNECTION_STATE,
	//
	// response_state
	//
	SPDM_DATA_RESPONSE_STATE,
	//
	// Certificate info
	//
	SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
	SPDM_DATA_LOCAL_SLOT_COUNT,
	SPDM_DATA_PEER_PUBLIC_ROOT_CERT_HASH,
	SPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
	SPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
	SPDM_DATA_MUT_AUTH_REQUESTED,
	//
	// Negotiated result
	//
	SPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
	SPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
	//
	// Pre-shared key Hint
	// If PSK is present, then PSK_EXCHANGE is used.
	// Otherwise, the KEY_EXCHANGE is used.
	//
	SPDM_DATA_PSK_HINT,
	//
	// SessionData
	//
	SPDM_DATA_SESSION_USE_PSK,
	SPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
	SPDM_DATA_SESSION_END_SESSION_ATTRIBUTES,
	//
	// Opaque data that can be used by the application
	// during callback functions such spdm_device_send_message_func.
	//
	SPDM_DATA_OPAQUE_CONTEXT_DATA,
	//
	// MAX
	//
	SPDM_DATA_MAX,
} spdm_data_type_t;

typedef enum {
	SPDM_DATA_LOCATION_LOCAL,
	SPDM_DATA_LOCATION_CONNECTION,
	SPDM_DATA_LOCATION_SESSION,
	SPDM_DATA_LOCATION_MAX,
} spdm_data_location_t;

typedef struct {
	spdm_data_location_t location;
	// data_type specific:
	//   session_id for the negoatiated key.
	//   SlotId for the certificate.
	//   req_slot_id + measurement_hash_type for SPDM_DATA_MUT_AUTH_REQUESTED
	uint8 additional_data[4];
} spdm_data_parameter_t;

typedef enum {
	//
	// Before GET_VERSION/VERSION
	//
	SPDM_CONNECTION_STATE_NOT_STARTED,
	//
	// After GET_VERSION/VERSION
	//
	SPDM_CONNECTION_STATE_AFTER_VERSION,
	//
	// After GET_CAPABILITIES/CAPABILITIES
	//
	SPDM_CONNECTION_STATE_AFTER_CAPABILITIES,
	//
	// After NEGOTIATE_ALGORITHMS/ALGORITHMS
	//
	SPDM_CONNECTION_STATE_NEGOTIATED,
	//
	// After GET_DIGESTS/DIGESTS
	//
	SPDM_CONNECTION_STATE_AFTER_DIGESTS,
	//
	// After GET_CERTIFICATE/CERTIFICATE
	//
	SPDM_CONNECTION_STATE_AFTER_CERTIFICATE,
	//
	// After CHALLENGE/CHALLENGE_AUTH, and ENCAP CALLENGE/CHALLENG_AUTH if MUT_AUTH is enabled.
	//
	SPDM_CONNECTION_STATE_AUTHENTICATED,
	//
	// MAX
	//
	SPDM_CONNECTION_STATE_MAX,
} spdm_connection_state_t;

typedef enum {
	//
	// Normal response.
	//
	SPDM_RESPONSE_STATE_NORMAL,
	//
	// Other component is busy.
	//
	SPDM_RESPONSE_STATE_BUSY,
	//
	// Hardware is not ready.
	//
	SPDM_RESPONSE_STATE_NOT_READY,
	//
	// Firmware Update is done. Need resync.
	//
	SPDM_RESPONSE_STATE_NEED_RESYNC,
	//
	// Processing Encapsulated message.
	//
	SPDM_RESPONSE_STATE_PROCESSING_ENCAP,
	//
	// MAX
	//
	SPDM_RESPONSE_STATE_MAX,
} spdm_response_state_t;

/**
  Set an SPDM context data.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  data_type                     Type of the SPDM context data.
  @param  parameter                    Type specific parameter of the SPDM context data.
  @param  data                         A pointer to the SPDM context data.
  @param  data_size                     size in bytes of the SPDM context data.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The data is NULL or the data_type is zero.
  @retval RETURN_UNSUPPORTED           The data_type is unsupported.
  @retval RETURN_ACCESS_DENIED         The data_type cannot be set.
  @retval RETURN_NOT_READY             data is not ready to set.
**/
return_status spdm_set_data(IN void *spdm_context,
			    IN spdm_data_type_t data_type,
			    IN spdm_data_parameter_t *parameter, IN void *data,
			    IN uintn data_size);

/**
  Get an SPDM context data.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  data_type                     Type of the SPDM context data.
  @param  parameter                    Type specific parameter of the SPDM context data.
  @param  data                         A pointer to the SPDM context data.
  @param  data_size                     size in bytes of the SPDM context data.
                                       On input, it means the size in bytes of data buffer.
                                       On output, it means the size in bytes of copied data buffer if RETURN_SUCCESS,
                                       and means the size in bytes of desired data buffer if RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The data_size is NULL or the data is NULL and *data_size is not zero.
  @retval RETURN_UNSUPPORTED           The data_type is unsupported.
  @retval RETURN_NOT_FOUND             The data_type cannot be found.
  @retval RETURN_NOT_READY             The data is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status spdm_get_data(IN void *spdm_context,
			    IN spdm_data_type_t data_type,
			    IN spdm_data_parameter_t *parameter,
			    IN OUT void *data, IN OUT uintn *data_size);

/**
  Get the last error of an SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.

  @return Last error of an SPDM context.
*/
uint32 spdm_get_last_error(IN void *spdm_context);

/**
  Get the last SPDM error struct of an SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  last_spdm_error                Last SPDM error struct of an SPDM context.
*/
void spdm_get_last_spdm_error_struct(IN void *spdm_context,
				     OUT spdm_error_struct_t *last_spdm_error);

/**
  Set the last SPDM error struct of an SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  last_spdm_error                Last SPDM error struct of an SPDM context.
*/
void spdm_set_last_spdm_error_struct(IN void *spdm_context,
				     IN spdm_error_struct_t *last_spdm_error);

/**
  Initialize an SPDM context.

  The size in bytes of the spdm_context can be returned by spdm_get_context_size.

  @param  spdm_context                  A pointer to the SPDM context.
*/
void spdm_init_context(IN void *spdm_context);

/**
  Reset an SPDM context.

  The size in bytes of the spdm_context can be returned by spdm_get_context_size.

  @param  spdm_context                  A pointer to the SPDM context.
*/
void spdm_reset_context(IN void *context);

/**
  Return the size in bytes of the SPDM context.

  @return the size in bytes of the SPDM context.
**/
uintn spdm_get_context_size(void);

/**
  Send an SPDM transport layer message to a device.

  The message is an SPDM message with transport layer wrapper,
  or a secured SPDM message with transport layer wrapper.

  For requester, the message is a transport layer SPDM request.
  For responder, the message is a transport layer SPDM response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than timeout.

  @retval RETURN_SUCCESS               The SPDM message is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is sent to the device.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
typedef return_status (*spdm_device_send_message_func)(IN void *spdm_context,
						       IN uintn message_size,
						       IN void *message,
						       IN uint64 timeout);

/**
  Receive an SPDM transport layer message from a device.

  The message is an SPDM message with transport layer wrapper,
  or a secured SPDM message with transport layer wrapper.

  For requester, the message is a transport layer SPDM response.
  For responder, the message is a transport layer SPDM request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than timeout.

  @retval RETURN_SUCCESS               The SPDM message is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is received from the device.
  @retval RETURN_INVALID_PARAMETER     The message is NULL, message_size is NULL or
                                       the *message_size is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
typedef return_status (*spdm_device_receive_message_func)(
	IN void *spdm_context, IN OUT uintn *message_size, IN OUT void *message,
	IN uint64 timeout);

/**
  Register SPDM device input/output functions.

  This function must be called after spdm_init_context, and before any SPDM communication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  send_message                  The fuction to send an SPDM transport layer message.
  @param  receive_message               The fuction to receive an SPDM transport layer message.
**/
void spdm_register_device_io_func(
	IN void *spdm_context, IN spdm_device_send_message_func send_message,
	IN spdm_device_receive_message_func receive_message);

/**
  Encode an SPDM or APP message to a transport layer message.

  For normal SPDM message, it adds the transport layer wrapper.
  For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
  For secured APP message, it encrypts a secured message then adds the transport layer wrapper.

  The APP message is encoded to a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  is_requester                  Indicates if it is a requester message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
typedef return_status (*spdm_transport_encode_message_func)(
	IN void *spdm_context, IN uint32 *session_id, IN boolean is_app_message,
	IN boolean is_requester, IN uintn spdm_message_size,
	IN void *spdm_message, IN OUT uintn *transport_message_size,
	OUT void *transport_message);

/**
  Decode an SPDM or APP message from a transport layer message.

  For normal SPDM message, it removes the transport layer wrapper,
  For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
  For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.

  The APP message is decoded from a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  is_requester                  Indicates if it is a requester message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.

  @retval RETURN_SUCCESS               The message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
  @retval RETURN_UNSUPPORTED           The transport_message is unsupported.
**/
typedef return_status (*spdm_transport_decode_message_func)(
	IN void *spdm_context, OUT uint32 **session_id,
	OUT boolean *is_app_message, IN boolean is_requester,
	IN uintn transport_message_size, IN void *transport_message,
	IN OUT uintn *message_size, OUT void *message);

/**
  Register SPDM transport layer encode/decode functions for SPDM or APP messages.

  This function must be called after spdm_init_context, and before any SPDM communication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  transport_encode_message       The fuction to encode an SPDM or APP message to a transport layer message.
  @param  transport_decode_message       The fuction to decode an SPDM or APP message from a transport layer message.
**/
void spdm_register_transport_layer_func(
	IN void *spdm_context,
	IN spdm_transport_encode_message_func transport_encode_message,
	IN spdm_transport_decode_message_func transport_decode_message);

/**
  Reset message A cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_a(IN void *spdm_context);

/**
  Reset message B cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_b(IN void *spdm_context);

/**
  Reset message C cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_c(IN void *spdm_context);

/**
  Reset message MutB cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_mut_b(IN void *spdm_context);

/**
  Reset message MutC cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_mut_c(IN void *spdm_context);

/**
  Reset message M cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_m(IN void *spdm_context);

/**
  Reset message buffer in SPDM context according to request code.

  @param  spdm_context                A pointer to the SPDM context.
  @param  spdm_request                The SPDM request code.
*/
void spdm_reset_message_buffer_via_request_code(IN void *context,
			       IN uint8 request_code);

/**
  Append message A cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_a(IN void *spdm_context, IN void *message,
				    IN uintn message_size);

/**
  Append message B cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_b(IN void *spdm_context, IN void *message,
				    IN uintn message_size);

/**
  Append message C cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_c(IN void *spdm_context, IN void *message,
				    IN uintn message_size);

/**
  Append message MutB cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_mut_b(IN void *spdm_context, IN void *message,
					IN uintn message_size);

/**
  Append message MutC cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_mut_c(IN void *spdm_context, IN void *message,
					IN uintn message_size);

/**
  Append message M cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_m(IN void *spdm_context, IN void *message,
				    IN uintn message_size);

/**
  Append message K cache in SPDM context.

  @param  spdm_session_info              A pointer to the SPDM session context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_k(IN void *spdm_session_info,
				    IN void *message, IN uintn message_size);

/**
  Append message F cache in SPDM context.

  @param  spdm_session_info              A pointer to the SPDM session context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_f(IN void *spdm_session_info,
				    IN void *message, IN uintn message_size);

/**
  This function gets the session info via session ID.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The SPDM session ID.

  @return session info.
**/
void *spdm_get_session_info_via_session_id(IN void *spdm_context,
					   IN uint32 session_id);

/**
  This function gets the secured message context via session ID.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The SPDM session ID.

  @return secured message context.
**/
void *spdm_get_secured_message_context_via_session_id(IN void *spdm_context,
						      IN uint32 session_id);

/**
  This function gets the secured message context via session ID.

  @param  spdm_session_info              A pointer to the SPDM context.

  @return secured message context.
**/
void *
spdm_get_secured_message_context_via_session_info(IN void *spdm_session_info);

/**
  This function assigns a new session ID.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The SPDM session ID.

  @return session info associated with this new session ID.
**/
void *spdm_assign_session_id(IN void *spdm_context, IN uint32 session_id,
			     IN boolean use_psk);

/**
  This function frees a session ID.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The SPDM session ID.

  @return freed session info assicated with this session ID.
**/
void *spdm_free_session_id(IN void *spdm_context, IN uint32 session_id);

/*
  This function calculates current TH data with message A and message K.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean spdm_calculate_th_for_exchange(
	IN void *spdm_context, IN void *spdm_session_info,
	IN uint8 *cert_chain_data, OPTIONAL IN uintn cert_chain_data_size,
	OPTIONAL IN OUT uintn *th_data_buffer_size, OUT void *th_data_buffer);

/*
  This function calculates current TH data with message A, message K and message F.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.
  @param  mut_cert_chain_data             Certitiface chain data without spdm_cert_chain_t header in mutual authentication.
  @param  mut_cert_chain_data_size         size in bytes of the certitiface chain data in mutual authentication.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean spdm_calculate_th_for_finish(IN void *spdm_context,
				     IN void *spdm_session_info,
				     IN uint8 *cert_chain_data,
				     OPTIONAL IN uintn cert_chain_data_size,
				     OPTIONAL IN uint8 *mut_cert_chain_data,
				     OPTIONAL IN uintn mut_cert_chain_data_size,
				     OPTIONAL IN OUT uintn *th_data_buffer_size,
				     OUT void *th_data_buffer);

/*
  This function calculates th1 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th1 hash

  @retval RETURN_SUCCESS  th1 hash is calculated.
*/
return_status spdm_calculate_th1_hash(IN void *spdm_context,
				      IN void *spdm_session_info,
				      IN boolean is_requester,
				      OUT uint8 *th1_hash_data);

/*
  This function calculates th2 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th2 hash

  @retval RETURN_SUCCESS  th2 hash is calculated.
*/
return_status spdm_calculate_th2_hash(IN void *spdm_context,
				      IN void *spdm_session_info,
				      IN boolean is_requester,
				      OUT uint8 *th2_hash_data);

/**
  This function returns peer certificate chain buffer including spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer including spdm_cert_chain_t header is returned.
  @retval FALSE Peer certificate chain buffer including spdm_cert_chain_t header is not found.
**/
boolean spdm_get_peer_cert_chain_buffer(IN void *spdm_context,
					OUT void **cert_chain_buffer,
					OUT uintn *cert_chain_buffer_size);

/**
  This function returns peer certificate chain data without spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.

  @retval TRUE  Peer certificate chain data without spdm_cert_chain_t header is returned.
  @retval FALSE Peer certificate chain data without spdm_cert_chain_t header is not found.
**/
boolean spdm_get_peer_cert_chain_data(IN void *spdm_context,
				      OUT void **cert_chain_data,
				      OUT uintn *cert_chain_data_size);

/**
  This function returns local used certificate chain buffer including spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.

  @retval TRUE  Local used certificate chain buffer including spdm_cert_chain_t header is returned.
  @retval FALSE Local used certificate chain buffer including spdm_cert_chain_t header is not found.
**/
boolean spdm_get_local_cert_chain_buffer(IN void *spdm_context,
					 OUT void **cert_chain_buffer,
					 OUT uintn *cert_chain_buffer_size);

/**
  This function returns local used certificate chain data without spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.

  @retval TRUE  Local used certificate chain data without spdm_cert_chain_t header is returned.
  @retval FALSE Local used certificate chain data without spdm_cert_chain_t header is not found.
**/
boolean spdm_get_local_cert_chain_data(IN void *spdm_context,
				       OUT void **cert_chain_data,
				       OUT uintn *cert_chain_data_size);

/**
  Reads a 24-bit value from memory that may be unaligned.

  @param  buffer  The pointer to a 24-bit value that may be unaligned.

  @return The 24-bit value read from buffer.
**/
uint32 spdm_read_uint24(IN uint8 *buffer);

/**
  Writes a 24-bit value to memory that may be unaligned.

  @param  buffer  The pointer to a 24-bit value that may be unaligned.
  @param  value   24-bit value to write to buffer.

  @return The 24-bit value to write to buffer.
**/
uint32 spdm_write_uint24(IN uint8 *buffer, IN uint32 value);

#endif
