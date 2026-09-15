# libspdm Responder API (DRAFT)

## Introduction
This document details the public API available to Integrators when constructing an SPDM Responder
using libspdm.

## SPDM Messages

---
### libspdm_responder_dispatch_message
---

### Description
Waits for a request message from the Requester. Once a message is received it processes the request,
forms a response message, and sends the response to the Requester.

### Parameters

**spdm_context**<br/>
The SPDM context.

### Details
Before calling this function the Integrator should have initialized the SPDM context and populated
it with configuration parameters, such as the Responder's capabilities and supported cryptography
algorithms.
<br/><br/>

---
### libspdm_get_response_func
---

### Description
Is called if libspdm receives an application (non-SPDM) message.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**is_app_message**<br/>
Indicates if the message is an application (non-SPDM) or SPDM message.

**request_size**<br/>
The size, in bytes, of the request message.

**request**<br/>
A pointer to a buffer that stores the request message.

**response_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the response message will be stored.
On output, indicates the size, in bytes, of the response message.

**response**<br/>
A pointer to a buffer that will store the response message.

### Details
TBD
<br/><br/>


---
### libspdm_register_get_response_func
---

### Description
Registers the location of the `libspdm_get_response_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**get_response_func**<br/>
A function pointer to the `libspdm_get_response_func` function.

### Details
TBD
<br/><br/>


---
### libspdm_generate_error_response
---

### Description
Generates an `ERROR` response message from the provided error code and error data.

### Parameters

**spdm_context**<br/>
The SPDM context.

**error_code**<br/>
The error code that will be used in `Param1` of the `ERROR` response message. This parameter is not
validated.

**error_data**<br/>
The error data that will be used in `Param2` of the `ERROR` response message. This parameter is not
validated.

**spdm_response_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the response message will be stored.
On output, indicates the size, in bytes, of the response message.

**spdm_response**<br/>
A pointer to a buffer that will store the response message.

### Details
TBD
<br/><br/>


---
### libspdm_generate_extended_error_response
---

### Description
Generates an `ERROR` response message from the provided error code, error data, and extended error
data.

### Parameters

**spdm_context**<br/>
The SPDM context.

**error_code**<br/>
The error code that will be used in `Param1` of the `ERROR` response message. This parameter is not
validated.

**error_data**<br/>
The error data that will be used in `Param2` of the `ERROR` response message. This parameter is not
validated.

**extended_error_data_size**<br/>
The size, in bytes, of the `extended_error_data` buffer.

**extended_error_data**<br/>
The extended error data that will be used in `ExtendedErrorData` of the `ERROR` response message.
This parameter is not validated.

**spdm_response_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the response message will be stored.
On output, indicates the size, in bytes, of the response message.

**spdm_response**<br/>
A pointer to a buffer that will store the response message.

### Details
TBD
<br/><br/>


---
### libspdm_session_state_callback_func
---

### Description
Is called whenever, for a given session ID, a session changes state.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session whose state has changed.

**session_state**<br/>
Specifies the state the session has transitioned to. Its value is one of
- LIBSPDM_SESSION_STATE_NOT_STARTED
    - The initial state.
- LIBSPDM_SESSION_STATE_HANDSHAKING
    - The Requester and Responder have started the handshake phase of session establishment.
- LIBSPDM_SESSION_STATE_ESTABLISHED
    - The Requester and Responder have established a session.

### Details
TBD
<br/><br/>


---
### libspdm_register_session_state_callback_func
---

### Description
Registers the location of the `libspdm_session_state_callback_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**spdm_session_state_callback**<br/>
A function pointer to the `libspdm_session_state_callback_func` function.

### Details
TBD
<br/><br/>


---
### libspdm_connection_state_callback_func
---

### Description
Is called whenever a connection changes state.

### Parameters

**spdm_context**<br/>
The SPDM context.

**connection_state**<br/>
Specifies the state the connection has transitioned to. Its value is one of
- `LIBSPDM_CONNECTION_STATE_NOT_STARTED`
    - The initial state after the SPDM context has been initialized or reset.
- `LIBSPDM_CONNECTION_STATE_AFTER_VERSION`
    - The state immediately after a successful `GET_VERSION` request and `VERSION` response.
- `LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES`
    - The state immediately after a successful `GET_CAPABILITIES` request and `CAPABILITIES`
      response.
- `LIBSPDM_CONNECTION_STATE_NEGOTIATED`
    - The state immediately after a successful `NEGOTIATE_ALGORITHMS` request and `ALGORITHMS`
      response.
- `LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS`
    - The state immediately after a successful `GET_DIGESTS` request and `DIGESTS` response.
- `LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE`
    - The state immediately after a successful `GET_CERTIFICATE` request and `CERTIFICATE` response.
- `LIBSPDM_CONNECTION_STATE_AUTHENTICATED`
    - The state immediately after a successful `CHALLENGE` request and `CHALLENGE_AUTH` response.

### Details
TBD
<br/><br/>


---
### libspdm_register_connection_state_callback_func
---

### Description
Registers the location of the `libspdm_connection_state_callback_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**spdm_connection_state_callback**<br/>
A function pointer to the `libspdm_connection_state_callback_func` function.

### Details
TBD
<br/><br/>


---
### libspdm_key_update_callback_func
---

### Description
Is called whenever, for a given session ID, a session's secret is updated.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session whose secret has changed.

**key_update_op**<br/>
Specifies the key exchange or update operation that caused the secret to change value. Its value is
one of
- LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE
- LIBSPDM_KEY_UPDATE_OPERATION_COMMIT_UPDATE
- LIBSPDM_KEY_UPDATE_OPERATION_DISCARD_UPDATE

### Details
TBD
<br/><br/>


---
### libspdm_register_key_update_callback_func
---

### Description
Registers the location of the `libspdm_key_update_callback_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**spdm_key_update_callback**<br/>
A function pointer to the `libspdm_key_update_callback_func` function.

### Details
TBD
<br/><br/>


## Encapsulated Requests

---
### libspdm_encap_flow_handler_func
---

### Description
Is called when libspdm needs the next encapsulated request, or when the encapsulated flow can be
terminated.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session the encapsulated flow belongs to, or NULL if it is not associated with a session. When
both endpoints have set `HANDSHAKE_IN_THE_CLEAR_CAP` the session-based mutual authentication flow is
conducted outside of a session, and this is still the session that the flow belongs to.

**encap_flow_type**<br/>
Specifies the encapsulated flow that is in progress. Its value is one of
- `LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH`
    - The basic mutual authentication flow, signaled by the Responder in `CHALLENGE_AUTH`.
- `LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH`
    - The session-based mutual authentication flow, signaled by the Responder in
      `KEY_EXCHANGE_RSP`.
- `LIBSPDM_ENCAP_FLOW_REQ_INITIATED`
    - A flow that the Requester began with `GET_ENCAPSULATED_REQUEST`.

**last_request_code**<br/>
The request code of the encapsulated request whose response has just been processed. Its value is 0
when libspdm is responding to `GET_ENCAPSULATED_REQUEST`.

**error_code**<br/>
If the Requester delivered an encapsulated `ERROR` then its `ErrorCode`, and the encapsulated
flow terminates once this function returns. Its value is 0 otherwise.

**terminate_flow**<br/>
Its value is false on input. On output, set to true to end the encapsulated flow.
`encap_request_size` is then ignored. It must be set to true when `error_code` is non-zero.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
The Integrator populates the buffer by calling one of the `libspdm_get_encap_request_*` functions,
passing `session_id` through to it unmodified. Returning an error terminates the flow with
`ERROR(Unspecified)`, as does producing a request that is not legal for `encap_flow_type`.
<br/><br/>
libspdm does not call this function when it determines the next message itself: while a multi-part
`GET_CERTIFICATE` or `KEY_UPDATE` is in progress, when reissuing an outstanding request with
`RESPOND_IF_READY`, or when it must terminate the flow on the Responder's behalf.
<br/><br/>
It is called when the Requester delivers an encapsulated `ERROR`, including
`ErrorCode=ResponseNotReady`, so that the Integrator learns why the flow ended. libspdm then
terminates the flow by clearing `ENCAPSULATED_RESPONSE_ACK.Param2`. For `ResponseNotReady` the
outstanding request is retained and reissued with `RESPOND_IF_READY` when the Requester returns
with `GET_ENCAPSULATED_REQUEST`.
<br/><br/>


---
### libspdm_register_encap_flow_handler
---

### Description
Registers the location of the `libspdm_encap_flow_handler_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**encap_flow_handler**<br/>
A function pointer to the `libspdm_encap_flow_handler_func` function.

### Details
The Integrator shall register a handler if the Responder's `ENCAP_CAP` is set.
<br/><br/>


---
### libspdm_get_encap_request_get_digests
---

### Description
Populates the buffer with an encapsulated `GET_DIGESTS` request.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The `session_id` given to `libspdm_encap_flow_handler_func`.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
Returns `LIBSPDM_STATUS_UNSUPPORTED_CAP` if the Requester's `CERT_CAP` is not set.
<br/><br/>


---
### libspdm_get_encap_request_get_certificate
---

### Description
Populates the buffer with an encapsulated `GET_CERTIFICATE` request.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The `session_id` given to `libspdm_encap_flow_handler_func`.

**slot_id**<br/>
The slot of the Requester's certificate chain to be retrieved, which is less than
`SPDM_MAX_SLOT_COUNT`.

**cert_chain_size**<br/>
The size, in bytes, of `cert_chain`.

**cert_chain**<br/>
A pointer to a buffer that will store the Requester's certificate chain.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
If the certificate chain spans multiple messages then libspdm issues the remaining requests itself,
accumulating the chain into `cert_chain`, and calls `libspdm_encap_flow_handler_func` once the
entire chain has been retrieved.
<br/><br/>
`cert_chain` shall therefore remain valid until the handler is next called, which is longer than
the call itself. A local variable of the function that calls
`libspdm_responder_dispatch_message`, or a member of the Integrator's own per-connection state, is
suitable; a local variable of the handler is not. Returns `LIBSPDM_STATUS_INVALID_PARAMETER` if
`cert_chain` is NULL, `cert_chain_size` is 0, or `slot_id` is not a valid slot.
<br/><br/>


---
### libspdm_get_encap_payload_size
---

### Description
Gets the size of the payload that the last encapsulated request retrieved.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The `session_id` given to `libspdm_encap_flow_handler_func`.

**payload_size**<br/>
On output, indicates the size, in bytes, of the payload that was written to the buffer given to the
encapsulated request function.

### Details
Some encapsulated requests, such as `GET_CERTIFICATE` and `GET_ENDPOINT_INFO`, are given a buffer
that libspdm writes the Requester's payload into. This is how the Integrator learns how much of that
buffer is valid.
<br/><br/>
The value applies to the payload of the request named by `last_request_code`, so it is read from
`libspdm_encap_flow_handler_func` when that handler is called for the request whose payload is
wanted. Only one encapsulated request is outstanding at a time, so a single accessor serves every
payload type.
<br/><br/>


---
### libspdm_get_encap_request_challenge
---

### Description
Populates the buffer with an encapsulated `CHALLENGE` request.

### Parameters

**spdm_context**<br/>
The SPDM context.

**req_slot_id**<br/>
The slot of the Requester's certificate chain to be authenticated against, or 0xFF if the
Requester's public key was provisioned.

**requester_context**<br/>
For SPDM 1.3 and above, a buffer of `SPDM_REQ_CONTEXT_SIZE` bytes holding the `Context` field, or
NULL for a zero-filled `Context`. It is ignored below SPDM 1.3.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
This is only legal in the basic mutual authentication flow, whose messages are always sent outside
of a session. libspdm terminates the flow once the encapsulated `CHALLENGE_AUTH` response has been
delivered. Returns `LIBSPDM_STATUS_INVALID_PARAMETER` if `req_slot_id` is neither a valid slot nor
0xFF.
<br/><br/>


---
### libspdm_get_encap_request_key_update
---

### Description
Populates the buffer with an encapsulated `KEY_UPDATE` request.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session in which the request is sent.

**operation**<br/>
`SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY` or `SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY`.
`SPDM_KEY_UPDATE_OPERATIONS_UPDATE_ALL_KEYS` is currently not legal in the encapsulated flow.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
`session_id` is passed by value, so the Integrator dereferences the `session_id` given to
`libspdm_encap_flow_handler_func`. After the acknowledgement libspdm issues the subsequent
`KEY_UPDATE` with `VerifyNewKey` itself.
<br/><br/>


---
### libspdm_get_encap_request_get_endpoint_info
---

### Description
Populates the buffer with an encapsulated `GET_ENDPOINT_INFO` request.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The `session_id` given to `libspdm_encap_flow_handler_func`.

**sub_code**<br/>
The `SubCode` of the request.

**slot_id**<br/>
The slot of the Requester's certificate chain used to sign the response, or 0xF if the Requester's
public key was provisioned. It is only meaningful when a signature is requested.

**request_attributes**<br/>
`SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED` to request a signature, otherwise 0.

**ep_info_size**<br/>
The size, in bytes, of `ep_info`.

**ep_info**<br/>
A pointer to a buffer that will store the Requester's endpoint information.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
libspdm records `request_attributes` and processes the `ENDPOINT_INFO` response accordingly, so a
signature is expected if, and only if, the Integrator asked for one. Requesting a signature when the
Requester's `EP_INFO_CAP_SIG` is not set returns `LIBSPDM_STATUS_UNSUPPORTED_CAP`.
<br/><br/>
libspdm writes the endpoint information into `ep_info` once the response is verified, and its size
is read with `libspdm_get_encap_payload_size`. `ep_info` shall therefore remain valid until the
handler is next called, which is longer than the call itself. A local variable of the function that
calls `libspdm_responder_dispatch_message`, or a member of the Integrator's own per-connection
state, is suitable; a local variable of the handler is not. Returns
`LIBSPDM_STATUS_INVALID_PARAMETER` if `ep_info` is NULL, `ep_info_size` is 0, or `slot_id` is
neither a valid slot nor 0xF.
<br/><br/>
If the Requester returns more endpoint information than `ep_info` can hold then the response is not
accepted and the encapsulated flow is terminated, in the same way as an oversized certificate chain.
<br/><br/>


---
### libspdm_get_encap_request_send_event
---

### Description
Populates the buffer with an encapsulated `SEND_EVENT` request.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session in which the request is sent.

**encap_request_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the encapsulated request will be
stored. On output, indicates the size, in bytes, of the encapsulated request.

**encap_request**<br/>
A pointer to a buffer that will store the encapsulated request.

### Details
`session_id` is passed by value, so the Integrator dereferences the `session_id` given to
`libspdm_encap_flow_handler_func`.
<br/><br/>