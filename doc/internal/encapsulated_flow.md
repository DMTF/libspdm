# Encapsulated Flows and API Patterns

Since its introduction in SPDM 1.1 to support mutual authentication, the encapsulated flow has
expanded in subsequent versions of the specification into multiple flows with different
characteristics. At a high level these flows can be categorized as

- Mutual Authentication
    - `GET_DIGEST` and `GET_CERTIFICATE`.
    - The deprecated basic mutual authentication flow also includes `CHALLENGE`.
- Certificate Retrieval
    - `GET_DIGEST` and `GET_CERTIFICATE` outside of the mutual authentication flow.
- Secure Session Management
    - `KEY_UPDATE` and `END_SESSION`.
- Events
    - `GET_SUPPORTED_EVENT_TYPES`, `SUBSCRIBE_EVENT_TYPES`, and `SEND_EVENT`.
- Endpoint Information
    - `GET_ENDPOINT_INFO`.

For libspdm, each type of encapsulated flow introduces requirements to support flexible handling of
the flow by the Integrator. Such requirements include the ability for a Responder to reject a
Requester during mutual authentication, determining which events to subscribe to, and input
parameters when calling `GET_ENDPOINT_INFO`. This document describes these decision points, forms
requirements around them, and outlines an API pattern to support them.

## Encapsulated Flow Initiation

The encapsulated flow can be explicitly initiated by the Responder via mutual authentication. In
this document this is termed as being Responder-initiated. The Requester-initiated encapsulated flow
begins with the Requester sending `GET_ENCAPSULATED_REQUEST` to the Responder outside of mutual
authentication. Reasons for the Requester to initiate the encapsulated flow include periodicity, or
the Responder may possess an out-of-band (non-SPDM) mechanism to the Requester.

## Encapsulated Flow Independence

It shall be possible, where applicable, for the Integrator to specify an individual secure session
for the encapsulated flow or have it outside of a secure session. For libspdm this translates to
having an encapsulated context for each secure session and the non-session context. In addition,
libspdm should support arbitrary and interleaved encapsulated messages between secure sessions and
outside of a secure session. For example, libspdm should be able to accommodate the sequence
1. `GET_ENCAPSULATED_REQUEST` / `ENCAPSULATED_REQUEST` in `Session1`.
2. `GET_ENCAPSULATED_REQUEST` / `ENCAPSULATED_REQUEST` in `Session2`.
3. `DELIVER_ENCAPSULATED_RESPONSE` / `ENCAPSULATED_RESPONSE_ACK` in `Session1`.
4. `DELIVER_ENCAPSULATED_RESPONSE` / `ENCAPSULATED_RESPONSE_ACK` in `Session2`.

## Control and Decision Points

### Mutual Authentication

Integrator may
- Evaluate the `CHALLENGE.Context` or `KEY_EXCHANGE.OpaqueData` fields to determine whether to
  proceed with mutual authentication.
- Specify whether to issue `GET_DIGESTS` and/or `GET_CERTIFICATE` or not.
- Specify the Requester's certificate slot.
    - For session-based mutual authentication the certificate slot is specified either in
      `KEY_EXCHANGE_RSP` or `ENCAPSULATED_RESPONSE_ACK`.
- Evaluate `CHALLENGE.OpaqueData` or `FINISH.OpaqueData` to determine whether or not to accept
  authentication of the Requester.

### Secure Session Management

For `KEY_UPDATE` Integrator may specify `UpdateKey` or `UpdateAllKeys`. Presumably libspdm would
automatically follow that up with `VerifyNewKey`.

For `END_SESSION` there is nothing for the Integrator to specify, as the Negotiated State Clearing
Indicator does not apply to the Requester as it does not have `CACHE_CAP`.

### Events

After the encapsulated `SUPPORTED_EVENT_TYPES` response is received, the Integrator may examine the
`SupportedEventGroupsList` to determine which events to subscribe to, if at all. If they do wish
to subscribe to events then they can specify the events in `SubscribeList`. At any appropriate time
the Integrator may unsubscribe from all events.

### Endpoint Information

Integrator may specify `SubCode`, `SlotID`, or `SignatureRequested`.

## Message Enforcement

Encapsulated requests are limited by message type and connection or session state. These limits are
enforced by both the Requester and Responder.

### Basic Mutual Authentication

If the Responder signals for mutual authentication in its `CHALLENGE_AUTH` response then the next
request from the Requester must be `GET_ENCAPSULATED_REQUEST`. After that the encapsulated requests
from the Responder are limited to `GET_DIGESTS`, `GET_CERTIFICATE`, and `CHALLENGE`. The Responder
can terminate the flow by clearing `ENCAPSULATED_RESPONSE_ACK.Param2` or sending an `ERROR`
response. Once the encapsulated `CHALLENGE_AUTH` response is returned to the Responder, then it
must terminate the encapsulated flow by clearing `ENCAPSULATED_RESPONSE_ACK.Param2`.

### Session-based Mutual Authentication

If the Responder signals for mutual authentication in its `KEY_EXCHANGE_RSP` then the next request
from the Requester depends on the value of `MutAuthRequested`. If
- Bit 0 is set then the next request must be `FINISH` and there is no encapsulated flow.
- Bit 1 is set then the next request must be `GET_ENCAPSULATED_REQUEST`.
- Bit 2 is set then the next request must be `DELIVER_ENCAPSULATED_RESPONSE` with
  `EncapsulatedResponse` delivering the Requester's `DIGESTS` response.

Within the encapsulated flow the encapsulated requests are limited to `GET_DIGESTS` and
`GET_CERTIFICATE`. The Responder can terminate the flow by clearing
`ENCAPSULATED_RESPONSE_ACK.Param2` or sending an `ERROR` response.

### Requester-initiated Encapsulated Flow

The Requester-initiated encapsulated flow begins with the Requester sending
`GET_ENCAPSULATED_REQUEST`. If outside of a session then the following encapsulated requests are
legal.
- `GET_CERTIFICATE`
- `GET_DIGESTS`
- `GET_ENDPOINT_INFO`

Within a session the above encapsulated requests are all legal, with the addition of the following
encapsulated requests.
- `GET_SUPPORTED_EVENT_TYPES`
- `SUBSCRIBE_EVENT_TYPES`
- `SEND_EVENT`
- `KEY_UPDATE`
- `END_SESSION`

The Responder can terminate the flow by clearing `ENCAPSULATED_RESPONSE_ACK.Param2` or sending an
`ERROR` response.

## Basic Design and State Management

For encapsulated requests that originate from the Integrator the basic flow is
1. If possible, Integrator signals to the Requester that it should send `GET_ENCAPSULATED_REQUEST`,
   possibly for a specific session or outside of a session.
2. libspdm waits for the Requester to send `GET_ENCAPSULATED_REQUEST` in the appropriate channel.
3. libspdm calls into the encapsulated state management handler. The handler specifies the request
   message and its parameters.
    - The handler is implemented by the Integrator.
4. libspdm sends `ENCAPSULATED_REQUEST` and processes `DELIVER_ENCAPSULATED_RESPONSE`.
5. Control returns to the handler where the Integrator either terminates the encapsulated flow or
   specifies a new request message to be sent to the Requester.
    - This continues until the encapsulated flow is terminated by the Integrator.

Example encapsulated state management handler:
```C
/* libspdm receives a GET_ENCAPSULATED_REQUEST or DELIVER_ENCAPSULATED_RESPONSE message and calls
 * into libspdm_encap_state_handler. */

libspdm_return_t libspdm_encap_state_handler (void *spdm_context,
                                              uint32_t *session_id,
                                              libspdm_encap_flow_type_t encap_flow_type, ...)
{
    /* Integrator can use a pointer in libspdm_session_info or non-session spdm_context to access
     * Integrator-defined state related to the encapsulated flow. */

    switch (state) {
    case a:
    /* Get digests. Information can be retrieved via LIBSPDM_DATA_PEER_* and libspdm_get_data. */
    return libspdm_encap_get_digest(..., session_id);

    case b:
    /* Get certificate chain from certificate slot 5. */
    return libspdm_encap_get_certificate(..., session_id, 5);

    case c:
    /* Get endpoint information using certificate slot 5. */
    return libspdm_encap_get_endpoint_info(..., session_id, ..., 5, ...);

    case d:
    /* Terminate encapsulated flow. */
    return libspdm_encap_terminate_flow(..., session_id);
    }
}
```

### Multiple Message Handling

When multiple encapsulated `GET_CERTIFICATE` requests are issued to retrieve a single certificate
chain, then libspdm handles the multiple `ENCAPSULATED_RESPONSE` and `DELIVER_ENCAPSULATED_RESPONSE`
messages. Once the entire certificate chain has been retrieved then libspdm calls
`libspdm_encap_state_handler`.
