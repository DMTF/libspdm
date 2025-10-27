# Encapsulated Flows and API Patterns for Responder

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
- Evaluate `CHALLENGE.OpaqueData` or `FINISH.OpaqueData` to determine whether or not to accept
  authentication of the Requester.

### Secure Session Management

For `KEY_UPDATE` Integrator may specify `UpdateKey` or `UpdateAllKeys`. Presumably libspdm would
automatically follow that up with `VerifyNewKey`.

For `END_SESSION` there is nothing for the Integrator to specify, as the Negotiated State Clearing
Indicator does not apply the Requester as it does not have `CACHE_CAP`.

### Events

After the encapsulated `SUPPORTED_EVENT_TYPES` response is received, the Integrator may examine the
`SupportedEventGroupsList` to determine which events to subscribe to, if at all. If they do wish
to subscribe to events then they can specify the events in `SubscribeList`. At any appropriate time
the Integrator may unsubscribe from all events.

### Endpoint Information

Integrator may specify `SubCode`, `SlotID`, or `SignatureRequested`.

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
/* libspdm receives a GET_ENCAPSULATED_REQUEST message and calls into libspdm_encap_state_handler */

libspdm_return_t libspdm_encap_state_handler (void *spdm_context, uint32_t *session_id, ...)
{
    /* Integrator can use a pointer in libspdm_session_info or larger spdm_context to access
     * Integrator-defined state related to the encapsulated flow. */

    switch (state) {
    case a:
    /* Generate encapsulated request. */
    return libspdm_encap_get_digest(..., session_id, &slot_mask, digest_buffer);

    case b:
    /* Get certificate chain from certificate slot 5. */
    return libspdm_encap_get_certificate(..., session_id, 5, &cert_chain_size, cert_chain_buffer);

    case c:
    /* Get endpoint information using certificate slot 5. */
    return libspdm_encap_get_endpoint_info(..., session_id, ..., 5, ...);

    case d:
    /* Terminate encapsulated flow. */
    return libspdm_encap_terminate_flow(..., session_id);
    }
}
```
