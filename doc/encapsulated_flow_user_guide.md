# User Guide for the Responder Encapsulated Flow

The SPDM 1.1 specification introduced encapsulated requests so that a Responder can send SPDM
request messages to the Requester. Originally the messages were limited to mutual authentication and
secure session management, but in subsequent SPDM releases the number and type of encapsulated
messages increased. Starting with libspdm 4.0, the library introduced a new architecture that allows
the Responder Integrator more flexibility when dealing with the different encapsulated flows.

## Prerequisites

The Responder Integrator must set `LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP` at build time, and set
`ENCAP_CAP` at run time. In addition, the Requester must also set `ENCAP_CAP`. Where signatures
are present in Requester-signed messages, the Responder must select a value of `ReqBaseAsymAlg`
(or `ReqPqcAsymAlg`) that it can verify.

## Encapsulated Flow Types

libspdm classifies encapsulated flows into three types:
- Basic Mutual Authentication
    - Triggered by the Responder through its `CHALLENGE_AUTH` response to the Requester.
- Session-based Mutual Authentication
    - Triggered by the Responder through its `KEY_EXCHANGE_RSP` response to the Requester.
- Requester-initiated
    - Triggered by the Requester when it sends the `GET_ENCAPSULATED_REQUEST` message to the
      Responder.
    - The Requester may send this message periodically, or the Responder may possess an out-of-band
      (non-SPDM) method of signaling to the Requester to start this encapsulated flow.

## Encapsulated Flow Handler

The encapsulated flow handler has the following API declaration:
```C
typedef libspdm_return_t (*libspdm_encap_flow_handler_func)(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request);
```
The Integrator must implement this handler, and register it with libspdm via the
`libspdm_register_encap_flow_handler()` function. The handler is called by libspdm during the
encapsulated flow to provide the Integrator with information about the state of the encapsulated
flow. In addition, it allows the Integrator to send appropriate encapsulated request messages to the
Requester. Detailed information about the handler can be found in the [Responder API document](https://github.com/DMTF/libspdm/blob/main/doc/api/responder_api.md#libspdm_encap_flow_handler_func).

The handler needs no state of its own in the common case. `last_request_code` identifies where
the flow is, so a `switch` on it is usually sufficient, as in each of the examples below. The
Integrator only needs to track its own state when it issues the same request code more than
once within a flow, such as retrieving certificate chains from several slots.

### Buffer Allocation and Ownership

Some encapsulated requests take a buffer from the Integrator rather than allocating one, and libspdm
writes the Requester's payload into it. `libspdm_get_encap_request_get_certificate()` and
`libspdm_get_encap_request_get_endpoint_info()` both do this, and in each case the buffer must
remain valid after the handler returns. This is why the examples below give these buffers static
storage duration rather than placing them on the stack.

The certificate chain is the demanding case. libspdm retains the pointer and copies each
`CERTIFICATE` response into it as the chain arrives, issuing as many encapsulated `GET_CERTIFICATE`
requests as the chain requires without calling the handler in between. Once the entire chain has
been retrieved libspdm calls the handler with `last_request_code` equal to `SPDM_GET_CERTIFICATE`,
at which point the Integrator can read the chain.

Whichever request was issued, the size of the payload that arrived is obtained with
`libspdm_get_encap_payload_size()`. Only one encapsulated request is outstanding at a time, so that
one function reports the size of whichever payload the handler is currently being called for.

### Encapsulated Errors

If the Requester cannot fulfil an encapsulated request it returns an encapsulated `ERROR` message.
libspdm calls the handler with `error_code` set to that `ErrorCode`, so that the Integrator learns
why the flow ended, and then terminates the flow by clearing `ENCAPSULATED_RESPONSE_ACK.Param2`. The
handler must acknowledge this by setting the value of `terminate_flow` to `true`; it cannot continue
the flow. The value of `error_code` is `0` on every other call.

`ErrorCode == ResponseNotReady` is the one value that does not mean the operation has failed. The
Requester is asking for more time rather than declining the request, and the encapsulated request
remains outstanding. libspdm retains it and, when the Requester next sends
`GET_ENCAPSULATED_REQUEST`, reissues it as an encapsulated `RESPOND_IF_READY` request without
calling the handler. The flow therefore resumes where it left off and can still complete. An
Integrator that releases per-flow state when a flow ends should keep that state for this
`ErrorCode`, since the flow it belongs to is going to continue.

This resumption requires `LIBSPDM_RESPOND_IF_READY_SUPPORT`. When that macro is `0` libspdm does not
retain the outstanding request, and `ResponseNotReady` ends the flow like any other `ErrorCode`.

## Encapsulated Flows

### Basic Mutual Authentication

As part of `CHALLENGE` request processing, libspdm calls `libspdm_challenge_start_mut_auth()` to
query the Integrator on whether to pursue basic mutual authentication. If this function returns
`true` then the basic mutual authentication flow begins, during which the Integrator can send the
encapsulated `GET_DIGESTS`, `GET_CERTIFICATE`, and `CHALLENGE` requests to the Requester.

```C
libspdm_return_t encap_flow_handler(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request)
{
    /* libspdm retains this buffer after the handler returns, so it cannot be on the stack.
     * See Buffer Ownership above. */
    static uint8_t cert_chain[0x1000];

    LIBSPDM_ASSERT(session_id == NULL);
    LIBSPDM_ASSERT(encap_flow_type == LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);

    if (error_code != 0) {
        /* The Requester returned an encapsulated ERROR, whose ErrorCode is in error_code, so this
         * flow ends here. */
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }

    switch (last_request_code) {
    case 0:
        /* Get digests. Information can be retrieved via LIBSPDM_DATA_PEER_* and
         * libspdm_get_data. */
        return libspdm_get_encap_request_get_digests(spdm_context, session_id,
                                                     encap_request_size, encap_request);
    case SPDM_GET_DIGESTS:
        /* Retrieve certificate chain from slot 5. */
        return libspdm_get_encap_request_get_certificate(spdm_context, session_id, 5,
                                                         sizeof(cert_chain), cert_chain,
                                                         encap_request_size, encap_request);
    case SPDM_GET_CERTIFICATE:
        /* Send CHALLENGE request to Requester using certificate chain slot 5. libspdm terminates
         * the flow itself once the Requester delivers CHALLENGE_AUTH, so this handler is not
         * called again. */
        return libspdm_get_encap_request_challenge(spdm_context, 5, NULL,
                                                   encap_request_size, encap_request);
    default:
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }
}
```

### Session-based Mutual Authentication

As part of `KEY_EXCHANGE` request processing, libspdm calls `libspdm_key_exchange_start_mut_auth()`
to query the Integrator on whether to pursue session-based mutual authentication. If this function
returns a non-zero value then the session-based mutual authentication flow begins.

If `SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED` is returned by the Integrator then no
encapsulated messages are exchanged between the Requester and Responder. This value is required if
the Requester has set its `PUB_KEY_ID_CAP`. The Integrator may also select this value if it already
is in possession of the Requester's certificate chain and does not need to issue an encapsulated
`GET_CERTIFICATE` request to the Requester.

If `SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST` is returned by the Integrator
then the encapsulated flow is initiated and the Integrator can send encapsulated `GET_DIGESTS` and
`GET_CERTIFICATE` requests to the Requester.

If `SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS` is returned by the Integrator
then the encapsulated flow is initiated with an implicit `GET_DIGESTS` request sent to the
Requester.

```C
libspdm_return_t encap_flow_handler(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request)
{
    /* libspdm retains this buffer after the handler returns, so it cannot be on the stack.
     * See Buffer Ownership above. */
    static uint8_t cert_chain[0x1000];

    LIBSPDM_ASSERT(session_id != NULL);
    LIBSPDM_ASSERT(encap_flow_type == LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);

    if (error_code != 0) {
        /* The Requester returned an encapsulated ERROR, whose ErrorCode is in error_code, so this
         * flow ends here. Unless the ErrorCode is ResponseNotReady, in which case libspdm resumes
         * the flow, the Requester's certificate slot is never designated and the session does not
         * complete mutual authentication. */
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }

    /* Here last_request_code also distinguishes the two encapsulated variants: the
     * WITH_ENCAP_REQUEST flow starts with a value of 0, whereas the WITH_GET_DIGESTS flow starts
     * with SPDM_GET_DIGESTS, since libspdm issued that request implicitly. */
    switch (last_request_code) {
    case 0:
        /* Get digests. Information can be retrieved via LIBSPDM_DATA_PEER_* and
         * libspdm_get_data. */
        return libspdm_get_encap_request_get_digests(spdm_context, session_id,
                                                     encap_request_size, encap_request);
    case SPDM_GET_DIGESTS:
        /* Retrieve certificate chain from slot 5. */
        return libspdm_get_encap_request_get_certificate(spdm_context, session_id, 5,
                                                         sizeof(cert_chain), cert_chain,
                                                         encap_request_size, encap_request);
    case SPDM_GET_CERTIFICATE: {
        /* The certificate chain has been retrieved, so designate the slot that the Requester
         * must sign FINISH with. KEY_EXCHANGE_RSP.SlotIDParam could not convey it, so libspdm
         * sends it in the final ENCAPSULATED_RESPONSE_ACK. */
        libspdm_data_parameter_t parameter;
        uint8_t slot_id = 5;

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
        libspdm_write_uint32(parameter.additional_data, *session_id);

        libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID, &parameter,
                         &slot_id, sizeof(slot_id));
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }
    default:
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }
}
```

Note that `session_id` is never `NULL` in this flow. When both endpoints have set
`HANDSHAKE_IN_THE_CLEAR_CAP` the encapsulated messages are exchanged outside of a session, but
libspdm still passes the session identifier that the flow belongs to.

### Requester-initiated

This flow begins when the Requester sends `GET_ENCAPSULATED_REQUEST` without the Responder
triggering it via an SPDM response message. If the `GET_ENCAPSULATED_REQUEST` is outside of a
session then the following encapsulated requests are legal:
- `GET_DIGESTS`
- `GET_CERTIFICATE`
- `GET_ENDPOINT_INFO`
    - SPDM 1.3+

Within a session the above encapsulated requests are all legal, with the addition of the following
encapsulated requests:
- `SEND_EVENT`
    - SPDM 1.3+
- `KEY_UPDATE`

```C
libspdm_return_t encap_flow_handler(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request)
{
    /* libspdm retains these buffers after the handler returns, so they cannot be on the stack.
     * See Buffer Ownership above. */
    static uint8_t cert_chain[0x1000];
    static uint8_t ep_info[0x100];

    LIBSPDM_ASSERT(encap_flow_type == LIBSPDM_ENCAP_FLOW_REQ_INITIATED);

    if (error_code != 0) {
        /* The Requester returned an encapsulated ERROR, whose ErrorCode is in error_code, so this
         * flow ends here. */
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }

    switch (last_request_code) {
    case 0:
        /* The Requester sent GET_ENCAPSULATED_REQUEST, so the flow is beginning. */
        return libspdm_get_encap_request_get_digests(spdm_context, session_id,
                                                     encap_request_size, encap_request);
    case SPDM_GET_DIGESTS:
        /* Retrieve the certificate chain in slot 5. libspdm issues as many encapsulated
         * GET_CERTIFICATE requests as the chain requires, and calls this handler again only once
         * the entire chain has been retrieved. */
        return libspdm_get_encap_request_get_certificate(spdm_context, session_id, 5,
                                                         sizeof(cert_chain), cert_chain,
                                                         encap_request_size, encap_request);
    case SPDM_GET_CERTIFICATE: {
        size_t cert_chain_size;

        /* cert_chain now holds the Requester's certificate chain. Its size is not known until the
         * final CERTIFICATE response has been processed, so it is retrieved here. */
        if (libspdm_get_encap_payload_size(spdm_context, session_id, &cert_chain_size) !=
            LIBSPDM_STATUS_SUCCESS) {
            *terminate_flow = true;

            return LIBSPDM_STATUS_SUCCESS;
        }

        return libspdm_get_encap_request_get_endpoint_info(
            spdm_context, session_id,
            SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
            5,
            SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
            sizeof(ep_info), ep_info,
            encap_request_size, encap_request);
    }
    case SPDM_GET_ENDPOINT_INFO: {
        size_t ep_info_size;

        /* ep_info now holds the Requester's endpoint information, and the same function that
         * reported the size of the certificate chain reports its size. */
        if (libspdm_get_encap_payload_size(spdm_context, session_id, &ep_info_size) !=
            LIBSPDM_STATUS_SUCCESS) {
            *terminate_flow = true;

            return LIBSPDM_STATUS_SUCCESS;
        }

        if (session_id == NULL) {
            /* The remaining requests are only legal within a session, so the flow ends here. */
            *terminate_flow = true;

            return LIBSPDM_STATUS_SUCCESS;
        }

        /* libspdm_get_encap_request_send_event() would be issued the same way. Note that these
         * functions take the session identifier by value, as they have no meaning outside of a
         * session. */
        return libspdm_get_encap_request_key_update(spdm_context, *session_id,
                                                    SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY,
                                                    encap_request_size, encap_request);
    }
    case SPDM_KEY_UPDATE:
        /* libspdm issued the VerifyNewKey request itself, so both keys are now in use. */
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    default:
        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    }
}
```

If the Integrator produces a request that is not legal for this flow, such as `KEY_UPDATE` outside
of a session, libspdm does not send it to the Requester and terminates the flow with `Unspecified`.
