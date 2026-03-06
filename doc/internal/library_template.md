# Library Template

This document specifies naming schemes, patterns, and layouts for core library files in
https://github.com/DMTF/libspdm/tree/main/library.

## Library File Names

### Requester

File names for non-encapsulated messages take the form libspdm_req_*message_name*.c, where
`message_name` is the request message.

```
// File names for CHALLENGE and END_SESSION request messages.
spdm_requester/libspdm_req_challenge.c
spdm_requester/libspdm_req_end_session.c
```

File names for encapsulated messages take the form libspdm_req_encap_*message_name*.c where
`message_name` is the encapsulated response message.

```
// File names for encapsulated CHALLENGE_AUTH and CERTIFICATE response messages.
spdm_requester/libspdm_req_encap_challenge_auth.c
spdm_requester/libspdm_req_encap_certificate.c
```

### Responder

File names for non-encapsulated messages take the form libspdm_rsp_*message_name*.c, where
`message_name` is the response message.

```
// File names for CHALLENGE_AUTH and END_SESSION_ACK response messages.
spdm_responder/libspdm_rsp_challenge_auth.c
spdm_responder/libspdm_rsp_end_session_ack.c
```

File names for encapsulated messages take the form libspdm_rsp_encap_*message_name*.c where
`message_name` is the encapsulated request message.

```
// File names for encapsulated CHALLENGE and GET_CERTIFICATE request messages.
spdm_responder/libspdm_rsp_encap_challenge.c
spdm_responder/libspdm_rsp_encap_get_certificate.c
```
