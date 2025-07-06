# Standard Measurement Report

The SPDM specification grants the Requester flexibility when retrieving measurements from a
Responder via `GET_MEASUREMENTS`. This flexibility includes the presence or absence of a signature,
multiple `GET_MEASUREMENTS` requests to individual measurement indices, and the ability to indicate
whether the Requester desires the measurements to be encoded as a raw bitstream or a cryptographic
hash. However, it is possible for a Requester to construct measurement artifacts that are not easily
consumed by a Verifier, if at all. For example a Verifier may reject the evaluation of multiple
`GET_MEASUREMENTS` requests to the same Responder.

This document describes a standard measurement report for an SPDM Responder that is constructed by a
SPDM Requester and consumed by a Verifier while all agents are operating in production mode. In
particular, a production Verifier may only support a measurement report of this type and can point
to this document to advertise that restriction to other agents.

## Standard Measurement Report Definition

The standard measurement report is a byte buffer that consists of the L1/L2 transcript along with
the signature over the transcript if the Responder supports signing. It is comprised of a single
`GET_MEASUREMENTS` request and a single `MEASUREMENTS` response.

For SPDM 1.0 and 1.1, the byte buffer is {`GET_MEASUREMENTS`, `MEASUREMENTS`}. For SPDM 1.2 and
later, the byte buffer is {`VCA`, `GET_MEASUREMENTS`, `MEASUREMENTS`}. The `GET_MEASUREMENTS`
request has the following properties:
* `Param2 = 0xFF`
    * All measurement indices are requested.
* If the Responder supports signature generation (`MEAS_CAP = 10b`) then `SignatureRequested` is
  set, else it is not set.
* For SPDM 1.2 and later, `RawBitStreamRequested` is not set.
    * This is a hint to the Responder to hash measurements instead of producing their raw values.
* For SPDM 1.3 and later, `NewMeasurementRequested` is not set.
    * This requests the current state of the Responder and not its future state.

## Rationale

### Single Request and Response

Capturing all measurements in a single response provides an atomic snapshot of the state of the
Responder at a specific point in time. As such, a Verifier need not have to reason about the state
of the Responder through multiple measurement requests and responses with a possibly unknown amount
of time between each message.

### Byte Buffer

A raw byte buffer allows the Verifier to verify the signature, if supported by the Responder, over
the rest of the measurement report without any transformation of data.

### `RawBitStreamRequested`

In the interest of message size, `RawBitStreamRequested` is not set, indicating preference, when
given the opportunity, for hashed measurements instead of raw measurements. In particular, certain
raw measurements may only be examined for the purpose of debugging, whereas the hashed measurements
are evaluated by the Verifier while the Responder is in production.

### `NewMeasurementRequested`

Presumably the Verifier evaluates the current state of the Responder and not its future state. As
such `NewMeasurementRequested` is not set.
