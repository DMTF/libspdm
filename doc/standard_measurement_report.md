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

There are 2 types of Standard Measurement Report. A verifier shall support All-Measurements Report
and may support One-by-One-Measurements Report.

## Standard All-Measurements Report Definition

The standard all-measurements report is a byte buffer that consists of the L1/L2 transcript along with
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

### Rationale

#### Single Request and Response

Capturing all measurements in a single response provides an atomic snapshot of the state of the
Responder at a specific point in time. As such, a Verifier need not have to reason about the state
of the Responder through multiple measurement requests and responses with a possibly unknown amount
of time between each message.

#### Byte Buffer

A raw byte buffer allows the Verifier to verify the signature, if supported by the Responder, over
the rest of the measurement report without any transformation of data.

#### `RawBitStreamRequested`

In the interest of message size, `RawBitStreamRequested` is not set, indicating preference, when
given the opportunity, for hashed measurements instead of raw measurements. In particular, certain
raw measurements may only be examined for the purpose of debugging, whereas the hashed measurements
are evaluated by the Verifier while the Responder is in production.

#### `NewMeasurementRequested`

Presumably the Verifier evaluates the current state of the Responder and not its future state. As
such `NewMeasurementRequested` is not set.

## Standard One-by-One-Measurements Report Definition

The standard one-by-one-measurements report is a byte buffer that consists of the L1/L2 transcript along with
the signature over the transcript if the Responder supports signing. It is comprised of multiple
`GET_MEASUREMENTS` requests and multiple `MEASUREMENTS` responses.

For SPDM 1.0 and 1.1, the byte buffer is {`GET_MEASUREMENTS`(0), `MEASUREMENTS`(0),
`GET_MEASUREMENTS`(1), `MEASUREMENTS`(1), ..., `GET_MEASUREMENTS`(n), `MEASUREMENTS`(n)}.
For SPDM 1.2 and later, the byte buffer is {`VCA`, `GET_MEASUREMENTS`(0), `MEASUREMENTS`(0),
`GET_MEASUREMENTS`(1), `MEASUREMENTS`(1), ..., `GET_MEASUREMENTS`(n), `MEASUREMENTS`(n)}.

The `GET_MEASUREMENTS`(0) request has the following properties:
* `Param2 = 0x00`
    * Total number of measurement blocks is requested.
    * Assuming that the Responder returns `n` measurement blocks in `MEASUREMENTS`(0).
* `SignatureRequested` is not set.
* For SPDM 1.2 and later, `RawBitStreamRequested` is not set.
* For SPDM 1.3 and later, `NewMeasurementRequested` is not set.

The `GET_MEASUREMENTS`(1) to `GET_MEASUREMENTS`(n) request has the following properties:
* `Param2`
    * The requested measurement index. It must be between 0x1 and 0xFE, inclusive and incremental.
    * Only successful `GET_MEASUREMENTS`(x) and `MEASUREMENTS`(x) are recorded in the measurement report.
* `SignatureRequested`
    * For `GET_MEASUREMENTS`(1), ..., and `GET_MEASUREMENTS`(n-1), it is not set.
    * For `GET_MEASUREMENTS`(n), if the Responder supports signature generation (`MEAS_CAP = 10b`)
      then it is set, else it is not set.
    * For SPDM 1.2 and later, if the requester detected the signed `MEASUREMENT`(n)
      `content change` field is `01b`(changed), the requester should discard this measurement report
      and recollect from the beginning.
* For SPDM 1.2 and later, `RawBitStreamRequested` is not set.
* For SPDM 1.3 and later, `NewMeasurementRequested` is not set.

### Rationale

#### One-by-One Request and Response

The requester shall collect All-Measurements Report at first. Only if the device cannot return
all measurements at one time due to some errors (such as transport layer limitation),
then the requester can try to collect One-by-One-Measurements Report.

#### Detecting Measurement Report format

The verifier may check the first `GET_MEASUREMENTS` in the Measurement Report.
* If the `Param2` is `0xFF`(All Measurements), then it is All-Measurements Report.
  The whole Measurement report should include only one `GET_MEASUREMENTS`/`MEASUREMENTS` pair.
* If the `Param2` is `0x00`(Total Number), then it is One-by-One-Measurements Report.
  The whole Measurement report should include only `n`+1 `GET_MEASUREMENTS`/`MEASUREMENTS` pairs.

#### Non-Sequentially Increased Measurement Index

The `Param2`(measurement index) in `GET_MEASUREMENTS`(1) to `GET_MEASUREMENTS`(n) is
non-sequentially incremental.
A device may implement non-sequentially increased measurement index.
For example, a device has 3 measurement blocks. The index is 1, 4 and 6.
Then the `Param2` of `GET_MEASUREMENTS`(1) is 1, the `Param2` of `GET_MEASUREMENTS`(2) is 4,
and the `Param2` of `GET_MEASUREMENTS`(3) is 6.
The requester may send a `GET_MEASUREMENTS` with `Param2` 2, but it will get `ERROR` response.
As such, the `GET_MEASUREMENTS` with `Param2` 2 and `ERROR` response are NOT included
in the measurement report.
Once the successfully received number of measurement block is `n`-1, the requester should send
the next `GET_MEASUREMENTS` with `SignatureRequested` set.

#### Completeness

The requester shall request the total number of measurement block (`n`) first,
then request all `n` measurement blocks one by one incrementally.

#### Atomicity

The requester shall verify the `content change` and recollect One-by-One-Measurements report
in case that the `MeasurementRecord` fields of previous `MEASUREMENTS` responses are changed.

#### Integrity

The requester shall request a digital signature in the last message `GET_MEASUREMENTS`(n)
for the whole measurement report, if supported by the Responder.

