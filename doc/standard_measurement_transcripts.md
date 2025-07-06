# DMTF SPDM Standard Measurement Transcripts

This document describes two standard measurement transcripts for an SPDM Responder that are
constructed by an SPDM Requester and consumed by a Verifier while all agents are operating in
production mode. A specification for, or an implementation of, a Verifier or Requester can specify
and publish support for these transcripts.

## Common Properties

A standard measurement transcript is a byte buffer that consists of the L1/L2 transcript along with
a signature over the transcript if the Responder supports measurement signing. All
`GET_MEASUREMENT` requests have the following properties:
* For SPDM 1.2 and later, `RawBitStreamRequested` is not set.
* For SPDM 1.3 and later, `NewMeasurementRequested` is not set.

## Single-request Measurement Transcript Definition

The single-request measurement transcript is comprised of a single `GET_MEASUREMENTS` request and a
single `MEASUREMENTS` response. All measurement blocks are present in the `MEASUREMENTS` response.

For SPDM 1.0 and 1.1, the byte buffer is
```
{GET_MEASUREMENTS, MEASUREMENTS}
```

For SPDM 1.2 and later, the byte buffer is
```
{VCA, GET_MEASUREMENTS, MEASUREMENTS}
```

The `GET_MEASUREMENTS` request has the following properties:
* If the Responder supports signature generation (`MEAS_CAP = 10b`) then `SignatureRequested` is
  set, else it is not set.
* `Param2 = 0xFF`

## Multiple-request Measurement Transcript Definition

The multiple-request measurement transcript is comprised of multiple `GET_MEASUREMENTS` requests and
multiple `MEASUREMENTS` responses. Apart from `MEASUREMENTS(0)`, a single and unique measurement
block is present in each `MEASUREMENTS` response.

For SPDM 1.0 and 1.1, the byte buffer is
```
{GET_MEASUREMENTS(0), MEASUREMENTS(0), GET_MEASUREMENTS(1), MEASUREMENTS(1), ..., GET_MEASUREMENTS(N), MEASUREMENTS(N)}
```

For SPDM 1.2 and later, the byte buffer is
```
{VCA, GET_MEASUREMENTS(0), MEASUREMENTS(0), GET_MEASUREMENTS(1), MEASUREMENTS(1), ..., GET_MEASUREMENTS(N), MEASUREMENTS(N)}
```

The `GET_MEASUREMENTS(0)` request has the following properties:
* `SignatureRequested` is not set.
* `Param2 = 0x00`

The value of `N` is equal to the value of `MEASUREMENTS(0).Param1`.

The `GET_MEASUREMENTS(1)` to `GET_MEASUREMENTS(N - 1)` requests have the following properties:
* `SignatureRequested` is not set.
* `Param2` starts with a value of `0x01` and its value increments by `1` with each successive
  `GET_MEASUREMENTS` request. This is repeated until the number of `MEASUREMENT` responses in this
  step is equal to `N - 1`. The last measurement index of this step is denoted as `I`.

The `GET_MEASUREMENTS(N)` request has the following properties:
* If the Responder supports signature generation (`MEAS_CAP = 10b`) then `SignatureRequested` is
  set, else it is not set.
* `Param2` starts with a value of `I + 1` and its value increments by `1` until `MEASUREMENT(N)`
  is returned.
