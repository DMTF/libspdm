/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_MEASLIB_H
#define RESPONDER_MEASLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/**
 * Collect the device measurement.
 *
 * libspdm will call this function to retrieve the measurements for a device.
 * The "measurement_index" parameter indicates the measurement requested.
 *
 * On success, measurements_count must not be 0, and for a single measurement index it must be 1
 * with a non-zero measurements_size, because libspdm asserts these. content_changed must always be
 * set. libspdm has not validated slot_id_param when it calls this function.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicates the session in which the request was received.
 *                       If NULL then the request was not received in a session.
 * @param  spdm_version  Indicates the negotiated SPDM version.
 *
 * @param  measurement_specification  Indicates the measurement specification.
 * Must be an SPDM_MEASUREMENT_SPECIFICATION_* value in spdm.h.
 *
 * @param  measurement_hash_algo  Indicates the measurement hash algorithm.
 * Must be SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_* value in spdm.h.
 *
 * @param  measurement_index  The index of the measurement to collect.
 * A value of 0x00 requests only the total number of measurements to be returned in
 * "measurements_count". The parameters "measurements" and "measurements_size" will be left
 * unmodified.
 *
 * A value of [0x01 - 0xFE] requests a single measurement for that measurement index
 * be returned. On success, "measurements_count" will be set to 1 and the
 * "measurements" and "measurements_size" fields will be set based
 * on the single measurement. An invalid measurement index will cause
 * "measurements_count" to return 0.
 *
 * A value of 0xFF requests all measurements be returned.
 * On success, "measurements_count", "measurements", and "measurements_size"
 * fields will be set with data from all measurements.
 *
 * @param request_attribute A bitmask whose fields are SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_*.
 *
 * @param  requester_nonce  If not NULL, a pointer to the requester nonce (32 bytes) from the
 *                          GET_MEASUREMENTS request. It is present when the GENERATE_SIGNATURE
 *                          attribute is set, otherwise it is NULL.
 *
 * @param  slot_id_param  The slot ID from the GET_MEASUREMENTS request (BIT[0:3]).
 *                        It is valid when the GENERATE_SIGNATURE attribute is set, otherwise it is 0.
 *
 * @param  request_context_size  The size, in bytes, of request_context.
 * @param  request_context       If spdm_version is greater than 1.2, then it is a pointer to the
 *                               Context field in the request message, else it is NULL and ignore
 *
 * @param  content_changed
 * The content change field of the MEASUREMENTS response, which is one of the
 * SPDM_MEASUREMENTS_RESPONSE_CONTENT_* values. libspdm uses it for SPDM 1.2 and later when the
 * response is signed.
 *
 * @param  measurements_count
 * When "measurement_index" is zero, returns the total count of
 * measurements available for the device. None of the actual measurements are
 * returned however, and "measurements" and "measurements_size" are unmodified.
 *
 * When "measurement_index" is non-zero, returns the number of measurements
 * returned in "measurements" and "measurements_size". If "measurement_index"
 * is an invalid index not supported by the device, "measurements_count" will
 * return 0 and the function will return LIBSPDM_STATUS_MEAS_INVALID_INDEX.
 *
 * @param  measurements
 * A pointer to a destination buffer to store the concatenation of all device
 * measurement blocks. This buffer will only be modified if "measurement_index" is non-zero.
 *
 * @param  measurements_size
 * On input, indicates the size in bytes of the destination buffer.
 * On output, indicates the total size in bytes of all device measurement
 * blocks in the buffer. This field should only be modified if "measurement_index" is non-zero.
 * The maximum size is SPDM_MAX_MEASUREMENT_RECORD_LENGTH (2^24 - 1 bytes).
 *
 * @retval LIBSPDM_STATUS_SUCCESS             The measurements were collected.
 * @retval LIBSPDM_STATUS_MEAS_INVALID_INDEX  measurement_index is not supported. libspdm sends
 *                                            ERROR(InvalidRequest).
 * @retval Others                             libspdm sends ERROR(Unspecified).
 **/
extern libspdm_return_t libspdm_measurement_collection(
    void *spdm_context,
    const uint32_t *session_id,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    const uint8_t *requester_nonce,
    uint8_t slot_id_param,
    size_t request_context_size,
    const void *request_context,
    uint8_t *content_changed,
    uint8_t *measurements_count,
    void *measurements,
    size_t *measurements_size);

/**
 * This functions returns the opaque data in a MEASUREMENTS response.
 *
 * It is called immediately after libspdm_measurement_collection() is called and allows the opaque
 * data field to vary based on the GET_MEASUREMENTS request.
 *
 * When SPDM 1.2 or later is negotiated, libspdm calls this function only if an OpaqueDataFmt was
 * selected, and the opaque data must use that format, which LIBSPDM_DATA_OTHER_PARAMS_SUPPORT
 * gives. The opaque data should not be larger than SPDM_MAX_OPAQUE_DATA_SIZE. If false is returned
 * then libspdm sends ERROR(Unspecified), so to send no opaque data, return true and set
 * opaque_data_size to 0.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicates the session in which the request was received.
 *                       If NULL then the request was not received in a session.
 * @param  spdm_version  Indicates the negotiated SPDM version.
 *
 * @param  measurement_specification  Indicates the measurement specification.
 * Must be an SPDM_MEASUREMENT_SPECIFICATION_* value in spdm.h.
 *
 * @param  measurement_hash_algo  Indicates the measurement hash algorithm.
 * Must be SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_* value in spdm.h.
 *
 * @param  measurement_index  The index of the measurement to collect.
 *
 * @param request_attribute A bitmask whose fields are SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_*.
 *
 * @param  request_context_size  The size, in bytes, of request_context.
 * @param  request_context       If spdm_version is greater than 1.2, then it is a pointer to the
 *                               Context field in the request message, else it is NULL and ignore
 *
 * @param opaque_data
 * A pointer to a destination buffer whose size, in bytes, is opaque_data_size. The opaque data is
 * copied to this buffer.
 *
 * @param opaque_data_size
 * On input, indicates the size, in bytes, of the destination buffer.
 * On output, indicates the size of the opaque data.
 *
 * @retval true   The opaque data was returned.
 * @retval false  The opaque data could not be returned.
 **/
extern bool libspdm_measurement_opaque_data(
    void *spdm_context,
    const uint32_t *session_id,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    size_t request_context_size,
    const void *request_context,
    void *opaque_data,
    size_t *opaque_data_size);

/**
 * This function calculates the measurement summary hash.
 *
 * The hash is the MeasurementSummaryHash field as DSP0274 defines it, and libspdm does not compute
 * any part of it. libspdm passes a pointer into the CHALLENGE_AUTH, KEY_EXCHANGE_RSP or
 * PSK_EXCHANGE_RSP response as measurement_summary_hash, so this function writes the field in
 * place.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  spdm_version               The SPDM version.
 * @param  base_hash_algo             The hash algo to use on summary.
 * @param  measurement_specification  Indicates the negotiated measurement specification.
 *                                    (SPDM_MEASUREMENT_SPECIFICATION_*)
 * @param  measurement_hash_algo      Indicates the measurement hash algorithm.
 *                                    (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
 *
 * @param  measurement_summary_hash_type  The type of the measurement summary hash. Either
 *                                        SPDM_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH or
 *                                        SPDM_REQUEST_ALL_MEASUREMENTS_HASH.
 * @param  measurement_summary_hash       The buffer to store the measurement summary hash.
 * @param  measurement_summary_hash_size  The size in bytes of the buffer.
 *
 * @retval true   Measurement summary hash is successfully generated.
 * @retval false  Error when generating the measurement summary hash.
 **/
extern bool libspdm_generate_measurement_summary_hash(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash,
    uint32_t measurement_summary_hash_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/**
 * Collect the measurement extension log.
 *
 * libspdm calls this function for each MEASUREMENT_EXTENSION_LOG request. *spdm_mel must remain
 * valid after this function returns, because libspdm copies from it afterwards. A Requester can
 * read the MEL with several requests, and new entries can be appended between them, but existing
 * bytes must not change. If true is returned with an spdm_mel_size of 0 then libspdm sends
 * ERROR(InvalidRequest), and if false is returned then it sends ERROR(OperationFailed).
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  session_id                 Indicates the session in which the request was received.
 *                                    If NULL then the request was not received in a session.
 * @param  mel_specification          Indicates the measurement extension log specification.
 * @param  measurement_specification  Indicates the negotiated measurement specification.
 *                                    (SPDM_MEASUREMENT_SPECIFICATION_*)
 * @param  measurement_hash_algo  Indicates the measurement hash algorithm.
 *                                Must be SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_* value in spdm.h.
 * @param  spdm_mel               Return the pointer of MEL.
 * @param  spdm_mel_size          Return the size of MEL.
 *
 * @retval true  measurement extension log is generated.
 * @retval false measurement extension log is not generated.
 **/
extern bool libspdm_measurement_extension_log_collection(
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t mel_specification,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    void **spdm_mel,
    size_t *spdm_mel_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */

#endif /* RESPONDER_MEASLIB_H */
