#include "spdm_device_secret_lib_internal.h"
#include "crypto_stub_internal.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
libspdm_return_t libspdm_measurement_collection(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t mesurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *device_measurement_count,
    void *device_measurement,
    size_t *device_measurement_size)
{
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

bool libspdm_measurement_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_generate_measurement_summary_hash(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t  *measurement_summary_hash,
    uint32_t measurement_summary_hash_size)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/*Collect the measurement extension log.*/
bool libspdm_measurement_extension_log_collection(
    void *spdm_context,
    uint8_t mel_specification,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    void **spdm_mel,
    size_t *spdm_mel_size)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
