/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_read_cached_last_csr_request(uint8_t **last_csr_request,
                                          size_t *last_csr_request_len,
                                          uint8_t req_csr_tracking_tag,
                                          uint8_t *available_rsp_csr_tracking_tag)
{
    bool res;
    uint8_t index;
    size_t file_size;
    uint8_t *file_data;

    file_data = NULL;
    *available_rsp_csr_tracking_tag = 0;
    char file[] = "cached_last_csr_x_request";
    /*change the file name, for example: cached_last_csr_1_request*/
    file[16] = (char)(req_csr_tracking_tag + '0');
    res = libspdm_read_input_file(file, (void **)last_csr_request, last_csr_request_len);

    for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
        file[16] = (char)(index + '0');
        libspdm_read_input_file(file, (void **)(&file_data), &file_size);
        if (file_size == 0) {
            *available_rsp_csr_tracking_tag |=  (1 << index);
        } else {
            if (file_data != NULL) {
                free(file_data);
            }
        }
    }

    return res;
}

bool libspdm_cache_last_csr_request(const uint8_t *last_csr_request,
                                    size_t last_csr_request_len,
                                    uint8_t req_csr_tracking_tag)
{
    bool res;

    char file[] = "cached_last_csr_x_request";
    /*change the file name, for example: cached_last_csr_1_request*/
    file[16] = (char)(req_csr_tracking_tag + '0');
    res = libspdm_write_output_file(file, last_csr_request, last_csr_request_len);

    return res;
}

/*clean the cached last SPDM csr request*/
bool libspdm_discard_all_cached_last_request()
{
    uint8_t index;

    char file[] = "cached_last_csr_x_request";

    for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
        file[16] = (char)(index + '0');
        if (!libspdm_write_output_file(file, NULL, 0)) {
            return false;
        }
    }

    return true;
}

/*
 * return true represent that: the device complete the csr by reset successfully
 * return false represent that: the device complete the csr need reset
 **/
bool libspdm_read_cached_csr(uint8_t **csr_pointer, size_t *csr_len)
{
    bool res;
    char *file;

    file = "test_csr/cached.csr";

    res = libspdm_read_input_file(file, (void **)csr_pointer, csr_len);
    return res;
}

bool libspdm_gen_csr_without_reset(uint32_t base_hash_algo, uint32_t base_asym_algo,
                                   uint8_t *requester_info, size_t requester_info_length,
                                   uint8_t *opaque_data, uint16_t opaque_data_length,
                                   size_t *csr_len, uint8_t *csr_pointer,
                                   bool is_device_cert_model)
{
    bool result;
    size_t hash_nid;
    size_t asym_nid;
    void *context;
    size_t csr_buffer_size;

    csr_buffer_size = *csr_len;

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *x509_ca_cert;
        void *prikey, *cert;
        size_t prikey_size, cert_size;

        result = libspdm_read_responder_private_key(
            base_asym_algo, &prikey, &prikey_size);
        if (!result) {
            return false;
        }

        result = libspdm_read_responder_certificate(
            base_asym_algo, &cert, &cert_size);
        if (!result) {
            return false;
        }

        result = libspdm_x509_construct_certificate(cert, cert_size,
                                                    (uint8_t **)&x509_ca_cert);
        if ((x509_ca_cert == NULL) || (!result)) {
            return false;
        }

        result = libspdm_asym_get_private_key_from_pem(
            base_asym_algo, prikey, prikey_size, NULL, &context);
        if (!result) {
            libspdm_zero_mem(prikey, prikey_size);
            free(prikey);
            return false;
        }
        hash_nid = libspdm_get_hash_nid(base_hash_algo);
        asym_nid = libspdm_get_aysm_nid(base_asym_algo);

        char *subject_name = "C=NL,O=PolarSSL,CN=PolarSSL Server 1";

        result = libspdm_gen_x509_csr(hash_nid, asym_nid,
                                      requester_info, requester_info_length,
                                      !is_device_cert_model,
                                      context, subject_name,
                                      csr_len, csr_pointer,
                                      x509_ca_cert);
        libspdm_asym_free(base_asym_algo, context);
        libspdm_zero_mem(prikey, prikey_size);
        free(prikey);
        free(cert);
    } else {
#endif
    void *x509_ca_cert;
    void *cert;
    size_t cert_size;

    result = libspdm_get_responder_private_key_from_raw_data(base_asym_algo, &context);
    if (!result) {
        return false;
    }

    result = libspdm_read_responder_certificate(
        base_asym_algo, &cert, &cert_size);
    if (!result) {
        return false;
    }

    result = libspdm_x509_construct_certificate(cert, cert_size,
                                                (uint8_t **)&x509_ca_cert);
    if ((x509_ca_cert == NULL) || (!result)) {
        return false;
    }

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    asym_nid = libspdm_get_aysm_nid(base_asym_algo);

    char *subject_name = "C=NL,O=PolarSSL,CN=PolarSSL Server 1";

    result = libspdm_gen_x509_csr(hash_nid, asym_nid,
                                  requester_info, requester_info_length,
                                  !is_device_cert_model,
                                  context, subject_name,
                                  csr_len, csr_pointer,
                                  x509_ca_cert);
    libspdm_asym_free(base_asym_algo, context);
    free(cert);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

    if (csr_buffer_size < *csr_len) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"csr buffer is too small to store generated csr! \n"));
        result = false;
    }
    return result;
}

bool libspdm_gen_csr(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    bool is_device_cert_model
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *is_busy, bool *unexpected_request
#endif
    )
{
    bool result;
    uint8_t *cached_last_csr_request;
    size_t cached_last_request_len;
    uint8_t *cached_csr;
    size_t csr_buffer_size;
    uint8_t rsp_csr_tracking_tag;

    csr_buffer_size = *csr_len;

    /*device gen csr need reset*/
    if (*need_reset) {
        result = libspdm_read_cached_last_csr_request(&cached_last_csr_request,
                                                      &cached_last_request_len,
                                                      1, &rsp_csr_tracking_tag);

        /*get the cached last csr request and csr*/
        if ((result) &&
            (cached_last_request_len == request_size) &&
            (libspdm_consttime_is_mem_equal(cached_last_csr_request, request,
                                            request_size)) &&
            (libspdm_read_cached_csr(&cached_csr, csr_len)) &&
            (*csr_len != 0)) {

            /*get and save cached csr*/
            if (csr_buffer_size < *csr_len) {
                free(cached_csr);
                free(cached_last_csr_request);
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "csr buffer is too small to store cached csr! \n"));
                return false;
            } else {
                libspdm_copy_mem(csr_pointer, csr_buffer_size, cached_csr, *csr_len);
            }

            /*device don't need reset this time*/
            *need_reset = false;

            free(cached_csr);
            free(cached_last_csr_request);
            return true;
        } else {
            if (cached_last_csr_request != NULL) {
                free(cached_last_csr_request);
            }

            /*device need reset this time: cache the last_csr_request */
            result = libspdm_cache_last_csr_request(request, request_size, 1);
            if (!result) {
                return result;
            }

            /*device need reset this time*/
            *need_reset = true;
            return true;
        }
    } else {
        result = libspdm_gen_csr_without_reset(base_hash_algo, base_asym_algo,
                                               requester_info, requester_info_length,
                                               opaque_data, opaque_data_length,
                                               csr_len, csr_pointer, is_device_cert_model);
        return result;
    }

}

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
bool libspdm_gen_csr_ex(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    uint8_t req_cert_model,
    uint8_t *req_csr_tracking_tag,
    uint8_t req_key_pair_id,
    bool overwrite
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *is_busy, bool *unexpected_request
#endif
    )
{
    bool result;
    uint8_t *cached_last_csr_request;
    size_t cached_last_request_len;
    uint8_t *cached_csr;
    size_t csr_buffer_size;
    uint8_t rsp_csr_tracking_tag;
    uint8_t available_csr_tracking_tag;
    uint8_t *request_change;
    uint8_t index;
    bool flag;
    bool is_device_cert_model;

    available_csr_tracking_tag = 0;
    csr_buffer_size = *csr_len;

    /*device gen csr need reset*/
    if (*need_reset) {
        result = libspdm_read_cached_last_csr_request(&cached_last_csr_request,
                                                      &cached_last_request_len,
                                                      *req_csr_tracking_tag,
                                                      &rsp_csr_tracking_tag);

        for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
            if (((rsp_csr_tracking_tag >> index) & 0x01) == 0x01) {
                available_csr_tracking_tag = index;
                break;
            }
        }

        if (*req_csr_tracking_tag == 0) {
            if (available_csr_tracking_tag == 0) {
                /*no available tracking tag*/
                #if LIBSPDM_SET_CERT_CSR_PARAMS
                *is_busy = true;
                #endif
                return false;
            } else {
                flag = false;
            }
        } else {
            /*matched csr_tracking_tag*/
            if (((rsp_csr_tracking_tag >> *req_csr_tracking_tag) & 0x01) == 0) {
                flag = true;
            } else {
                /*unexpected*/
                return false;
            }
        }

        /*get the cached last csr request and csr*/
        if ((result) &&
            (cached_last_request_len == request_size) &&
            (libspdm_consttime_is_mem_equal(cached_last_csr_request, request,
                                            request_size)) &&
            (libspdm_read_cached_csr(&cached_csr, csr_len)) &&
            (*csr_len != 0) &&
            (flag)) {

            /*get and save cached csr*/
            if (csr_buffer_size < *csr_len) {
                free(cached_csr);
                free(cached_last_csr_request);
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "csr buffer is too small to store cached csr! \n"));
                return false;
            } else {
                libspdm_copy_mem(csr_pointer, csr_buffer_size, cached_csr, *csr_len);
            }

            /*device don't need reset this time*/
            *need_reset = false;

            free(cached_csr);
            free(cached_last_csr_request);
            return true;
        } else {
            if (cached_last_csr_request != NULL) {
                free(cached_last_csr_request);
            }

            if ((*req_csr_tracking_tag == 0) && (available_csr_tracking_tag != 0)) {
                request_change = malloc(request_size);
                libspdm_copy_mem(request_change, request_size, request,request_size);

                if (overwrite) {
                    available_csr_tracking_tag = 1;
                    /*discard all previously generated CSRTrackingTags. */
                    result = libspdm_discard_all_cached_last_request();
                    if (!result) {
                        free(request_change);
                        return result;
                    }
                }

                request_change[3] |=
                    (available_csr_tracking_tag <<
                        SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET);

                /*device need reset this time: cache the last_csr_request */
                result = libspdm_cache_last_csr_request(request_change,
                                                        request_size, available_csr_tracking_tag);
                if (!result) {
                    free(request_change);
                    return result;
                }

                /*device need reset this time*/
                *need_reset = true;
                *req_csr_tracking_tag = available_csr_tracking_tag;
                free(request_change);
                return true;
            } else {
                /*the device is busy*/
                #if LIBSPDM_SET_CERT_CSR_PARAMS
                *is_busy = true;
                #endif
                return false;
            }
        }
    } else {
        if (req_cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT) {
            is_device_cert_model = true;
        } else {
            is_device_cert_model = false;
        }
        result = libspdm_gen_csr_without_reset(base_hash_algo, base_asym_algo,
                                               requester_info, requester_info_length,
                                               opaque_data, opaque_data_length,
                                               csr_len, csr_pointer, is_device_cert_model);
        return result;
    }
}
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/

#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
