/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * SPDM responder sample over MCTP. Pairs with
 * samples/spdm_requester_mctp flashed onto a second board on the same
 * I3C bus.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <libmctp.h>
#include <zephyr/pmci/mctp/mctp_i3c_target.h>

#include "library/spdm_common_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm.h"

#include "libspdm/zephyr/mctp_io.h"

#include "sample_ecp256.h"
#include "sample_static_blob_store.h"
#include "sample_support.h"

LOG_MODULE_REGISTER(spdm_responder_mctp, LOG_LEVEL_INF);

MCTP_I3C_TARGET_DT_DEFINE(mctp_i3c_tgt, DT_NODELABEL(mctp_i3c));

/*
 * Application payload exchanged over the secured session. The requester
 * sample must agree on APP_REQUEST / APP_REPLY.
 */
#define APP_REQUEST "ping"
#define APP_REPLY   "pong"

/*
 * Application-message handler. libspdm calls this for every message
 * that arrives inside a secured session with is_app_message == true.
 * This sample implements a trivial request/reply protocol: it answers
 * the request "ping" with "pong". Change the body to handle your own
 * application payload.
 */
static libspdm_return_t app_message_handler(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    (void)spdm_context;

    /* Only answer application messages inside a secured session; let
     * libspdm's default handler deal with everything else. */
    if (!is_app_message || session_id == NULL) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (request_size == sizeof(APP_REQUEST) - 1 &&
        memcmp(request, APP_REQUEST, request_size) == 0) {
        LOG_INF("received secured app request \"%s\", replying \"%s\"",
                APP_REQUEST, APP_REPLY);
        if (*response_size < sizeof(APP_REPLY) - 1) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        memcpy(response, APP_REPLY, sizeof(APP_REPLY) - 1);
        *response_size = sizeof(APP_REPLY) - 1;
        return LIBSPDM_STATUS_SUCCESS;
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}


static struct libspdm_zephyr_mctp_io spdm_io;

static int configure_spdm(void *spdm_ctx)
{
    libspdm_data_parameter_t param;
    spdm_version_number_t version;
    uint8_t u8;
    uint32_t u32;
    uint16_t u16;

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;

    version = (spdm_version_number_t)SPDM_MESSAGE_VERSION_12
              << SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (libspdm_set_data(spdm_ctx, LIBSPDM_DATA_SPDM_VERSION, &param,
                         &version, sizeof(version)) != LIBSPDM_STATUS_SUCCESS) {
        return -1;
    }

    /* CT_EXPONENT advertises this responder's worst-case crypto
     * response time as 2^CT microseconds, and the requester waits that
     * long for crypto-bearing responses. It defaults to 0, i.e. 1 us,
     * which no software implementation can meet. All crypto runs in
     * software here, so KEY_EXCHANGE can take well over a second;
     * CT=22 (~4.2 s) gives ample headroom without being absurdly large.
     */
    u8 = 22U;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                           &param, &u8, sizeof(u8));

    u32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    if (libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &param,
                         &u32, sizeof(u32)) != LIBSPDM_STATUS_SUCCESS) {
        return -1;
    }

    u8 = 0U;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_MEASUREMENT_SPEC,
                           &param, &u8, sizeof(u8));

    u32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &param,
                           &u32, sizeof(u32));

    u32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &param,
                           &u32, sizeof(u32));

    u16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_DHE_NAME_GROUP, &param,
                           &u16, sizeof(u16));

    u16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                           &param, &u16, sizeof(u16));

    u16 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                           &param, &u16, sizeof(u16));

    u16 = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_KEY_SCHEDULE, &param,
                           &u16, sizeof(u16));

    u8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
                           &param, &u8, sizeof(u8));

    return 0;
}

#ifdef CONFIG_LIBSPDM_CRYPTO_MBEDTLS
static int install_responder_cert_chain(void *spdm_ctx)
{
    libspdm_data_parameter_t param;
    void *cert_chain = NULL;
    size_t cert_chain_size = 0;
    uint8_t u8;
    bool res;

    res = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, NULL, NULL);
    if (!res || cert_chain == NULL) {
        LOG_ERR("failed to load responder cert chain");
        return -1;
    }

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    param.additional_data[0] = 0; /* slot 0 */
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                           &param, cert_chain, cert_chain_size);

    u8 = 1U << 0; /* only slot 0 populated */
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
                           &param, &u8, sizeof(u8));
    return 0;
}
#endif

int main(void)
{
    struct mctp *mctp_ctx;
    void *spdm_ctx;
    size_t ctx_size;
    void *spdm_scratch;
    size_t scratch_size;
    libspdm_return_t status;
    int rc;
    uint8_t local_eid = mctp_i3c_tgt.endpoint_id;

    LOG_INF("SPDM responder on %s", CONFIG_BOARD_TARGET);
    LOG_INF("local EID=%u", local_eid);

    mctp_ctx = mctp_init();
    __ASSERT_NO_MSG(mctp_ctx != NULL);
    mctp_register_bus(mctp_ctx, &mctp_i3c_tgt.binding, local_eid);

    rc = libspdm_zephyr_mctp_io_init(&spdm_io, mctp_ctx, 0);
    if (rc != 0) {
        LOG_ERR("libspdm_zephyr_mctp_io_init failed: %d", rc);
        return rc;
    }

    ctx_size = libspdm_get_context_size();
    spdm_ctx = malloc(ctx_size);
    if (spdm_ctx == NULL) {
        LOG_ERR("libspdm context alloc failed (%zu bytes)", ctx_size);
        return -1;
    }

    libspdm_init_context(spdm_ctx);

    rc = libspdm_zephyr_mctp_io_register(spdm_ctx, &spdm_io);
    if (rc != 0) {
        LOG_ERR("libspdm_zephyr_mctp_io_register failed: %d", rc);
        return rc;
    }

    scratch_size = libspdm_get_sizeof_required_scratch_buffer(spdm_ctx);
    spdm_scratch = malloc(scratch_size);
    if (spdm_scratch == NULL) {
        LOG_ERR("scratch buffer alloc failed (%zu bytes)", scratch_size);
        return -1;
    }
    libspdm_set_scratch_buffer(spdm_ctx, spdm_scratch, scratch_size);

    if (configure_spdm(spdm_ctx) != 0) {
        LOG_ERR("configure_spdm failed");
        return -1;
    }

#ifdef CONFIG_LIBSPDM_CRYPTO_MBEDTLS
    if (sample_static_blob_register(sample_ecp256_blobs) != 0) {
        LOG_ERR("secret blob registration failed");
        return -1;
    }
    /* X.509 validity checks need a wall clock. Point it at a time
     * inside the sample certificates' window. */
    sample_wallclock_init(SAMPLE_ECP256_WALLCLOCK_S);
    if (install_responder_cert_chain(spdm_ctx) != 0) {
        return -1;
    }

    /* Hook in the application-message dispatcher: libspdm invokes
     * app_message_handler() whenever a secured message lands with
     * is_app_message set.
     */
    libspdm_register_get_response_func(spdm_ctx, app_message_handler);
#endif

    LOG_INF("entering responder dispatch loop");
    while (true) {
        status = libspdm_responder_dispatch_message(spdm_ctx);
        if (status == LIBSPDM_STATUS_SUCCESS) {
            /* One request was received, processed, and answered. */
            LOG_INF("received an SPDM request and sent a response");
            continue;
        }
        if (status == LIBSPDM_STATUS_RECEIVE_FAIL) {
            continue;
        }
        LOG_WRN("dispatch returned 0x%x", status);
    }

    return 0;
}
