/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * SPDM requester sample over MCTP.
 *
 * Pair this sample with samples/spdm_responder_mctp flashed onto a
 * second board on the same bus.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <libmctp.h>
#if defined(CONFIG_MCTP_I3C_CONTROLLER)
#include <zephyr/pmci/mctp/mctp_i3c_controller.h>
#elif defined(CONFIG_MCTP_I2C_GPIO_CONTROLLER)
#include <zephyr/pmci/mctp/mctp_i2c_gpio_controller.h>
#else
#error "no supported MCTP controller binding selected (I3C or I2C+GPIO)"
#endif

#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm.h"

#include "libspdm/zephyr/mctp_io.h"

#include "sample_ecp256.h"
#include "sample_static_blob_store.h"
#include "sample_support.h"

LOG_MODULE_REGISTER(spdm_requester_mctp, LOG_LEVEL_INF);

/*
 * Application payload exchanged over the secured session.
 * The responder sample must agree on APP_REQUEST / APP_REPLY.
 */
#define APP_REQUEST "ping"
#define APP_REPLY   "pong"

#define LOCAL_EID 20U
#define PEER_EID  11U

/*
 * The MCTP bus binding is selected per board: MCTP over I3C on
 * npcx4m8f_evb, MCTP over I2C+GPIO on frdm_mcxn947. Both expose a
 * struct mctp_binding at .binding, so the rest of the sample is
 * transport agnostic.
 */
#if defined(CONFIG_MCTP_I3C_CONTROLLER)
MCTP_I3C_CONTROLLER_DT_DEFINE(mctp_ctrl, DT_NODELABEL(mctp_i3c));
#else /* CONFIG_MCTP_I2C_GPIO_CONTROLLER */
MCTP_I2C_GPIO_CONTROLLER_DT_DEFINE(mctp_ctrl, DT_NODELABEL(mctp_i2c));
#endif

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

    u32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    if (libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &param,
                         &u32, sizeof(u32)) != LIBSPDM_STATUS_SUCCESS) {
        return -1;
    }

    u8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
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
static int install_peer_root_cert(void *spdm_ctx)
{
    libspdm_data_parameter_t param;
    void *cert_chain = NULL;
    size_t cert_chain_size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool res;

    res = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    if (!res || cert_chain == NULL) {
        LOG_ERR("cannot load responder cert chain to extract root");
        return -1;
    }

    res = libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + hash_size,
        cert_chain_size - sizeof(spdm_cert_chain_t) - hash_size,
        0, &root_cert, &root_cert_size);
    if (!res) {
        LOG_ERR("cert-chain root extract failed");
        free(cert_chain);
        return -1;
    }

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    (void)libspdm_set_data(spdm_ctx, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                           &param, (void *)root_cert, root_cert_size);
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

    LOG_INF("SPDM requester on %s", CONFIG_BOARD_TARGET);
    LOG_INF("local EID=%u, peer EID=%u", LOCAL_EID, PEER_EID);

    mctp_ctx = mctp_init();
    __ASSERT_NO_MSG(mctp_ctx != NULL);
    mctp_register_bus(mctp_ctx, &mctp_ctrl.binding, LOCAL_EID);

    rc = libspdm_zephyr_mctp_io_init(&spdm_io, mctp_ctx, PEER_EID);
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
    if (install_peer_root_cert(spdm_ctx) != 0) {
        return -1;
    }
#endif

    LOG_INF("issuing GET_VERSION");
    status = libspdm_init_connection(spdm_ctx, true);
    if (status != LIBSPDM_STATUS_SUCCESS) {
        LOG_ERR("GET_VERSION failed: 0x%x", status);
        return -1;
    }
    LOG_INF("GET_VERSION ok");

    LOG_INF("issuing GET_CAPABILITIES + NEGOTIATE_ALGORITHMS");
    status = libspdm_init_connection(spdm_ctx, false);
    if (status != LIBSPDM_STATUS_SUCCESS) {
        LOG_ERR("CAPABILITIES/ALGORITHMS failed: 0x%x", status);
        return -1;
    }
    LOG_INF("GET_CAPABILITIES + NEGOTIATE_ALGORITHMS ok");

#ifdef CONFIG_LIBSPDM_CRYPTO_MBEDTLS
    {
        uint8_t slot_mask = 0;
        uint8_t total_digest[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];

        status = libspdm_get_digest(spdm_ctx, NULL, &slot_mask, total_digest);
        if (status != LIBSPDM_STATUS_SUCCESS) {
            LOG_ERR("GET_DIGESTS failed: 0x%x", status);
            return -1;
        }
        LOG_INF("GET_DIGESTS ok, slot_mask=0x%02x", slot_mask);
    }

    {
        static uint8_t cert_buf[0x800];
        size_t cert_chain_size = sizeof(cert_buf);

        status = libspdm_get_certificate(spdm_ctx, NULL, 0,
                                         &cert_chain_size, cert_buf);
        if (status != LIBSPDM_STATUS_SUCCESS) {
            LOG_ERR("GET_CERTIFICATE failed: 0x%x", status);
            return -1;
        }
        LOG_INF("GET_CERTIFICATE ok, chain_size=%zu", cert_chain_size);
    }

    {
        uint8_t slot_mask = 0;

        status = libspdm_challenge(spdm_ctx, NULL, 0,
                                   SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   NULL, &slot_mask);
        if (status != LIBSPDM_STATUS_SUCCESS) {
            LOG_ERR("CHALLENGE_AUTH failed: 0x%x", status);
            return -1;
        }
        LOG_INF("CHALLENGE_AUTH ok");
    }

    LOG_INF("*** SPDM authenticated handshake PASSED ***");

    /*
     * Open an encrypted SPDM session, send the request as a single
     * AEAD-protected application message, check the reply, then close
     * the session.
     */
    {
        uint32_t session_id = 0;
        uint8_t heartbeat_period = 0;
        uint8_t reply[64];
        size_t reply_size = sizeof(reply);

        LOG_INF("starting secure session + ping/pong");

        status = libspdm_start_session(
            spdm_ctx, false /* use_psk */, NULL, 0,
            SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
            0 /* slot_id */, 0 /* session_policy */,
            &session_id, &heartbeat_period, NULL);
        if (status != LIBSPDM_STATUS_SUCCESS) {
            LOG_ERR("KEY_EXCHANGE/FINISH failed: 0x%x", status);
            return -1;
        }

        status = libspdm_send_receive_data(
            spdm_ctx, &session_id, true /* is_app_message */,
            APP_REQUEST, sizeof(APP_REQUEST) - 1, reply, &reply_size);
        if (status != LIBSPDM_STATUS_SUCCESS) {
            LOG_ERR("app message exchange failed: 0x%x", status);
            (void)libspdm_stop_session(spdm_ctx, session_id, 0);
            return -1;
        }

        if (reply_size != sizeof(APP_REPLY) - 1 ||
            memcmp(reply, APP_REPLY, reply_size) != 0) {
            LOG_ERR("unexpected reply (%zu bytes)", reply_size);
            (void)libspdm_stop_session(spdm_ctx, session_id, 0);
            return -1;
        }
        LOG_INF("sent \"%s\", received \"%s\"", APP_REQUEST, APP_REPLY);

        (void)libspdm_stop_session(spdm_ctx, session_id, 0);
        LOG_INF("*** SPDM session ping/pong PASSED ***");
    }
#else
    LOG_INF("*** SPDM handshake (version/caps/algs) PASSED ***");
#endif

    return 0;
}
