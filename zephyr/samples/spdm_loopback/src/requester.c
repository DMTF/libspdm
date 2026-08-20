/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * SPDM requester thread for the libspdm Zephyr loopback demo.
 */

#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm.h"

#include "spdm_loopback.h"

/*
 * Application payload exchanged over the secured session.
 * The responder in responder.c must agree on APP_REQUEST / APP_REPLY.
 */
#define APP_REQUEST "ping"
#define APP_REPLY   "pong"

void *requester_spdm_context;
void *requester_scratch;

static bool install_peer_root_cert(void *ctx)
{
    libspdm_data_parameter_t parameter;
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
        printk("[requester] cannot load responder cert chain "
               "(needed only to extract root cert)\n");
        return false;
    }

    res = libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + hash_size,
        cert_chain_size - sizeof(spdm_cert_chain_t) - hash_size,
        0, &root_cert, &root_cert_size);
    if (!res) {
        printk("[requester] cert-chain root extract failed\n");
        free(cert_chain);
        return false;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(ctx, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                     &parameter, (void *)root_cert, root_cert_size);
    return true;
}

static void configure_requester(void *ctx)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    spdm_version_number_t version;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(ctx, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &version, sizeof(version));

    u8 = 0;
    libspdm_set_data(ctx, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter,
                     &u8, sizeof(u8));

    /* Requester capabilities: pair the responder side. */
    u32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_set_data(ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &u32, sizeof(u32));

    u8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_set_data(ctx, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &u8, sizeof(u8));
    u32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    libspdm_set_data(ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &u32, sizeof(u32));
    u32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    libspdm_set_data(ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &u32, sizeof(u32));
    u16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
    libspdm_set_data(ctx, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &u16, sizeof(u16));
    u16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    libspdm_set_data(ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &u16, sizeof(u16));
    u16 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    libspdm_set_data(ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &u16, sizeof(u16));
    u16 = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
    libspdm_set_data(ctx, LIBSPDM_DATA_KEY_SCHEDULE, &parameter,
                     &u16, sizeof(u16));
    u8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(ctx, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &u8, sizeof(u8));
}

void requester_thread_main(void *a, void *b, void *c)
{
    struct mock_transport *t = (struct mock_transport *)a;
    libspdm_return_t status;
    size_t scratch_size;

    ARG_UNUSED(b);
    ARG_UNUSED(c);

    if (k_sem_take(&responder_ready, SPDM_LOOPBACK_READY_TIMEOUT) != 0) {
        printk("[requester] responder did not come up, giving up\n");
        return;
    }
    printk("[requester] starting\n");

    requester_spdm_context = malloc(libspdm_get_context_size());
    if (requester_spdm_context == NULL) {
        printk("[requester] ctx alloc failed\n");
        return;
    }
    libspdm_init_context(requester_spdm_context);

    mock_transport_install(requester_spdm_context, t);
    configure_requester(requester_spdm_context);
    if (!install_peer_root_cert(requester_spdm_context)) {
        return;
    }

    scratch_size = libspdm_get_sizeof_required_scratch_buffer(
        requester_spdm_context);
    requester_scratch = malloc(scratch_size);
    if (requester_scratch == NULL) {
        printk("[requester] scratch alloc failed (%zu)\n", scratch_size);
        return;
    }
    libspdm_set_scratch_buffer(requester_spdm_context,
                               requester_scratch, scratch_size);

    printk("[requester] ready, scratch=%zu bytes\n", scratch_size);

    /* GET_VERSION only first -- this is the smallest amount of bytes
     * that exercises the loopback transport, the MCTP framing and
     * both libspdm state machines. */
    status = libspdm_init_connection(requester_spdm_context, true);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printk("[requester] GET_VERSION failed: 0x%x\n", status);
        return;
    }
    printk("[requester] GET_VERSION ok\n");

    /* Now run GET_CAPABILITIES + NEGOTIATE_ALGORITHMS. */
    status = libspdm_init_connection(requester_spdm_context, false);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printk("[requester] init_connection (caps+algs) failed: 0x%x\n",
               status);
        return;
    }
    printk("[requester] GET_CAPABILITIES + NEGOTIATE_ALGORITHMS ok\n");

    {
        uint8_t slot_mask = 0;
        uint8_t total_digest[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];

        status = libspdm_get_digest(requester_spdm_context, NULL,
                                    &slot_mask, total_digest);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printk("[requester] GET_DIGESTS failed: 0x%x\n", status);
            return;
        }
        printk("[requester] GET_DIGESTS ok, slot_mask=0x%02x\n", slot_mask);
    }

    {
        static uint8_t cert_buf[0x800];
        size_t cert_chain_size = sizeof(cert_buf);

        status = libspdm_get_certificate(requester_spdm_context, NULL,
                                         0, &cert_chain_size, cert_buf);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printk("[requester] GET_CERTIFICATE failed: 0x%x\n", status);
            return;
        }
        printk("[requester] GET_CERTIFICATE ok, chain_size=%zu\n",
               cert_chain_size);
    }

    {
        uint8_t slot_mask = 0;

        status = libspdm_challenge(requester_spdm_context, NULL, 0,
                                   SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   NULL, &slot_mask);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printk("[requester] CHALLENGE_AUTH failed: 0x%x\n", status);
            return;
        }
        printk("[requester] CHALLENGE_AUTH ok\n");
    }

    printk("[requester] *** SPDM authenticated handshake PASSED ***\n");

    /*
     * Open an encrypted SPDM session, send the request as a single
     * AEAD-protected application message, check the reply, then close the
     * session.
     */
    {
        uint32_t session_id = 0;
        uint8_t heartbeat_period = 0;
        uint8_t reply[64];
        size_t reply_size = sizeof(reply);

        status = libspdm_start_session(
            requester_spdm_context, false /* use_psk */, NULL, 0,
            SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
            0 /* slot_id */, 0 /* session_policy */,
            &session_id, &heartbeat_period, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printk("[requester] KEY_EXCHANGE/FINISH failed: 0x%x\n", status);
            return;
        }

        status = libspdm_send_receive_data(
            requester_spdm_context, &session_id, true /* is_app_message */,
            APP_REQUEST, sizeof(APP_REQUEST) - 1, reply, &reply_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printk("[requester] app message exchange failed: 0x%x\n", status);
            libspdm_stop_session(requester_spdm_context, session_id, 0);
            return;
        }

        if (reply_size != sizeof(APP_REPLY) - 1 ||
            memcmp(reply, APP_REPLY, reply_size) != 0) {
            printk("[requester] unexpected reply (%zu bytes)\n", reply_size);
            libspdm_stop_session(requester_spdm_context, session_id, 0);
            return;
        }
        printk("[requester] sent \"%s\", received \"%s\"\n",
               APP_REQUEST, APP_REPLY);

        libspdm_stop_session(requester_spdm_context, session_id, 0);
    }

    printk("[requester] *** SPDM session ping/pong PASSED ***\n");
}
