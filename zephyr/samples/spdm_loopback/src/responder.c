/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * SPDM responder thread for the libspdm Zephyr loopback demo.
 */

#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "library/spdm_common_lib.h"
#include "library/spdm_responder_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm.h"

#include "spdm_loopback.h"

/*
 * Application payload exchanged over the secured session. The requester
 * (requester.c) must agree on APP_REQUEST / APP_REPLY.
 */
#define APP_REQUEST "ping"
#define APP_REPLY   "pong"

/*
 * Application-message handler. libspdm calls this for every message
 * that arrives inside a secured session with is_app_message == true.
 * This sample implements a trivial request/reply protocol: it answers
 * the request "ping" with "pong".
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
        printk("[responder] received secured app request \"%s\", replying \"%s\"\n",
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

void *responder_spdm_context;
void *responder_scratch;

static bool install_responder_cert_chain(void *ctx)
{
    libspdm_data_parameter_t parameter;
    void *cert_chain = NULL;
    size_t cert_chain_size = 0;
    uint8_t u8;
    bool res;

    res = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, NULL, NULL);
    if (!res || cert_chain == NULL) {
        printk("[responder] failed to load responder cert chain\n");
        return false;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    parameter.additional_data[0] = 0; /* slot 0 */
    libspdm_set_data(ctx, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                     &parameter, cert_chain, cert_chain_size);

    u8 = 1 << 0; /* only slot 0 populated */
    libspdm_set_data(ctx, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
                     &parameter, &u8, sizeof(u8));
    return true;
}

static void configure_responder(void *ctx)
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

    u32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    libspdm_set_data(ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &u32, sizeof(u32));

    /* Algorithms to advertise. Match what the requester proposes. */
    u8 = 0;
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

void responder_thread_main(void *a, void *b, void *c)
{
    struct mock_transport *t = (struct mock_transport *)a;
    libspdm_return_t status;
    size_t scratch_size;

    ARG_UNUSED(b);
    ARG_UNUSED(c);

    printk("[responder] starting\n");

    responder_spdm_context = malloc(libspdm_get_context_size());
    if (responder_spdm_context == NULL) {
        printk("[responder] ctx alloc failed\n");
        return;
    }
    libspdm_init_context(responder_spdm_context);

    mock_transport_install(responder_spdm_context, t);
    configure_responder(responder_spdm_context);
    if (!install_responder_cert_chain(responder_spdm_context)) {
        return;
    }

    scratch_size = libspdm_get_sizeof_required_scratch_buffer(
        responder_spdm_context);
    responder_scratch = malloc(scratch_size);
    if (responder_scratch == NULL) {
        printk("[responder] scratch alloc failed (%zu)\n", scratch_size);
        return;
    }
    libspdm_set_scratch_buffer(responder_spdm_context,
                               responder_scratch, scratch_size);

    /* Hook in the application-message dispatcher: libspdm invokes
     * app_message_handler() whenever a secured message lands with
     * is_app_message set.
     */
    libspdm_register_get_response_func(responder_spdm_context,
                                       app_message_handler);

    printk("[responder] ready, scratch=%zu bytes\n", scratch_size);

    k_sem_give(&responder_ready);

    while (1) {
        status = libspdm_responder_dispatch_message(responder_spdm_context);
        if (status == LIBSPDM_STATUS_SUCCESS) {
            /* One request was received, processed, and answered. */
            printk("[responder] received a request and sent a response\n");
            continue;
        }
        if (status == LIBSPDM_STATUS_RECEIVE_FAIL) {
            /* Link closed by main() after the requester finished, or
             * the peer went quiet for MOCK_TIMEOUT_MS. Either way
             * there is nothing left to serve. */
            printk("[responder] no more requests, exiting\n");
            return;
        }
        printk("[responder] dispatch returned 0x%x\n", status);
    }
}
