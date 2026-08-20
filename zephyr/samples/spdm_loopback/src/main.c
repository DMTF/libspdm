/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "spdm_loopback.h"
#include "sample_ecp256.h"
#include "sample_static_blob_store.h"
#include "sample_support.h"

/* The two channels making up the loopback link. */
static struct mock_channel req_to_rsp;
static struct mock_channel rsp_to_req;

static struct mock_transport requester_transport;
static struct mock_transport responder_transport;

K_SEM_DEFINE(responder_ready, 0, 1);

#define STACK_SIZE 16384

K_THREAD_STACK_DEFINE(responder_stack, STACK_SIZE);
K_THREAD_STACK_DEFINE(requester_stack, STACK_SIZE);
static struct k_thread responder_thread;
static struct k_thread requester_thread;

int main(void)
{
    printk("\nlibspdm Zephyr loopback demo\n");
    printk("============================\n");

    if (sample_static_blob_register(sample_ecp256_blobs) != 0) {
        printk("secret blob registration failed\n");
        return -1;
    }

    /* X.509 validity checks need a wall clock. Point it at a time
     * inside the sample certificates' window. */
    sample_wallclock_init(SAMPLE_ECP256_WALLCLOCK_S);

    mock_channel_init(&req_to_rsp);
    mock_channel_init(&rsp_to_req);

    requester_transport.tx = &req_to_rsp;
    requester_transport.rx = &rsp_to_req;
    responder_transport.tx = &rsp_to_req;
    responder_transport.rx = &req_to_rsp;

    k_thread_create(&responder_thread, responder_stack, STACK_SIZE,
                    responder_thread_main, &responder_transport, NULL, NULL,
                    K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
    k_thread_name_set(&responder_thread, "spdm_rsp");

    k_thread_create(&requester_thread, requester_stack, STACK_SIZE,
                    requester_thread_main, &requester_transport, NULL, NULL,
                    K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
    k_thread_name_set(&requester_thread, "spdm_req");

    /* Wait for the requester to finish, then tell the responder that
     * the link is gone so it winds down immediately instead of sitting
     * out its receive timeout. */
    k_thread_join(&requester_thread, K_SECONDS(60));
    mock_channel_close(&req_to_rsp);
    k_thread_join(&responder_thread, K_SECONDS(5));
    printk("\nlibspdm Zephyr loopback demo: main exiting\n");
    return 0;
}
