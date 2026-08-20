/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * In-process loopback transport for the demo.
 *
 * The libspdm device_send / device_receive callbacks below receive
 * already-framed transport bytes (MCTP + SPDM) and shuttle them
 * across two synchronised buffers - no real wire involved.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "library/spdm_common_lib.h"
#include "library/spdm_transport_mctp_lib.h"

#include "spdm_loopback.h"

#define MOCK_TIMEOUT_MS 60000

/*
 * Per-context state.
 *
 * libspdm has no generic "opaque per-context pointer" data key, so a
 * small static table keyed on the spdm_context pointer stands in for
 * one.
 */
struct loopback_endpoint {
    void *spdm_context;
    struct mock_transport *chan;   /* this side's tx/rx channel pair */

    uint8_t msg_buf[SPDM_LOOPBACK_BUFFER_SIZE];
    bool msg_buf_in_use;
};

#define LOOPBACK_MAX_ENDPOINTS 4
static struct loopback_endpoint endpoints[LOOPBACK_MAX_ENDPOINTS];
static struct k_spinlock endpoints_lock;

void mock_channel_init(struct mock_channel *ch)
{
    ch->len = 0;
    ch->closed = false;
    k_sem_init(&ch->ready, 0, 1);
    k_sem_init(&ch->freed, 1, 1);  /* slot starts empty */
}

void mock_channel_close(struct mock_channel *ch)
{
    ch->closed = true;
    k_sem_give(&ch->ready);
}

/* Claim a table entry for @spdm_context. Called once per context from
 * mock_transport_install(), before that context is handed to libspdm,
 * so the table is fully populated before any callback can run. */
static struct loopback_endpoint *endpoint_bind(void *spdm_context,
                                               struct mock_transport *chan)
{
    k_spinlock_key_t key = k_spin_lock(&endpoints_lock);

    for (int i = 0; i < LOOPBACK_MAX_ENDPOINTS; i++) {
        if (endpoints[i].spdm_context == NULL) {
            endpoints[i].spdm_context = spdm_context;
            endpoints[i].chan = chan;
            endpoints[i].msg_buf_in_use = false;
            k_spin_unlock(&endpoints_lock, key);
            return &endpoints[i];
        }
    }

    k_spin_unlock(&endpoints_lock, key);
    printk("mock_transport: endpoint table full\n");
    return NULL;
}

/* Entries are never reassigned after endpoint_bind(), so no lock is
 * needed on this path even though the two roles run on separate threads. */
static struct loopback_endpoint *endpoint_find(void *spdm_context)
{
    for (int i = 0; i < LOOPBACK_MAX_ENDPOINTS; i++) {
        if (endpoints[i].spdm_context == spdm_context) {
            return &endpoints[i];
        }
    }
    return NULL;
}

static struct mock_transport *mock_transport_get(void *spdm_context)
{
    struct loopback_endpoint *ep = endpoint_find(spdm_context);

    return (ep != NULL) ? ep->chan : NULL;
}

static libspdm_return_t mock_send_message(void *spdm_context,
                                          size_t message_size,
                                          const void *message,
                                          uint64_t timeout)
{
    struct mock_transport *t = mock_transport_get(spdm_context);

    if (t == NULL || t->tx == NULL) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    if (message_size > sizeof(t->tx->buf)) {
        printk("mock_send: msg %zu > buf %zu\n", message_size,
               sizeof(t->tx->buf));
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    /* Wait for the slot to be drained by the peer. */
    if (k_sem_take(&t->tx->freed, K_MSEC(MOCK_TIMEOUT_MS)) != 0) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    memcpy(t->tx->buf, message, message_size);
    t->tx->len = message_size;
    k_sem_give(&t->tx->ready);
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t mock_receive_message(void *spdm_context,
                                             size_t *message_size,
                                             void **message,
                                             uint64_t timeout)
{
    struct mock_transport *t = mock_transport_get(spdm_context);

    if (t == NULL || t->rx == NULL) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    if (k_sem_take(&t->rx->ready, K_MSEC(MOCK_TIMEOUT_MS)) != 0) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (t->rx->closed) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (t->rx->len > *message_size) {
        printk("mock_recv: msg %zu > caller buf %zu\n", t->rx->len,
               *message_size);
        k_sem_give(&t->rx->freed);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    memcpy(*message, t->rx->buf, t->rx->len);
    *message_size = t->rx->len;
    t->rx->len = 0;
    k_sem_give(&t->rx->freed);
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t acquire_sender_buffer(void *spdm_context,
                                              void **msg_buf_ptr)
{
    struct loopback_endpoint *ep = endpoint_find(spdm_context);

    if (ep == NULL || ep->msg_buf_in_use) {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }
    ep->msg_buf_in_use = true;
    memset(ep->msg_buf, 0, sizeof(ep->msg_buf));
    *msg_buf_ptr = ep->msg_buf;
    return LIBSPDM_STATUS_SUCCESS;
}

static void release_sender_buffer(void *spdm_context, const void *msg_buf_ptr)
{
    struct loopback_endpoint *ep = endpoint_find(spdm_context);

    ARG_UNUSED(msg_buf_ptr);
    if (ep != NULL) {
        ep->msg_buf_in_use = false;
    }
}

static libspdm_return_t acquire_receiver_buffer(void *spdm_context,
                                                void **msg_buf_ptr)
{
    return acquire_sender_buffer(spdm_context, msg_buf_ptr);
}

static void release_receiver_buffer(void *spdm_context, const void *msg_buf_ptr)
{
    release_sender_buffer(spdm_context, msg_buf_ptr);
}

void mock_transport_install(void *spdm_context, struct mock_transport *t)
{
    if (endpoint_bind(spdm_context, t) == NULL) {
        return;
    }

    libspdm_register_device_io_func(spdm_context,
                                    mock_send_message,
                                    mock_receive_message);

    libspdm_register_transport_layer_func(
        spdm_context,
        SPDM_LOOPBACK_BUFFER_SIZE - SPDM_LOOPBACK_TRANSPORT_ADDITIONAL,
        SPDM_LOOPBACK_TRANSPORT_HEADER_SIZE,
        SPDM_LOOPBACK_TRANSPORT_TAIL_SIZE,
        libspdm_transport_mctp_encode_message,
        libspdm_transport_mctp_decode_message);

    libspdm_register_device_buffer_func(spdm_context,
                                        SPDM_LOOPBACK_BUFFER_SIZE,
                                        SPDM_LOOPBACK_BUFFER_SIZE,
                                        acquire_sender_buffer,
                                        release_sender_buffer,
                                        acquire_receiver_buffer,
                                        release_receiver_buffer);
}
