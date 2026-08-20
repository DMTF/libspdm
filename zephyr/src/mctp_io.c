/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 *
 *  Implementation of the MCTP IO declared in
 *  include/libspdm/zephyr/mctp_io.h.
 **/

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <libmctp.h>

#include "industry_standard/mctp.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_transport_mctp_lib.h"

#include "libspdm/zephyr/mctp_io.h"

LOG_MODULE_REGISTER(libspdm_mctp_io, CONFIG_LIBSPDM_MCTP_LOG_LEVEL);

/* Tag used for requests this node originates. libspdm keeps at most one
 * request in flight, so a single tag is sufficient and stays within the
 * MCTP rule that a tag owner must not reuse a tag for a second
 * outstanding request. libmctp's mctp_message_tx_request() would pick a
 * tag for us, but it takes ownership of a heap-allocated buffer and can
 * fail with -EBUSY once tags run out, neither of which buys anything
 * here: libmctp delivers responses to its rx callback regardless of
 * whether the tag was allocated through it.
 */
#define MCTP_IO_REQUEST_TAG 0U

/* How long to wait between retries when an asynchronous binding reports
 * that a previous packet is still in flight.
 */
#define MCTP_IO_TX_RETRY_INTERVAL_US 200U

/* libspdm doesn't carry a per-context opaque pointer slot, so we keep
 * a small static map between spdm_context and our instance.
 */
struct mctp_io_map_entry {
    const void *spdm_context;
    struct libspdm_zephyr_mctp_io *io;
};

static struct mctp_io_map_entry mctp_io_map[CONFIG_LIBSPDM_MCTP_MAX_CONTEXTS];
static struct k_spinlock mctp_io_map_lock;

static int mctp_io_map_insert(const void *spdm_context,
                              struct libspdm_zephyr_mctp_io *io)
{
    k_spinlock_key_t key = k_spin_lock(&mctp_io_map_lock);
    struct mctp_io_map_entry *free_slot = NULL;

    for (size_t i = 0U; i < ARRAY_SIZE(mctp_io_map); i++) {
        if (mctp_io_map[i].spdm_context == spdm_context) {
            /* Re-registering a context replaces its association
             * rather than consuming a second slot. */
            mctp_io_map[i].io = io;
            k_spin_unlock(&mctp_io_map_lock, key);
            return 0;
        }
        if (free_slot == NULL && mctp_io_map[i].spdm_context == NULL) {
            free_slot = &mctp_io_map[i];
        }
    }

    if (free_slot != NULL) {
        free_slot->spdm_context = spdm_context;
        free_slot->io = io;
        k_spin_unlock(&mctp_io_map_lock, key);
        return 0;
    }

    k_spin_unlock(&mctp_io_map_lock, key);
    return -ENOMEM;
}

static int mctp_io_map_remove(const void *spdm_context)
{
    k_spinlock_key_t key = k_spin_lock(&mctp_io_map_lock);
    int ret = -ENOENT;

    for (size_t i = 0U; i < ARRAY_SIZE(mctp_io_map); i++) {
        if (mctp_io_map[i].spdm_context == spdm_context) {
            mctp_io_map[i].spdm_context = NULL;
            mctp_io_map[i].io = NULL;
            ret = 0;
            break;
        }
    }

    k_spin_unlock(&mctp_io_map_lock, key);
    return ret;
}

static struct libspdm_zephyr_mctp_io *mctp_io_map_lookup(const void *spdm_context)
{
    struct libspdm_zephyr_mctp_io *io = NULL;
    k_spinlock_key_t key = k_spin_lock(&mctp_io_map_lock);

    for (size_t i = 0U; i < ARRAY_SIZE(mctp_io_map); i++) {
        if (mctp_io_map[i].spdm_context == spdm_context) {
            io = mctp_io_map[i].io;
            break;
        }
    }

    k_spin_unlock(&mctp_io_map_lock, key);
    return io;
}

static bool mctp_io_is_spdm_message(const void *msg, size_t len)
{
    uint8_t type;

    if (len < 1U) {
        return false;
    }

    type = ((const uint8_t *)msg)[0] & 0x7FU;
    return (type == MCTP_MESSAGE_TYPE_SPDM) ||
           (type == MCTP_MESSAGE_TYPE_SECURED_MCTP);
}

static void rx_message_cb(uint8_t eid, bool tag_owner, uint8_t msg_tag,
                          void *data, void *msg, size_t len)
{
    struct libspdm_zephyr_mctp_io *io = data;
    struct libspdm_zephyr_mctp_io_rx_desc desc;
    int rc;

    if (io == NULL) {
        LOG_ERR("rx callback fired without an io pointer");
        return;
    }

    if (len == 0U || len > LIBSPDM_ZEPHYR_MCTP_BUFFER_SIZE) {
        LOG_WRN("dropping rx of unsupported length %zu (max %u)",
                len, (unsigned int)LIBSPDM_ZEPHYR_MCTP_BUFFER_SIZE);
        return;
    }

    if (!mctp_io_is_spdm_message(msg, len)) {
        LOG_DBG("ignoring non-SPDM message type 0x%02x from eid %u",
                ((const uint8_t *)msg)[0], eid);
        return;
    }

    /* Copy into a pool block */
    rc = k_mem_slab_alloc(&io->rx_slab, &desc.buf, K_NO_WAIT);
    if (rc != 0) {
        LOG_WRN("rx pool exhausted, dropping msg from eid %u (len %zu)",
                eid, len);
        return;
    }

    desc.len = len;
    desc.src_eid = eid;
    desc.msg_tag = msg_tag;
    desc.tag_owner = tag_owner;
    memcpy(desc.buf, msg, len);

    rc = k_msgq_put(&io->rx_msgq, &desc, K_NO_WAIT);
    if (rc != 0) {
        k_mem_slab_free(&io->rx_slab, desc.buf);
        LOG_WRN("rx queue full, dropping msg from eid %u (len %zu)",
                eid, len);
    }
}

/* Transmit one message, retrying while an asynchronous binding reports
 * a packet still in flight. libspdm passes the requester's RTT as the
 * timeout; a responder passes 0, which means "do not time out".
 */
static int mctp_io_tx(struct libspdm_zephyr_mctp_io *io, uint8_t dest_eid,
                      bool tag_owner, uint8_t msg_tag, const void *message,
                      size_t message_size, uint64_t timeout)
{
    int64_t start = k_uptime_ticks();
    int rc;

    for (;;) {
        rc = mctp_message_tx(io->mctp_ctx, dest_eid, tag_owner, msg_tag,
                             message, message_size);
        if (rc != -EBUSY) {
            return rc;
        }

        if (timeout != 0U &&
            (uint64_t)k_ticks_to_us_floor64(k_uptime_ticks() - start) >=
            timeout) {
            LOG_ERR("tx to eid %u still busy after %llu us",
                    dest_eid, timeout);
            return -EBUSY;
        }

        k_sleep(K_USEC(MCTP_IO_TX_RETRY_INTERVAL_US));
    }
}

static libspdm_return_t mctp_io_device_send_message(void *spdm_context,
                                                    size_t message_size,
                                                    const void *message,
                                                    uint64_t timeout)
{
    struct libspdm_zephyr_mctp_io *io = mctp_io_map_lookup(spdm_context);
    uint8_t dest_eid;
    uint8_t msg_tag;
    bool tag_owner;
    int rc;

    if (io == NULL) {
        LOG_ERR("send_message: no MCTP IO for ctx=%p", spdm_context);
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    if (message_size == 0U || message_size > LIBSPDM_ZEPHYR_MCTP_BUFFER_SIZE) {
        LOG_ERR("send_message: bad size %zu", message_size);
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    if (io->reply_pending) {
        /* Answering a request: back to its sender, same tag, TO
         * cleared. */
        dest_eid = io->reply_eid;
        msg_tag = io->reply_tag;
        tag_owner = false;
    } else {
        /* Originating a request: we own the tag. */
        dest_eid = io->peer_eid;
        msg_tag = MCTP_IO_REQUEST_TAG;
        tag_owner = true;
    }

    rc = mctp_io_tx(io, dest_eid, tag_owner, msg_tag, message, message_size,
                    timeout);
    if (rc != 0) {
        LOG_ERR("mctp_message_tx to eid %u failed: %d", dest_eid, rc);
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    /* The response is out; the request it answered is now settled. */
    io->reply_pending = false;

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t mctp_io_device_receive_message(void *spdm_context,
                                                       size_t *message_size,
                                                       void **message,
                                                       uint64_t timeout)
{
    struct libspdm_zephyr_mctp_io *io = mctp_io_map_lookup(spdm_context);
    struct libspdm_zephyr_mctp_io_rx_desc desc;
    libspdm_return_t status;
    k_timeout_t to;
    int rc;

    if (io == NULL) {
        LOG_ERR("receive_message: no MCTP IO for ctx=%p", spdm_context);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    if (message == NULL || message_size == NULL || *message == NULL) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* libspdm passes timeout in microseconds; 0 means "block forever". */
    if (timeout == 0U) {
        to = K_FOREVER;
    } else {
        to = K_USEC((int64_t)timeout);
    }

    rc = k_msgq_get(&io->rx_msgq, &desc, to);
    if (rc == -EAGAIN || rc == -ENOMSG) {
        /* Timeout or empty queue -- surface as receive-fail so
         * the libspdm dispatcher can treat it as end-of-stream. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (rc != 0) {
        LOG_ERR("k_msgq_get returned %d", rc);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* From here on the block is ours: every path must free it. */
    if (desc.len > *message_size) {
        LOG_ERR("rx message len %zu exceeds caller buffer %zu",
                desc.len, *message_size);
        status = LIBSPDM_STATUS_RECEIVE_FAIL;
        goto out_free;
    }

    /* A message that owns its tag is a request directed at us, so the
     * next thing libspdm sends is its response: remember where it has
     * to go. A message that doesn't is the response to a request we
     * originated and needs no reply context.
     */
    if (desc.tag_owner) {
        io->reply_eid = desc.src_eid;
        io->reply_tag = desc.msg_tag;
        io->reply_pending = true;
    }

    memcpy(*message, desc.buf, desc.len);
    *message_size = desc.len;
    status = LIBSPDM_STATUS_SUCCESS;

out_free:
    k_mem_slab_free(&io->rx_slab, desc.buf);
    return status;
}

static libspdm_return_t mctp_io_acquire_sender_buffer(void *spdm_context,
                                                      void **msg_buf_ptr)
{
    struct libspdm_zephyr_mctp_io *io = mctp_io_map_lookup(spdm_context);

    if (io == NULL || msg_buf_ptr == NULL) {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }
    if (io->send_buf_in_use) {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }

    io->send_buf_in_use = true;
    *msg_buf_ptr = io->send_buf;
    return LIBSPDM_STATUS_SUCCESS;
}

static void mctp_io_release_sender_buffer(void *spdm_context,
                                          const void *msg_buf_ptr)
{
    struct libspdm_zephyr_mctp_io *io = mctp_io_map_lookup(spdm_context);

    ARG_UNUSED(msg_buf_ptr);
    if (io == NULL) {
        return;
    }

    io->send_buf_in_use = false;
}

static libspdm_return_t mctp_io_acquire_receiver_buffer(void *spdm_context,
                                                        void **msg_buf_ptr)
{
    struct libspdm_zephyr_mctp_io *io = mctp_io_map_lookup(spdm_context);

    if (io == NULL || msg_buf_ptr == NULL) {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }
    if (io->recv_buf_in_use) {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }

    io->recv_buf_in_use = true;
    *msg_buf_ptr = io->recv_buf;
    return LIBSPDM_STATUS_SUCCESS;
}

static void mctp_io_release_receiver_buffer(void *spdm_context,
                                            const void *msg_buf_ptr)
{
    struct libspdm_zephyr_mctp_io *io = mctp_io_map_lookup(spdm_context);

    ARG_UNUSED(msg_buf_ptr);
    if (io == NULL) {
        return;
    }

    io->recv_buf_in_use = false;
}

int libspdm_zephyr_mctp_io_init(struct libspdm_zephyr_mctp_io *io,
                                struct mctp *mctp_ctx, uint8_t peer_eid)
{
    int rc;

    if (io == NULL || mctp_ctx == NULL) {
        return -EINVAL;
    }

    memset(io, 0, sizeof(*io));
    io->mctp_ctx = mctp_ctx;
    io->peer_eid = peer_eid;

    rc = k_mem_slab_init(&io->rx_slab, io->rx_pool,
                         LIBSPDM_ZEPHYR_MCTP_RX_BLOCK_SIZE,
                         LIBSPDM_ZEPHYR_MCTP_RX_QUEUE_DEPTH);
    if (rc != 0) {
        LOG_ERR("k_mem_slab_init failed: %d", rc);
        return rc;
    }

    k_msgq_init(&io->rx_msgq, io->rx_msgq_storage,
                sizeof(struct libspdm_zephyr_mctp_io_rx_desc),
                LIBSPDM_ZEPHYR_MCTP_RX_QUEUE_DEPTH);

    if (mctp_set_rx_all(mctp_ctx, rx_message_cb, io) != 0) {
        return -EIO;
    }
    return 0;
}

int libspdm_zephyr_mctp_io_register(void *spdm_context,
                                    struct libspdm_zephyr_mctp_io *io)
{
    int rc;

    if (spdm_context == NULL || io == NULL) {
        return -EINVAL;
    }

    rc = mctp_io_map_insert(spdm_context, io);
    if (rc != 0) {
        return rc;
    }

    libspdm_register_device_io_func(spdm_context,
                                    mctp_io_device_send_message,
                                    mctp_io_device_receive_message);

    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_ZEPHYR_MCTP_BUFFER_SIZE,
                                        LIBSPDM_ZEPHYR_MCTP_BUFFER_SIZE,
                                        mctp_io_acquire_sender_buffer,
                                        mctp_io_release_sender_buffer,
                                        mctp_io_acquire_receiver_buffer,
                                        mctp_io_release_receiver_buffer);

    /* The transport codec is a property of this layer, not of the
     * application: register it here so every MCTP app doesn't have to
     * repeat the same four arguments.
     */
    libspdm_register_transport_layer_func(spdm_context,
                                          LIBSPDM_ZEPHYR_MCTP_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_mctp_encode_message,
                                          libspdm_transport_mctp_decode_message);
    return 0;
}

int libspdm_zephyr_mctp_io_unregister(void *spdm_context)
{
    if (spdm_context == NULL) {
        return -EINVAL;
    }

    return mctp_io_map_remove(spdm_context);
}
