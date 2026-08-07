/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_LOOPBACK_H
#define SPDM_LOOPBACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>

/*
 * Buffer sizing.
 *
 * libspdm wants a contiguous send/receive buffer per side that is
 * large enough to hold the biggest SPDM message plus the transport
 * overhead. Keep it conservative for the loopback demo so we fit
 * inside Zephyr's default malloc/heap budget.
 */
#define SPDM_LOOPBACK_TRANSPORT_HEADER_SIZE   64
#define SPDM_LOOPBACK_TRANSPORT_TAIL_SIZE     64
#define SPDM_LOOPBACK_TRANSPORT_ADDITIONAL    (SPDM_LOOPBACK_TRANSPORT_HEADER_SIZE + \
                                               SPDM_LOOPBACK_TRANSPORT_TAIL_SIZE)
#define SPDM_LOOPBACK_BUFFER_SIZE             (0x1100 + SPDM_LOOPBACK_TRANSPORT_ADDITIONAL)

/*
 * Mock loopback transport.
 *
 * One mock_transport instance holds a TX channel and an RX channel.
 * The requester and responder each hold a pointer to one instance,
 * with their TX/RX swapped relative to each other.
 *
 * Send is non-blocking on a free slot, blocks if the previous message
 * has not been consumed yet. Receive blocks until data is available.
 */
struct mock_channel {
    uint8_t buf[SPDM_LOOPBACK_BUFFER_SIZE];
    size_t len;
    struct k_sem ready;   /* posted by sender after writing buf */
    struct k_sem freed;   /* posted by receiver after consuming */
    bool closed;          /* set by mock_channel_close() */
};

struct mock_transport {
    struct mock_channel *tx;   /* this side writes here */
    struct mock_channel *rx;   /* this side reads from here */
};

void mock_channel_init(struct mock_channel *ch);

/* Wake any reader blocked on this channel and make every subsequent
 * receive fail immediately, so the peer thread can wind down without
 * waiting out the receive timeout.
 */
void mock_channel_close(struct mock_channel *ch);

/* Attach t to spdm_context and register the libspdm device-IO, MCTP
 * framing and device-buffer callbacks on it.
 */
void mock_transport_install(void *spdm_context, struct mock_transport *t);

/* Posted by the responder once it can serve requests, waited on by the
 * requester before it sends GET_VERSION.
 */
extern struct k_sem responder_ready;

#define SPDM_LOOPBACK_READY_TIMEOUT K_SECONDS(10)

/* Roles. Each runs on its own Zephyr thread. */
void responder_thread_main(void *a, void *b, void *c);
void requester_thread_main(void *a, void *b, void *c);

#endif /* SPDM_LOOPBACK_H */
