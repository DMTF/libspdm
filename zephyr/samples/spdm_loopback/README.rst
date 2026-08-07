.. zephyr:code-sample:: spdm_loopback
   :name: libspdm loopback
   :relevant-api: spdm_common spdm_requester spdm_responder spdm_transport_mctp

   In-process SPDM requester <-> responder demo using libspdm on Zephyr.

Overview
********

This sample exercises the `libspdm <https://github.com/DMTF/libspdm>`_
Zephyr module by running an SPDM requester and an SPDM responder side
by side, in two threads of the same Zephyr application, talking through
a pair of synchronised buffers.

It performs the basic SPDM negotiation up to authenticating the responder.

Building and running
********************

The module ``libspdm`` needs to be discoverable by the build system. One
way to achieve this is by setting ``EXTRA_ZEPHYR_MODULES``. For instance,
from the samples directory:

.. code-block:: console

   west build -b qemu_x86_64 spdm_loopback -- -DEXTRA_ZEPHYR_MODULES=<path-to-libspdm>
   west build -t run

Expected output
***************

.. code-block:: console

   ** Booting Zephyr OS build v4.4.0-6198-g603fc3624d1b ***

   libspdm Zephyr loopback demo
   ============================
   [responder] starting
   [responder] ready, scratch=26496 bytes
   [requester] starting
   [requester] ready, scratch=26496 bytes
   [responder] received a request and sent a response
   [requester] GET_VERSION ok
   [responder] received a request and sent a response
   [responder] received a request and sent a response
   [responder] received a request and sent a response
   [requester] GET_CAPABILITIES + NEGOTIATE_ALGORITHMS ok
   [responder] received a request and sent a response
   [requester] GET_DIGESTS ok, slot_mask=0x01
   [responder] received a request and sent a response
   [requester] GET_CERTIFICATE ok, chain_size=1390
   [responder] received a request and sent a response
   [requester] CHALLENGE_AUTH ok
   [requester] *** SPDM authenticated handshake PASSED ***
   [responder] no more requests, exiting

   libspdm Zephyr loopback demo: main exiting
