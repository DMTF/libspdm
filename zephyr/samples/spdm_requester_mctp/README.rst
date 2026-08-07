.. zephyr:code-sample:: spdm_requester_mctp
   :name: libspdm requester over MCTP
   :relevant-api: spdm_common spdm_requester spdm_transport_mctp

   Run an SPDM requester on top of MCTP over an I3C bus, paired with
   the ``spdm_responder_mctp`` sample on a second board.

Overview
********

This sample exercises the libspdm Zephyr module's MCTP transport
binding. It implements an SPDM requester that communicates with a responder
over MCTP. The sample demonstrates how to set up the SPDM requester, send
requests, and handle responses using the libspdm API. The MCTP transport is
over an I3C bus. It was tested on a NPCX4.

Wiring
******

Check board overlay files for more details on how to wire the boards
together.

Building and Running
********************

The module ``libspdm`` needs to be discoverable by the build system. One
way to achieve this is by setting ``EXTRA_ZEPHYR_MODULES``. For instance,
from the samples directory:


.. code-block:: console

   west build -b npcx4m8f_evb spdm_requester_mctp  -- -DEXTRA_ZEPHYR_MODULES=<path-to-libspdm>
   west flash

Expected output
***************

.. code-block:: console

   *** Booting Zephyr OS build v4.4.0-6198-g603fc3624d1b ***
   [00:00:00.001,000] <inf> spdm_requester_mctp: SPDM requester on npcx4m8f_evb/npcx4m8f
   [00:00:00.001,000] <inf> spdm_requester_mctp: local EID=20, peer EID=11
   [00:00:00.001,000] <inf> mctp_i3c_controller: Enabling IBI for TARGET 0x200c10e0 PID 20a00000011 BCR 6
   [00:00:02.577,000] <inf> spdm_requester_mctp: issuing GET_VERSION
   [00:00:02.580,000] <inf> spdm_requester_mctp: GET_VERSION ok
   [00:00:02.580,000] <inf> spdm_requester_mctp: issuing GET_CAPABILITIES + NEGOTIATE_ALGORITHMS
   [00:00:02.590,000] <inf> spdm_requester_mctp: GET_CAPABILITIES + NEGOTIATE_ALGORITHMS ok
   [00:00:02.597,000] <inf> spdm_requester_mctp: GET_DIGESTS ok, slot_mask=0x01
   [00:00:05.209,000] <inf> spdm_requester_mctp: GET_CERTIFICATE ok, chain_size=1390
   [00:00:06.876,000] <inf> spdm_requester_mctp: CHALLENGE_AUTH ok
   [00:00:06.876,000] <inf> spdm_requester_mctp: *** SPDM authenticated handshake PASSED ***
   [00:00:06.876,000] <inf> spdm_requester_mctp: starting secure session + ping/pong
   [00:00:10.847,000] <inf> spdm_requester_mctp: sent "ping", received "pong"
   [00:00:10.856,000] <inf> spdm_requester_mctp: *** SPDM session ping/pong PASSED ***
