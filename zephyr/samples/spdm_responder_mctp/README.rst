.. zephyr:code-sample:: spdm_responder_mctp
   :name: libspdm responder over MCTP-I3C
   :relevant-api: spdm_common spdm_responder spdm_transport_mctp

   Run an SPDM responder on top of MCTP over an I3C bus, paired with
   the ``spdm_requester_mctp`` sample on a second board.

Overview
********

This sample exercises the libspdm Zephyr module's MCTP transport
binding. It implements an SPDM responder that communicates with a requester
over MCTP. The sample demonstrates how to set up the SPDM responder, which
then loops to receive requests, and handle responses using the libspdm API.
The MCTP transport is over an I3C bus. It was tested on a NPCX4.

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

   west build -b npcx4m8f_evb spdm_responder_mctp  -- -DEXTRA_ZEPHYR_MODULES=<path-to-libspdm>
   west flash

Expected output
***************

.. code-block:: console

   *** Booting Zephyr OS build v4.4.0-6198-g603fc3624d1b ***
   [00:00:00.000,000] <inf> spdm_responder_mctp: SPDM responder on npcx4m8f_evb/npcx4m8f
   [00:00:00.000,000] <inf> spdm_responder_mctp: local EID=11
   [00:00:02.586,000] <inf> spdm_responder_mctp: entering responder dispatch loop
   [00:00:11.674,000] <inf> spdm_responder_mctp: received an SPDM request and sent a response
   (...)
   [00:03:13.198,000] <inf> spdm_responder_mctp: received secured app request "ping", replying "pong"
