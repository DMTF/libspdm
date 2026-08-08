libspdm Zephyr module
=====================

This directory contains the necessary bits so that Zephyr RTOS based applications
can use libspdm as a module. Besides the normal Zephyr module bits: ``module.yml``,
``Kconfig`` and ``CMakeLists.txt``, this directory also contains some code.

There is basically two parts to this code:

 - Code that implements the APIs libspdm expects in terms of Zephyr
   APIs. This code is in the ``src/`` and ``include`` directory.
 - Some Zephyr application samples that use libspdm. This code is in the ``samples/``
   directory. More details on how to build and run (or flash) the samples are
   available at each sample directory.
