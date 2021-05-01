# This openspdm is a sample implementation for the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

## Feature

1) Specification

   The SPDM and secured message follow :

   DSP0274  Security Protocol and Data Model (SPDM) Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.0.pdf) and version [1.1.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0.pdf))

   DSP0277  Secured Messages using SPDM Specification (version [1.0.0b](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.0b.pdf))

   The MCTP and secured MCTP follow :

   DSP0275  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   DSP0276  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0a](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0a.pdf))

   The PCI DOE / IDE follow :

   PCI  Data Object Exchange (DOE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14143)

   PCI  Component Measurement and Authentication (CMA) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14236)

   PCI  Integrity and Data Encryption (IDE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/15149)

2) Both SPDM requester and SPDM responder.

3) Programming Context:

   No heap is required in the SPDM lib.
   No writable global variable is required in the SPDM lib. 

4) Implemented command and response: 

   SPDM 1.0: GET_VERSION, GET_CAPABILITY, NEGOTIATE_ALGORITHM, GET_DIGEST, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENT.

   SPDM 1.1: KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH, END_SESSION, HEARTBEAT, KEY_UPDATE, ENCAPSULATED message

5) Cryptographic algorithm support:

   The SPDM lib requires [cryptolib API](https://github.com/DMTF/Libspdm/blob/main/libspdm/include/hal/library/cryptlib.h), including random number, symmetric crypto, asymmetric crypto, hash and message authentication code etc.

   Current support algorithm: SHA-2, RSA-SSA/ECDSA, FFDHE/ECDHE, AES_GCM/ChaCha20Poly1305, HMAC.

   An [mbedtls](https://tls.mbed.org/) wrapper is included in [cryptlib_mbedtls](https://github.com/DMTF/libspdm/tree/main/libspdm/os_stub/cryptlib_mbedtls).

   An [openssl](https://www.openssl.org/) wrapper is included in [cryptlib_openssl](https://github.com/DMTF/libspdm/tree/main/libspdm/os_stub/cryptlib_openssl).

6) Execution context:

   Support to build an OS application for spdm_requester_emu and SpdmResponder_emu to trace the communication.

   Support to be included in UEFI host environment [EDKII](https://github.com/tianocore/edk2), such as [edkii_spdm_requester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

   Support to be included in [OpenBMC](https://github.com/openbmc). It is in planning, see [SPDM Integration](https://www.youtube.com/watch?v=PmgXkLJYI-E).

## Document

1) Presentation

   Open Source Firmware Conference 2020 - [openspdm](https://cfp.osfc.io/osfc2020/talk/ECQ88N/)

   Free and Open Source Developers European Meeting 2021 - [openspdm](https://fosdem.org/2021/schedule/event/firmware_uoifaaffsdc/)

2) openspdm library threat model:

   The user guide can be found at [threat_model](https://github.com/DMTF/Libspdm/blob/main/libspdm/doc/threat_model.md)

3) openspdm library design:

   The detailed design can be found at [design](https://github.com/DMTF/Libspdm/blob/main/libspdm/doc/design.md)

4) openspdm user guide:

   The user guide can be found at [user_guide](https://github.com/DMTF/Libspdm/blob/main/libspdm/doc/user_guide.md)

## Prerequisit

### Build Tool

1) [Visual Studio](https://visualstudio.microsoft.com/) (VS2015 or VS2019)

2) [GCC](https://gcc.gnu.org/) (above GCC5)

3) [LLVM](https://llvm.org/) (LLVM9)

   Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

4) [cmake](https://cmake.org/).

### Crypto library

1) [mbedtls](https://tls.mbed.org) as Crypto library. Version 2.16.6.

2) [openssl](https://www.openssl.org) as crypto library. Version 1.1.1g.

### Unit Test framework

1) [cmocka](https://cmocka.org/). Version 1.1.5.

## Build

### Git Submodule

   libspdm uses submodules for mbedtls, openssl and cmocka.

   To get a full buildable repo, please use `git submodule update --init`.
   If there is an update for submodules, please use `git submodule update`.

### Windows Build with CMake

   Use x86 command prompt for ARCH=ia32 and x64 command prompt for ARCH=x64. (TOOLCHAIN=VS2019|VS2015|CLANG)
   ```
   cd <libspdm|spdm_emu|spdm_dump>
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   nmake copy_sample_key
   nmake
   ```

### Linux Build with CMake

   (TOOLCHAIN=GCC|CLANG)
   ```
   cd <libspdm|spdm_emu|spdm_dump>
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

## Run Test

### Run [unit_test](https://github.com/DMTF/libspdm/tree/main/libspdm/unit_test)

   The UnitTest output is at libspdm/build/bin.
   Open one command prompt at output dir to run `test_spdm_requester > NUL` and `test_spdm_responder > NUL`.

   You may see something like:

   <pre>
      [==========] Running 2 test(s).
      [ RUN      ] test_spdm_responder_version_case1
      [       OK ] test_spdm_responder_version_case1
      [ RUN      ] test_spdm_responder_version_case2
      [       OK ] test_spdm_responder_version_case2
      [==========] 2 test(s) run.
      [  PASSED  ] 2 test(s).
   </pre>

### Run [spdm_emu](https://github.com/DMTF/spdm-emu/tree/main/spdm_emu/spdm_emu)

   The spdm_emu output is at spdm_emu/build/bin.
   Open one command prompt at output dir to run `spdm_responder_emu` and another command prompt to run `spdm_requester_emu`.

   Please refer to [spdm_emu](https://github.com/DMTF/spdm-emu/blob/main/spdm_emu/doc/spdm_emu.md) for detail.

### [spdm_dump](https://github.com/DMTF/spdm-dump/tree/main/spdm_dump/spdm_dump) tool

   The tool output is at spdm_dump/build/bin. It can be used to parse the pcap file for offline analysis.

   Please refer to [spdm_dump](https://github.com/DMTF/spdm-dump/blob/main/spdm_dump/doc/spdm_dump.md) for detail. 

### Other Test

  openspdm also supports other test such as code coverage, fuzzing, symbolic execution, model checker.

  Please refer to [test](https://github.com/DMTF/libspdm/blob/main/libspdm/doc/test.md) for detail. 

## Feature not implemented yet

1) Please refer to [issues](https://github.com/DMTF/libspdm/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

