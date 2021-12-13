# libspdm is a sample implementation that follows the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

## Feature

1) Specification

   The SPDM and secured message follow :

   [DSP0274](https://www.dmtf.org/dsp/DSP0274)  Security Protocol and Data Model (SPDM) Specification (version [1.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.1.pdf) and version [1.1.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf))

   [DSP0277](https://www.dmtf.org/dsp/DSP0277)  Secured Messages using SPDM Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.0.pdf))

   The MCTP and secured MCTP follow :

   [DSP0275](https://www.dmtf.org/dsp/DSP0275)  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   [DSP0276](https://www.dmtf.org/dsp/DSP0276)  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0.pdf))

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

   The SPDM lib requires [cryptolib API](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h), including random number, symmetric crypto, asymmetric crypto, hash and message authentication code etc.

   Current support algorithm: SHA-2, RSA-SSA/ECDSA, FFDHE/ECDHE, AES_GCM/ChaCha20Poly1305, HMAC.

   An [mbedtls](https://tls.mbed.org/) wrapper is included in [cryptlib_mbedtls](https://github.com/DMTF/libspdm/tree/main/os_stub/mbedtlslib).

   An [openssl](https://www.openssl.org/) wrapper is included in [cryptlib_openssl](https://github.com/DMTF/libspdm/tree/main/os_stub/openssllib).

6) Execution context:

   Support to build an OS application for spdm_requester_emu and SpdmResponder_emu to trace the communication.

   Support to be included in UEFI host environment [EDKII](https://github.com/tianocore/edk2), such as [edkii_spdm_requester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

   Support to be included in [OpenBMC](https://github.com/openbmc). It is in planning, see [SPDM Integration](https://www.youtube.com/watch?v=PmgXkLJYI-E).

## Documents

1) Presentation

   Open Source Firmware Conference 2020 - [openspdm](https://cfp.osfc.io/osfc2020/talk/ECQ88N/)

   Free and Open Source Developers European Meeting 2021 - [openspdm](https://fosdem.org/2021/schedule/event/firmware_uoifaaffsdc/)

2) libspdm library threat model:

   The user guide can be found at [threat_model](https://github.com/DMTF/libspdm/blob/main/doc/threat_model.md)

3) libspdm library design:

   The detailed design can be found at [design](https://github.com/DMTF/libspdm/blob/main/doc/design.md)

4) libspdm user guide:

   The user guide can be found at [user_guide](https://github.com/DMTF/libspdm/blob/main/doc/user_guide.md)

## Prerequisites

### Build Tools for Windows

1) Compiler (Choose one)

    a) [Visual Studio 2019](https://visualstudio.microsoft.com/)

    b) [Visual Studio 2015](https://visualstudio.microsoft.com/) 

    c) [LLVM](https://llvm.org/) (LLVM9)
Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

2) [cmake](https://cmake.org/) (Version [3.17.2](https://github.com/Kitware/CMake/releases/tag/v3.17.2) is known to work. Newer versions may fail).

### Build Tools for Linux

1) Compiler (Choose one)

    a) [GCC](https://gcc.gnu.org/) (above GCC5)

    b) [LLVM](https://llvm.org/) (above LLVM10), install steps: `sudo apt-get install llvm-10` then `sudo apt-get install clang-10`. Use `llvm-ar -version` and `clang -v` to confirm the LLVM version. If LLVM  installation fails or LLVM installation version is low, you can update Linux version to fix the issue.

2) [cmake](https://cmake.org/).


### Crypto library

1) [mbedtls](https://tls.mbed.org) as Crypto library. Version 2.27.0.

2) [openssl](https://www.openssl.org) as crypto library. Version 1.1.1l.

### Unit Test framework

1) [cmocka](https://cmocka.org/). Version 1.1.5.

## Build

### Git Submodule

   libspdm uses submodules for mbedtls, openssl and cmocka.

   To get a full buildable repo, please use `git submodule update --init`.
   If there is an update for submodules, please use `git submodule update`.

### Windows Builds
   For ia32 builds, use a `x86 Native Tools Command Prompt for Visual Studio...` command prompt.

   For x64 builds, use a `x64 Native Tools Command Prompt for Visual Studio...` command prompt.

   General build steps: (Note the `..` at the end of the cmake command). 
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<VS2019|VS2015|CLANG> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   nmake copy_sample_key
   nmake
   ```

   Example cmake commands: (Note the `..` at the end of the cmake command). 
   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=openssl ..
   
   cmake -G"NMake Makefiles" -DARCH=ia32 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=mbedtls ..
   
   ```

### Linux Builds
   If ia32 builds on 64 bit Linux machine, need install `sudo apt-get install gcc-multilib`.

   General build steps: (Note the `..` at the end of the cmake command).
  
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<GCC|CLANG> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```
Example cmake commands: (Note the `..` at the end of the cmake command). 
   ```
   cmake -DARCH=arm -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=openssl ..
   
   cmake -DARCH=x64 -DTOOLCHAIN=CLANG -DTARGET=Release -DCRYPTO=mbedtls ..
   
   ```

## Run Test

### Run [unit_test](https://github.com/DMTF/libspdm/tree/main/unit_test)

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

   Note: You MUST use a command prompt with the current working directory at libspdm/build/bin when running ULTs or they may fail.
   Eg. Don't run the ULT from libsdpm/build directory by calling "bin/test_spdm_responder > NULL"
   
### Run [spdm_emu](https://github.com/DMTF/spdm-emu)

   The spdm_emu output is at spdm_emu/build/bin.
   Open one command prompt at output dir to run `spdm_responder_emu`. Then open another command prompt to run `spdm_requester_emu`.

   Please refer to [spdm_emu](https://github.com/DMTF/spdm-emu/blob/main/doc/spdm_emu.md) for detail.

### [spdm_dump](https://github.com/DMTF/spdm-dump) tool

   The tool output is at spdm_dump/build/bin. It can be used to parse the pcap file for offline analysis.

   Please refer to [spdm_dump](https://github.com/DMTF/spdm-dump/blob/main/doc/spdm_dump.md) for detail. 

### Other Test

  libspdm also supports other test such as code coverage, fuzzing, symbolic execution, model checker.

  Please refer to [test](https://github.com/DMTF/libspdm/blob/main/doc/test.md) for detail. 

## Features not implemented yet

1) Please refer to [issues](https://github.com/DMTF/libspdm/issues) for detail

## Known limitations
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the library and the drivers are subject to change.
