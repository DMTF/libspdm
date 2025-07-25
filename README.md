# DMTF's Reference Implementation of [SPDM](https://www.dmtf.org/standards/spdm)

## Features

1) Specifications

   The SPDM and secured message libraries follow :

   [DSP0274](https://www.dmtf.org/dsp/DSP0274)  Security Protocol and Data Model (SPDM) Specification (version [1.0.2](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.2.pdf), version [1.1.4](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.4.pdf), version [1.2.3](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.3.pdf) and version [1.3.2](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.2.pdf))

   [DSP0277](https://www.dmtf.org/dsp/DSP0277)  Secured Messages using SPDM Specification (version [1.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.1.pdf), version [1.1.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.1.1.pdf), version [1.2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf))

   MCTP and secured MCTP follow :

   [DSP0275](https://www.dmtf.org/dsp/DSP0275)  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.2](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.2.pdf))

   [DSP0276](https://www.dmtf.org/dsp/DSP0276)  Secured Messages using SPDM over MCTP Binding Specification (version [1.2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.2.0.pdf))

   Storage Binding follows :

   [DSP0286](https://www.dmtf.org/dsp/DSP0286)  Security Protocol and Data Model (SPDM) to Storage Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0286_1.0.0.pdf))

   TCP Binding follows :

   [DSP0287](https://www.dmtf.org/dsp/DSP0287)  SPDM over TCP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0287_1.0.0.pdf))

   PCIe follows :

   PCI Express Base Specification [Revision 6.2](https://members.pcisig.com/wg/PCI-SIG/document/20590)

   CXL follows :

   Compute Express Link Specification [Revision 3.1](https://computeexpresslink.org/cxl-specification)

2) Includes libraries that can be used to construct an SPDM Requester and an SPDM Responder.

   Refer to the [libspdm API](https://github.com/DMTF/libspdm/tree/main/doc/api) for more information.

3) Programming Context

   The core libraries in `libspdm/library` require only the C99 freestanding headers and so are suitable for embedded and systems programming. Any functionality beyond the freestanding headers is provided by `libspdm/os_stub` or by the library's Integrator. All statically allocated memory in the core libraries is read-only. The core libraries do not dynamically allocate memory.

   Refer to [programming environment](https://github.com/DMTF/libspdm/blob/main/doc/programming_environment.md) for more information.

4) Implemented Requests and Responses

   SPDM 1.0: `GET_VERSION`, `GET_CAPABILITIES`, `NEGOTIATE_ALGORITHMS`, `GET_DIGESTS`, `GET_CERTIFICATE`, `CHALLENGE`, `GET_MEASUREMENTS`, and `VENDOR_DEFINED_REQUEST`.

   SPDM 1.1: `KEY_EXCHANGE`, `FINISH`, `PSK_EXCHANGE`, `PSK_FINISH`, `END_SESSION`, `HEARTBEAT`, `KEY_UPDATE`, and `ENCAPSULATED` messages.

   SPDM 1.2: `GET_CSR`, `SET_CERTIFICATE`, `CHUNK_SEND`, and `CHUNK_GET`.

   SPDM 1.3: `GET_KEY_PAIR_INFO`, `SET_KEY_PAIR_INFO`, `SUBSCRIBE_EVENT_TYPE`, `GET_SUPPORTED_EVENT_TYPES`, `GET_ENDPOINT_INFO` and `GET_MEASUREMENT_EXTENSION_LOG`. Additional SPDM 1.3 messages will be implemented in future releases.

5) Cryptography Support

   The SPDM library requires [cryptolib API](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h), including random number generation, symmetric cryptography, asymmetric cryptography, hash, and message authentication code.

   Currently supported traditional algorithms: Hash:SHA2/SHA3/SM3, Signature:RSA-SSA/RSA-PSS/ECDSA/EdDSA/SM2-Sign, KeyExchange:FFDHE/ECDHE/SM2-KeyExchange, AEAD:AES_GCM/ChaCha20Poly1305/SM4_GCM.
   Currently supported PQC algorithms: Signature:ML-DSA/SLH-DSA, KeyEncapsulation:ML-KEM.
   NOTE: NIST algorithms and Shang-Mi (SM) algorithms should not be mixed together.

   ML-DSA OID is defined in [IETF Algorithm Identifiers for ML-DSA (Draft)](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates).
   SLH-DSA OID is defined in [IETF Algorithm Identifiers for SLH-DSA (Draft)](https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-slhdsa).

   The endianness is defined in [crypto_endianness](https://github.com/DMTF/libspdm/blob/main/doc/crypto_endianness.md).

   An [Mbed TLS](https://tls.mbed.org/) wrapper is included in [cryptlib_mbedtls](https://github.com/DMTF/libspdm/tree/main/os_stub/cryptlib_mbedtls).
   NOTE: SMx, EdDSA, ML-DSA, SLH-DSA and ML-KEM are not supported.

   An [OpenSSL](https://www.openssl.org/) wrapper is included in [cryptlib_openssl](https://github.com/DMTF/libspdm/tree/main/os_stub/cryptlib_openssl).
   NOTE: SM2-KeyExchange and SM4_GCM are not supported.

   libspdm provides support for [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final). Refer to [libspdm FIPS](https://github.com/DMTF/libspdm/blob/main/doc/fips.md) for more information.

   libspdm implements a raw public key format as defined in [RFC7250](https://www.rfc-editor.org/rfc/rfc7250). Refer to [libspdm raw public key](https://github.com/DMTF/libspdm/blob/main/doc/raw_public_key.md) for more information.

6) Execution Context

   Support to build an OS application for spdm_requester_emu and spdm_responder_emu to trace communication between Requester and Responder in [spdm-emu](https://github.com/DMTF/spdm-emu).

   Support to build an OS application for SPDM validation in [SPDM-Responder-Validator](https://github.com/DMTF/SPDM-Responder-Validator) and TEE-IO validation in [tee-io-validator](https://github.com/intel/tee-io-validator).

   Support to build as part of the NVIDIA Linux kernel module driver in [open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules).

   Support to build as backend server for [QEMU](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/specs/spdm.rst).

   Support is included in UEFI host environment [EDKII](https://github.com/tianocore/edk2/tree/master/SecurityPkg/DeviceSecurity).

   Support is included in ARM Trusted Firmware Implementation of the Realm Management Monitor [TF-RMM](https://github.com/TF-RMM/tf-rmm).

   Support is included in [wolfSSL](https://www.wolfssl.com/wolfssl-libspdm-support).

   Support to be included in [OpenBMC](https://github.com/openbmc). It is in planning, see [SPDM Integration](https://www.youtube.com/watch?v=PmgXkLJYI-E).

   Support to be linked by other languages. For example, [Java verifier](https://github.com/altera-opensource/verifier) and [Rust spdm-utils](https://github.com/westerndigitalcorporation/spdm-utils).

   Support interoperability testing with other SPDM implementations. For example, [intel-server-prot-spdm](https://github.com/intel/intel-server-prot-spdm) and [spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs).

7) Supported architecture and cross-compiler based on X64 platform.

| Windows System  | ia32 | x64 | arm | aarch64 | riscv32 | riscv64 |
| --------------- | ---- | --- | --- | ------- | ------- | ------- |
| [VS2015](https://visualstudio.microsoft.com/vs/older-downloads/) |  cl  |  cl |  -  |    -    |    -    |    -    |
| [VS2019](https://visualstudio.microsoft.com/vs/older-downloads/) |  cl  |  cl |  -  |    -    |    -    |    -    |
| [VS2022](https://visualstudio.microsoft.com/vs/older-downloads/) |  cl  |  cl |  -  |    -    |    -    |    -    |
| [ARM_DS2022](https://developer.arm.com/downloads/-/arm-development-studio-downloads) |  -   |  -  | armclang | armclang |    -    |    -    |
| [GCC](https://gcc.gnu.org/) | gcc  | gcc |  -  |    -    |    -    |    -    |
| [CLANG](https://llvm.org/) | clang-cl | clang-cl |  -  |    -    |    -    |    -    |

| Linux System    | ia32 | x64 | arm | aarch64 | riscv32 | riscv64 |
| --------------- | ---- | --- | --- | ------- | ------- | ------- |
| [GCC](https://gcc.gnu.org/) | gcc  | gcc |  -  |    -    |    -    |    -    |
| [CLANG](https://llvm.org/) | clang|clang|  -  |    -    |    -    |    -    |
| [ARM_DS2022](https://developer.arm.com/downloads/-/arm-development-studio-downloads) |  -   |  -  | armclang | armclang |    -    |    -    |
| [ARM_GNU](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) |  -   |  -  | arm-none-linux-gnueabihf-gcc | aarch64-none-linux-gnu-gcc |    -    |    -    |
| [ARM_GNU_BARE_METAL](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) |  -   |  -  | arm-none-eabi | aarch64-none-elf |    -    |    -    |
| [ARM_GCC](https://packages.ubuntu.com/bionic/gcc-arm-linux-gnueabi) |  -   |  -  | arm-linux-gnueabi-gcc |    -    |    -    |    -    |
| [AARCH64_GCC](https://packages.ubuntu.com/bionic/gcc-aarch64-linux-gnu) |  -   |  -  |  -  | aarch64-linux-gnu-gcc |    -    |    -    |
| [RISCV_GNU](https://github.com/riscv/riscv-gnu-toolchain) |  -   |  -  |  -  |    -    | riscv32-unknown-linux-gnu-gcc | riscv64-unknown-linux-gnu-gcc |
| [RISCV64_GCC](https://packages.ubuntu.com/bionic/gcc-riscv64-linux-gnu) |  -   |  -  |  -  |    -    |    -    | riscv64-linux-gnu-gcc |
| [RISCV_XPACK](https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack) |  -   |  -  |  -  |    -    | riscv-none-elf-gcc | riscv-none-elf-gcc |
| [RISCV_NONE](https://archlinux.org/packages/extra/x86_64/riscv64-elf-gcc/) |  -   |  -  |  -  |    -    | riscv64-elf-gcc | riscv64-elf-gcc |

8) Static Analysis

Support [Coverity](https://scan.coverity.com/) scan tool.

Support [CodeQL](https://codeql.github.com/) tool.

## Documents

1) Presentation

   Open Source Firmware Conference 2020 - [openspdm](https://cfp.osfc.io/osfc2020/talk/ECQ88N/)

   Free and Open Source Developers European Meeting 2021 - [openspdm](https://fosdem.org/2021/schedule/event/firmware_uoifaaffsdc/)

2) Library Threat Model

   The threat model can be found at [threat_model](https://github.com/DMTF/libspdm/blob/main/doc/threat_model.md).

3) Library Design

   The detailed design can be found at [design](https://github.com/DMTF/libspdm/blob/main/doc/design.md).

4) User Guide

   The user guide can be found at [user_guide](https://github.com/DMTF/libspdm/blob/main/doc/user_guide.md).

## Prerequisites

### Build Tools for Windows

1) Compiler for IA32/X64 (Choose one)

    a) [Visual Studio 2022](https://visualstudio.microsoft.com/vs/older-downloads/), [Visual Studio 2019](https://visualstudio.microsoft.com/vs/older-downloads/), [Visual Studio 2015](https://visualstudio.microsoft.com/vs/older-downloads/)

    b) [LLVM](https://llvm.org/) (LLVM13)
    - Install [LLVM-13.0.0-win64.exe](https://github.com/llvm/llvm-project/releases/tag/llvmorg-13.0.0). Change the LLVM install path to `C:\LLVM`, and add LLVM path `C:\LLVM\bin` in PATH environment for CLANG build on Windows.
    - LLVM13 works good for clang and [libfuzzer](https://llvm.org/docs/LibFuzzer.html) build. Other versions are not validated for clang build.
    - The Visual Studio is needed for nmake.
    - Because the libfuzzer lib path is hard coded in CMakeLists, other versions may fail for libfuzzer build.

For other architectures, refer to [build](https://github.com/DMTF/libspdm/blob/main/doc/build.md).

2) [CMake](https://cmake.org/) (Version [3.17.2](https://github.com/Kitware/CMake/releases/tag/v3.17.2) is known to work. Newer versions may fail).

### Build Tools for Linux

1) Compiler for IA32/X64 (Choose one)

    a) [GCC](https://gcc.gnu.org/) (above GCC5)

    b) [LLVM](https://llvm.org/) (above LLVM10)
    - Install steps: `sudo apt-get install llvm-10` then `sudo apt-get install clang-10`.
    - Use `llvm-ar -version` and `clang -v` to confirm the LLVM version.
    - If LLVM installation fails or LLVM installation version is low, you can update Linux version to fix the issue.

For other architectures, refer to [build](https://github.com/DMTF/libspdm/blob/main/doc/build.md).

2) [CMake](https://cmake.org/).

### Cryptography Library

1) [Mbed TLS](https://tls.mbed.org) as cryptography library. Version 3.6.2.

2) [OpenSSL](https://www.openssl.org) as cryptography library. Version 3.5.1.

### Unit Test framework

1) [cmocka](https://cmocka.org/). Version 1.1.7.

## Build

### Git Submodule

   libspdm uses submodules for Mbed TLS, OpenSSL, and cmocka.

   To get a fully buildable repository, use `git submodule update --init`.
   If there is an update for submodules, use `git submodule update`.

### Windows Builds for IA32/X64
   For ia32 builds, use a `x86 Native Tools Command Prompt for Visual Studio...` command prompt.

   For x64 builds, use a `x64 Native Tools Command Prompt for Visual Studio...` command prompt.

   General build steps: (Note the `..` at the end of the cmake command).
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<VS2022|VS2019|VS2015|CLANG> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   nmake copy_sample_key
   nmake
   ```

   Example CMake commands:

   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=mbedtls ..
   ```

   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=mbedtls ..
   ```

   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=openssl ..
   ```

   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=openssl ..
   ```

   Note ia32 build is not supported for CLANG build on Windows.

   CMake can also generate Visual Studio project files. For example:

   ```
   cmake -G"Visual Studio 16 2019" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=mbedtls ..
   ```

   Support OpenSSL binary build. For example:

   ```
   Note: Install the OpenSSL with command `nmake install` before build libspdm.
   cmake -G"Visual Studio 16 2019" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH=<OPENSSL_PATH>/libcrypto.lib -DCOMPILED_LIBSSL_PATH=<OPENSSL_PATH>/libssl.lib ..
   ```

For other architectures, refer to [build](https://github.com/DMTF/libspdm/blob/main/doc/build.md).

### Linux Builds for IA32/X64
   If ia32 builds run on a 64-bit Linux machine, then install `sudo apt-get install gcc-multilib`.

   General build steps: (Note the `..` at the end of the cmake command).

   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<GCC|CLANG> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```
Example CMake commands:
   ```
   cmake -DARCH=ia32 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=openssl ..
   ```

   ```
   cmake -DARCH=ia32 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
   ```

   ```
   cmake -DARCH=arm -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=openssl ..
   ```

   ```
   cmake -DARCH=x64 -DTOOLCHAIN=CLANG -DTARGET=Release -DCRYPTO=mbedtls ..

   ```

   Support OpenSSL binary build. For example:
   ```
   Note: Install OpenSSL with command `sudo make install` before build libspdm.
   cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH=<OPENSSL_PATH>/libcrypto.a -DCOMPILED_LIBSSL_PATH=<OPENSSL_PATH>/libssl.a ..
   ```

For other architectures, refer to [build](https://github.com/DMTF/libspdm/blob/main/doc/build.md).

## Run Test

### Run [unit_test](https://github.com/DMTF/libspdm/tree/main/unit_test)

   The unit test output is at `libspdm/build/bin`.
   Open one command prompt at output dir to run `test_spdm_requester > NUL` and `test_spdm_responder > NUL`.

   You should see something like:

   <pre>
      [==========] Running 2 test(s).
      [ RUN      ] test_spdm_responder_version_case1
      [       OK ] test_spdm_responder_version_case1
      [ RUN      ] test_spdm_responder_version_case2
      [       OK ] test_spdm_responder_version_case2
      [==========] 2 test(s) run.
      [  PASSED  ] 2 test(s).
   </pre>

   Note: You must use a command prompt with the current working directory at `libspdm/build/bin` when running unit tests or they may fail.
   Eg. Don't run the unit tests from libsdpm/build directory by calling "bin/test_spdm_responder > NULL"

### Other Tests

  libspdm also supports other tests such as code coverage, fuzzing, symbolic execution, and model checker.

  Refer to [test](https://github.com/DMTF/libspdm/blob/main/doc/test.md) for more details.

### Unit Test Code Coverage Report

The weekly unit test code coverage report is at https://dmtf.github.io/libspdm/coverage_log/.

## Associated Repositories

### [spdm-emu](https://github.com/DMTF/spdm-emu)

   spdm-emu implements a full SPDM Requester and a full SPDM Responder using libspdm. It can be used
   to test a Requester or Responder implementation, or to see how libspdm can be integrated into a
   Requester or Responder implementation.

### [spdm-dump](https://github.com/DMTF/spdm-dump) tool

   spdm-dump can be used to parse `pcap` files that capture SPDM traffic for offline analysis.

## Features not implemented yet

1) Refer to [issues](https://github.com/DMTF/libspdm/issues) for more details.
