# libspdm is a sample implementation that follows the DMTF [SPDM](https://www.dmtf.org/standards/spdm) specifications

## Features

1) Specifications

   The SPDM and secured message libraries follow :

   [DSP0274](https://www.dmtf.org/dsp/DSP0274)  Security Protocol and Data Model (SPDM) Specification (version [1.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.1.pdf), version [1.1.2](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.2.pdf) and version [1.2.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.1.pdf))

   [DSP0277](https://www.dmtf.org/dsp/DSP0277)  Secured Messages using SPDM Specification (version [1.1.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.1.0.pdf))

   MCTP and secured MCTP follow :

   [DSP0275](https://www.dmtf.org/dsp/DSP0275)  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   [DSP0276](https://www.dmtf.org/dsp/DSP0276)  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0.pdf))

   PCIE follows :

   PCI Express Base Specification Revision 6.0 (version [1.0](https://members.pcisig.com/wg/PCI-SIG/document/16609))

2) Includes libraries that can be used to construct an SPDM Requester and an SPDM Responder.

3) Programming Context

   The core libraries in `libspdm/library` require only the C99 freestanding headers and so are suitable for embedded and systems programming. Any functionality beyond the freestanding headers is provided by `libspdm/os_stub` or by the library's integrator. All statically allocated memory in the core libraries is read-only. The core libraries do not dynamically allocate memory.

4) Implemented Requests and Responses

   SPDM 1.0: `GET_VERSION`, `GET_CAPABILITIES`, `NEGOTIATE_ALGORITHMS`, `GET_DIGESTS`, `GET_CERTIFICATE`, `CHALLENGE`, and `GET_MEASUREMENTS`.

   SPDM 1.1: `KEY_EXCHANGE`, `FINISH`, `PSK_EXCHANGE`, `PSK_FINISH`, `END_SESSION`, `HEARTBEAT`, `KEY_UPDATE`, and `ENCAPSULATED` messages.

   SPDM 1.2: `GET_CSR`, `SET_CERTIFICATE`, `CHUNK_SEND`, and `CHUNK_GET`.

5) Cryptographic Algorithm Support

   The SPDM library requires [cryptolib API](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h), including random number generation, symmetric cryptography, asymmetric cryptography, hash, and message authentication code.

   Currently supported algorithms: Hash:SHA2/SHA3/SM3, Signature:RSA-SSA/RSA-PSS/ECDSA/EdDSA/SM2-Sign, KeyExchange:FFDHE/ECDHE/SM2-KeyExchange, AEAD:AES_GCM/ChaCha20Poly1305/SM4_GCM.
   NOTE: NIST algorithms and Shang-Mi (SM) algorithms should not be mixed together.

   An [Mbed TLS](https://tls.mbed.org/) wrapper is included in [cryptlib_mbedtls](https://github.com/DMTF/libspdm/tree/main/os_stub/mbedtlslib).
   NOTE: SMx and EdDSA are not supported.

   An [OpenSSL](https://www.openssl.org/) wrapper is included in [cryptlib_openssl](https://github.com/DMTF/libspdm/tree/main/os_stub/openssllib).
   NOTE: SM2-KeyExchange and SM4_GCM are not supported.

6) Execution Context

   Support to build an OS application for spdm_requester_emu and spdm_responder_emu to trace communication between Requester and Responder.

   Support to be included in UEFI host environment [EDKII](https://github.com/tianocore/edk2), such as [edkii_spdm_requester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

   Support to be included in [OpenBMC](https://github.com/openbmc). It is in planning, see [SPDM Integration](https://www.youtube.com/watch?v=PmgXkLJYI-E).

## Documents

1) Presentation

   Open Source Firmware Conference 2020 - [openspdm](https://cfp.osfc.io/osfc2020/talk/ECQ88N/)

   Free and Open Source Developers European Meeting 2021 - [openspdm](https://fosdem.org/2021/schedule/event/firmware_uoifaaffsdc/)

2) Library Threat Model

   The user guide can be found at [threat_model](https://github.com/DMTF/libspdm/blob/main/doc/threat_model.md).

3) Library Design

   The detailed design can be found at [design](https://github.com/DMTF/libspdm/blob/main/doc/design.md).

4) User Guide

   The user guide can be found at [user_guide](https://github.com/DMTF/libspdm/blob/main/doc/user_guide.md).

## Prerequisites

### Build Tools for Windows

1) Compiler (Choose one)

    a) [Visual Studio 2022](https://visualstudio.microsoft.com/vs/older-downloads/)

    b) [Visual Studio 2019](https://visualstudio.microsoft.com/vs/older-downloads/)

    c) [Visual Studio 2015](https://visualstudio.microsoft.com/vs/older-downloads/)

    d) [LLVM](https://llvm.org/) (LLVM13) Download: [LLVM-13.0.0-win64.exe](https://github.com/llvm/llvm-project/releases/tag/llvmorg-13.0.0).
    - Add LLVM in PATH environment according to installation instruction.
    - Change LLVM install path to C:/LLVM.
    - LLVM13 works good for clang and [libfuzzer](https://llvm.org/docs/LibFuzzer.html) build. Other versions are not validated for clang build.
    - Because the libfuzzer lib path is hard coded in CMakeLists, other versions may fail for libfuzzer build.

2) [CMake](https://cmake.org/) (Version [3.17.2](https://github.com/Kitware/CMake/releases/tag/v3.17.2) is known to work. Newer versions may fail).

### Build Tools for Linux

1) Compiler (Choose one)

    a) [GCC](https://gcc.gnu.org/) (above GCC5)

    b) [LLVM](https://llvm.org/) (above LLVM10), install steps: `sudo apt-get install llvm-10` then `sudo apt-get install clang-10`. Use `llvm-ar -version` and `clang -v` to confirm the LLVM version. If LLVM installation fails or LLVM installation version is low, you can update Linux version to fix the issue.

2) [CMake](https://cmake.org/).

### Cryptography Library

1) [Mbed TLS](https://tls.mbed.org) as cryptography library. Version 2.28.1.

2) [OpenSSL](https://www.openssl.org) as cryptography library. Version 1.1.1q.

### Unit Test framework

1) [cmocka](https://cmocka.org/). Version 1.1.5.

## Build

### Git Submodule

   libspdm uses submodules for mbedtls, openssl, and cmocka.

   To get a fully buildable repository, use `git submodule update --init`.
   If there is an update for submodules, use `git submodule update`.

### Windows Builds
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

   Support openssl binary build. For example:

   ```
   Note: Please install the openssl with command `nmake install` before build libspdm.
   cmake -G"Visual Studio 16 2019" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH=<OPENSSL_PATH>/libcrypto.lib -DCOMPILED_LIBSSL_PATH=<OPENSSL_PATH>/libssl.lib ..
   ```
### Armclang build on Windows.
1) Install [MSYS2](https://www.msys2.org/).
2) Install amrclang (change the default installation path from C:\Program Files\Arm\Development Studio 2022.1 to C:\ArmStudio to avoid blank space)
3) Launch MSYS2 -> MSYS2 MINGW64.
4) Install cmake and make.
```
pacman -S mingw-w64-x86_64-cmake
pacman -S make
```
5) Setup build environment command
```
cd libspdm
mkdir build
cd build
export PATH=$PATH:/c/ArmStudio/sw/ARMCompiler6.18/bin
export CC=/c/ArmStudio/sw/ARMCompiler6.18/bin/armclang.exe
export ARM_PRODUCT_DEF=/c/ArmStudio/sw/mappings/gold.elmap
export ARMLMD_LICENSE_FILE=<license file>
```
6) some work around for Windows armclang build
- Add set(CMAKE_SYSTEM_ARCH "armv8-a") on the top of `C:\msys64\mingw64\share\cmake\Modules\Compiler\ARMClang.cmake`. The CMAKE_SYSTEM_ARCH is the target arch.
- ws2_32 is the socket lib, and the armclang does not support it. Change `set(libs ${libs} ws2_32)` to `#set(libs ${libs} ws2_32)` in `libspdm\os_stub\mbedtlslib\mbedtls\library\CMakeLists.txt`.
7) Build arm command
```
cmake -G"MSYS Makefiles" -DARCH=arm -DTOOLCHAIN=ARM_CLANG -DTARGET=Debug -DCRYPTO=mbedtls ..
make -j <thread number>
```
for example `make -j 8` or `make -j`
8) Build aarch64 command
```
cmake -G"MSYS Makefiles" -DARCH=aarch64 -DTOOLCHAIN=ARM_CLANG -DTARGET=Debug -DCRYPTO=mbedtls ..
make -j <thread number>
```
for example `make -j 8` or `make -j`

8) some feature for armclang build is TBD by user
When use libspdm with armclang build: `libspdm_sleep` and `libspdm_get_random_number_64` need to be completed.

### Linux Builds
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

   Support openssl binary build. For example:
   ```
   Note: Please install the openssl with command `sudo make install` before build libspdm.
   cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH=<OPENSSL_PATH>/libcrypto.a -DCOMPILED_LIBSSL_PATH=<OPENSSL_PATH>/libssl.a ..
   ```
### Armclang build on Linux.
1) Install  [Arm Development Studio 2022.1 linux](https://developer.arm.com/downloads/-/arm-development-studio-downloads) follow the [Arm Development Studio Getting Started Guide](https://developer.arm.com/documentation/101469/2022-1/Installing-and-configuring-Arm-Development-Studio/Installing-on-Linux)
2) Setup enviroment
```
echo 'export PATH=$PATH:/opt/arm/developmentstudio-2022.1/sw/ARMCompiler6.18/bin' | sudo tee -a ~/.bashrc
echo 'export ARM_PRODUCT_DEF=/opt/arm/developmentstudio-2022.1/sw/mappings/gold.elmap' | sudo tee -a ~/.bashrc
echo 'export ARMLMD_LICENSE_FILE=<license file>' | sudo tee -a ~/.bashrc
source ~/.bashrc
```
3) Build command for arm
```
cmake -DARCH=arm -DTOOLCHAIN=ARM_CLANG -DTARGET=Debug -DCRYPTO=mbedtls  ..
make copy_sample_key
make -j <thread number>
```
for example `make -j 8` or `make -j`
4) Build command for aarch64
```
cmake -DARCH=aarch64 -DTOOLCHAIN=ARM_CLANG -DTARGET=Debug -DCRYPTO=mbedtls  ..
make copy_sample_key
make -j <thread number>
```
for example `make -j 8` or `make -j`
5) some feature for armclang build is TBD by user
When use libspdm with armclang build: `libspdm_sleep` and `libspdm_get_random_number_64` need to be completed.

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

  libspdm also supports other tests such as code coverage, fuzzing, symbolic execution, model checker.

  Refer to [test](https://github.com/DMTF/libspdm/blob/main/doc/test.md) for more details.

## Associated Repsositories

### [spdm-emu](https://github.com/DMTF/spdm-emu)

   spdm-emu implements a full SPDM Requester and a full SPDM Responder using libspdm. It can be used
   to test a Requester or Responder implementation, or to see how libspdm can be integrated into a
   Requester or Responder implementation.

### [spdm-dump](https://github.com/DMTF/spdm-dump) tool

   spdm-dump can be used to parse `pcap` files that capture SPDM traffic for offline analysis.

## Features not implemented yet

1) Refer to [issues](https://github.com/DMTF/libspdm/issues) for more details.

## Known limitations
This package is only the sample code to show the concept of SPDM and should not be considered fit for production.
Any code including the API definition is subject to change.
