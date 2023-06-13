# Build libspdm

## Prerequisites

### Build Tools for Windows

#### Compiler for ARM/AARCH64 (Choose one)

a) [ARM Developerment Studio 2022](https://developer.arm.com/downloads/-/arm-development-studio-downloads) for ARM/AARCH64.
  - Install [MSYS2](https://www.msys2.org/).
  - Install ARM DS2022. Change the default installation path C:\ArmStudio.
  - Launch MSYS2 -> MSYS2 MINGW64.
  - Install cmake and make, with `pacman -S mingw-w64-x86_64-cmake` and `pacman -S make`.
  - Setup build environment
      ```
      export PATH=$PATH:/c/ArmStudio/sw/ARMCompiler6.18/bin
      export CC=/c/ArmStudio/sw/ARMCompiler6.18/bin/armclang.exe
      export ARM_PRODUCT_DEF=/c/ArmStudio/sw/mappings/gold.elmap
      export ARMLMD_LICENSE_FILE=<license file>
      ```
  - Apply below work around for Windows ARM DS2022 build
    - Add set(CMAKE_SYSTEM_ARCH "armv8-a") on the top of `C:\msys64\mingw64\share\cmake\Modules\Compiler\ARMClang.cmake`. The CMAKE_SYSTEM_ARCH is the target arch.
    - Change `set(libs ${libs} ws2_32)` to `#set(libs ${libs} ws2_32)` in `libspdm\os_stub\mbedtlslib\mbedtls\library\CMakeLists.txt`. ws2_32 is the socket lib, and the armclang does not support it.
  - Implement the TBD features. `libspdm_sleep` and `libspdm_get_random_number_64` need to be implemented before it can run on a real system.

### Build Tools for Linux

#### Compiler for ARM/AARCH64 (Choose one)

a) [ARM Developerment Studio 2022](https://developer.arm.com/downloads/-/arm-development-studio-downloads) for ARM/AARCH64.
  - Follow the [Arm Development Studio Getting Started Guide](https://developer.arm.com/documentation/101469/2022-1/Installing-and-configuring-Arm-Development-Studio/Installing-on-Linux) to install Linux version.
  - Setup build environment
      ```
      echo 'export PATH=$PATH:/opt/arm/developmentstudio-2022.1/sw/ARMCompiler6.18/bin' | sudo tee -a ~/.bashrc
      echo 'export ARM_PRODUCT_DEF=/opt/arm/developmentstudio-2022.1/sw/mappings/gold.elmap' | sudo tee -a ~/.bashrc
      echo 'export ARMLMD_LICENSE_FILE=<license file>' | sudo tee -a ~/.bashrc
      source ~/.bashrc
      ```
  - Implement the TBD features. `libspdm_sleep` and `libspdm_get_random_number_64` need to be implemented before it can run on a real system.

b) [ARM GNU](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads).
  - Download 11.2-2022.02: GNU/Linux target (arm-none-linux-gnueabihf, aarch64-none-linux-gnu), and unzip it.
  - Add <tool_path>/bin to the $PATH environment. For example:
      ```
      echo 'export PATH=~/gcc-arm-11.2-2022.02-x86_64-arm-none-linux-gnueabihf/bin:$PATH' | sudo tee -a ~/.bashrc
      echo 'export PATH=~/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu/bin:$PATH' | sudo tee -a ~/.bashrc
      source ~/.bashrc
      ```

c) [ARM GNU bare metal](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads).
  - Download 11.2-2022.02: GNU/Linux target (arm-none-eabi, aarch64-none-elf), and unzip it.
  - Add <tool_path>/bin to the $PATH environment. For example:
      ```
      echo 'export PATH=~/gcc-arm-11.2-2022.02-x86_64-arm-none-eabi/bin:$PATH' | sudo tee -a ~/.bashrc
      echo 'export PATH=~/gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf/bin:$PATH' | sudo tee -a ~/.bashrc
      source ~/.bashrc
      ```

d) [ARM GCC](https://packages.ubuntu.com/bionic/gcc-arm-linux-gnueabi) for ARM only
  - `sudo apt-get install gcc-arm-linux-gnueabi`

e) [AARCH64 GCC](https://packages.ubuntu.com/bionic/gcc-aarch64-linux-gnu) for AARCH64 only
  - `sudo apt-get install gcc-aarch64-linux-gnu`

#### Compiler for RISCV32/RISCV64 (Choose one)

a) [RISCV XPACK](https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/).
  - Download xPack GNU RISC-V Embedded GCC v12.2.0-1(xpack-riscv-none-elf-gcc-12.1.0-2-linux-x64.tar.gz), and unzip it.
  - Add <tool_path>/bin to the $PATH environment. For example:
      ```
      echo 'export PATH=~/xpack-riscv-none-elf-gcc-12.2.0-1/bin:$PATH' | sudo tee -a ~/.bashrc
      source ~/.bashrc
      ```
  - Test install successfully. Use `riscv-none-elf-gcc --version`, then the successful install can see `riscv-none-elf-gcc (xPack GNU RISC-V Embedded GCC x86_64) 12.1.0`.

b) [RISCV GNU](https://github.com/riscv-collab/riscv-gnu-toolchain)
  - Download the compiler
      ```
      sudo apt-get install autoconf automake autotools-dev curl python3 libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
      git clone --recursive https://github.com/riscv/riscv-gnu-toolchain
      ```
  - Compile for riscv64
      ```
      cd riscv-gnu-toolchain
      ./configure --prefix=/opt/riscv
      sudo make linux
      sudo ln -s /opt/riscv/bin/* /usr/bin
      ```
  - Compile for riscv32
      ```
      cd riscv-gnu-toolchain
      ./configure --prefix=/opt/riscv32 --with-arch=rv32gc --with-abi=ilp32d
      sudo make linux
      sudo ln -s /opt/riscv32/bin/* /usr/bin
      ```

c) [RISCV64 GCC](https://packages.ubuntu.com/bionic/gcc-riscv64-linux-gnu) for RISCV64 only
  - `sudo apt-get install gcc-riscv64-linux-gnu`

#### Compiler for ARC

a) [ARC GNU](https://github.com/foss-for-synopsys-dwc-arc-processors).
  - Download ARC GNU.
      ```
      sudo apt-get install -y texinfo byacc flex libncurses5-dev zlib1g-dev libexpat1-dev texlive build-essential git wget gawk bison xz-utils make python3 rsync locales
      mkdir arc_gnu
      cd arc_gnu
      git clone https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain.git
      git clone https://github.com/foss-for-synopsys-dwc-arc-processors/binutils-gdb.git binutils
      git clone https://github.com/foss-for-synopsys-dwc-arc-processors/gcc.git
      git clone --reference binutils https://github.com/foss-for-synopsys-dwc-arc-processors/binutils-gdb.git gdb
      git clone https://github.com/foss-for-synopsys-dwc-arc-processors/newlib.git
      git clone https://github.com/wbx-github/uclibc-ng.git # For For Linux uClibc toolchain
      git clone https://github.com/foss-for-synopsys-dwc-arc-processors/glibc.git # For Linux glibc toolchain
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git linux
      ```
  - Build tool chain.
      ```
      cd toolchain
      ./build-all.sh --no-elf32 --cpu hs38 --install-dir $INSTALL_ROOT
      # This command will build toolchain for arc HS Linux development, for other arc cores refer to https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/blob/arc-releases/README.md

      sudo ln -s /<work_dir>/arc_gnu/toolchain/bin/* /usr/bin
      ```

#### Compiler for NIOS-II

a) [NIOS2 GNU](https://www.intel.com/content/www/us/en/docs/programmable/683689/current/gnu-command-line-tools.html).
  - Follow the NIOS II document.

## Build

### Windows Builds for ARM/AARCH64

   For ARM DS2022 build (arm or aarch64) on Windows, Launch `MSYS2 -> MSYS2 MINGW64` command prompt.
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -G"MSYS Makefiles" -DARCH=<arm|aarch64> -DTOOLCHAIN=ARM_DS2022 -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

   Example CMake commands:

   ```
   cmake -G"MSYS Makefiles" -DARCH=arm -DTOOLCHAIN=ARM_DS2022 -DTARGET=Debug -DCRYPTO=mbedtls ..
   ```

   ```
   cmake -G"MSYS Makefiles" -DARCH=aarch64 -DTOOLCHAIN=ARM_DS2022 -DTARGET=Release -DCRYPTO=mbedtls ..
   ```

   Note: `make -j` can be used to accelerate the build.

### Linux Builds for ARM/AARCH64

#### Linux Builds with ARM DS2022

   For ARM DS2022 build (arm or aarch64) on Linux,
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<arm|aarch64> -DTOOLCHAIN=ARM_DS2022 -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

   Example CMake commands:

   ```
   cmake -DARCH=arm -DTOOLCHAIN=ARM_DS2022 -DTARGET=Debug -DCRYPTO=mbedtls ..
   ```

   ```
   cmake -DARCH=aarch64 -DTOOLCHAIN=ARM_DS2022 -DTARGET=Release -DCRYPTO=mbedtls ..
   ```

   Note: `make -j` can be used to accelerate the build.

#### Linux Builds with ARM_GNU Toolchain

   For ARM_GNU toolchain GNU/Linux target (arm-none-linux-gnueabihf, aarch64-none-linux-gnu) build on Linux,
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<arm|aarch64> -DTOOLCHAIN=ARM_GNU -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

   Example CMake commands:

   ```
   cmake -DARCH=arm -DTOOLCHAIN=ARM_GNU -DTARGET=Debug -DCRYPTO=mbedtls ..
   ```

   ```
   cmake -DARCH=aarch64 -DTOOLCHAIN=ARM_GNU -DTARGET=Release -DCRYPTO=mbedtls ..
   ```

   Note: `make -j` can be used to accelerate the build.

#### Linux Builds with ARM_GNU_BARE_METAL Toolchain

   For ARM_GNU_BARE_METAL toolchain GNU/Linux target (arm-none-eabi, aarch64-none-elf) build on Linux,
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<arm|aarch64> -DTOOLCHAIN=ARM_GNU_BARE_METAL -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

   Example CMake commands:

   ```
   cmake -DARCH=arm -DTOOLCHAIN=ARM_GNU_BARE_METAL -DTARGET=Debug -DCRYPTO=mbedtls ..
   ```
   ```
   cmake -DARCH=aarch64 -DTOOLCHAIN=ARM_GNU_BARE_METAL -DTARGET=Release -DCRYPTO=mbedtls ..
   ```

   Note: `make -j` can be used to accelerate the build.

### Linux Builds for RISCV32/RISCV64

   For RISCV_XPACK toolchain GNU/Linux target (riscv-none-elf-gcc-12.1.0-2-linux-x64) build on Linux,
   (The riscv64 arch is not supported now.)
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<riscv32> -DTOOLCHAIN=RISCV_XPACK -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

   Example CMake commands:
   ```
   cmake -DARCH=riscv32 -DTOOLCHAIN=RISCV_XPACK -DTARGET=Debug -DCRYPTO=mbedtls ..
   ```
   ```
   cmake -DARCH=riscv32 -DTOOLCHAIN=RISCV_XPACK -DTARGET=Release -DCRYPTO=mbedtls ..
   ```
   Note: `make -j` can be used to accelerate the build.

### Linux Builds inside build environments

If the toolchain is set to NONE then it will use the native toolchain of the
build environment. This is useful inside build environments such as Buildroot
or OpenEmbedded.

```shell
cd libspdm
mkdir build
cd build
cmake -DARCH=<arch> -DTOOLCHAIN=NONE -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
make
```

### Disabling unit and fuzz tests

Unit tests can be disable by adding -DDISABLE_TESTS=1 to CMake.

```shell
-DDISABLE_TESTS=1
```
