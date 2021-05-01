# Test in openspdm

Besides spdm_emu and UnitTest introduced in readme, openspdm also supports some other tests.

## Prerequisit

### Build Tool

1) [cmake](https://cmake.org/) for Windows and Linux.

## Run Test

### Test other ARCH (arm, aarch64, riscv32, riscv64, arc)

Linux support only.

1) Install compiler:

```
sudo apt-get install gcc-arm-linux-gnueabi
sudo apt-get install gcc-aarch64-linux-gnu
sudo apt-get install gcc-riscv64-linux-gnu
```
    Build riscv32 compiler:
    
```
sudo apt-get install autoconf automake autotools-dev curl python3 libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
git clone --recursive https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
./configure --prefix=/opt/riscv32 --with-arch=rv32gc --with-abi=ilp32d
sudo make linux
sudo ln -s /opt/riscv32/bin/* /usr/bin
```
   Build arc compiler:

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

cd toolchain
./build-all.sh --no-elf32 --cpu hs38 --install-dir $INSTALL_ROOT 
# This command will build toolchain for arc HS Linux development, for other arc cores please refer to https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/blob/arc-releases/README.md

sudo ln -s /<work_dir>/arc_gnu/toolchain/bin/* /usr/bin
```

2) Install [qemu](https://qemu.org).

```
sudo apt-get install build-essential pkg-config zlib1g-dev libglib2.0-0 libglib2.0-dev  libsdl2-dev libpixman-1-dev libfdt-dev autoconf automake libtool librbd-dev libaio-dev flex bison -y
wget https://download.qemu.org/qemu-4.2.0.tar.xz
tar xvf qemu-4.2.0.tar.xz
cd qemu-4.2.0
./configure --prefix=/usr/local/qemu --audio-drv-list=
sudo make -j 8 && sudo make install
sudo ln -s /usr/local/qemu/bin/* /usr/local/bin
```

3) Run test

For arm: `qemu-arm -L /usr/arm-linux-gnueabi <TestBinary>`

For aarch64: `qemu-aarch64 -L /usr/aarch64-linux-gnu <TestBinary>`

For riscv32: `qemu-riscv32 -L /opt/riscv32/sysroot <TestBinary>`

For riscv64: `qemu-riscv64 -L /usr/riscv64-linux-gnu <TestBinary>`

### Collect Code Coverage

1) Code Coverage in Windows with [DynamoRIO](https://dynamorio.org/)

   Download and install [DynamoRIO 8.0.0](https://github.com/DynamoRIO/dynamorio/wiki/Downloads).
   Then `set DRIO_PATH=<DynameRIO_PATH>`

   Install Perl [ActivePerl 5.26](https://www.activestate.com/products/perl/downloads/).

   Build cases.
   Goto openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. mkdir log and cd log.

   Run all tests and generate log file :
   `%DRIO_PATH%\<bin64|bin32>\drrun.exe -c %DRIO_PATH%\tools\<lib64|lib32>\release\drcov.dll -- <test_app>`
   
   Generate coverage data with filter :
   `%DRIO_PATH%\tools\<bin64|bin32>\drcov2lcov.exe -dir . -src_filter openspdm`
   
   Generate coverage report :
   `perl %DRIO_PATH%\tools\<bin64|bin32>\genhtml coverage.info`

   The final report is index.html.

2) Code Coverage in Linux with GCC and [lcov](http://ltp.sourceforge.net/coverage/lcov.php).

   Install lcov `sudo apt-get install lcov`.

   Build cases.
   Goto openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. mkdir log and cd log.

   Run all tests.

   Collect coverage data :
   `lcov --capture --directory <openspdm_root_dir> --output-file coverage.info`

   Collect coverage report :
   `genhtml coverage.info --output-directory .`

   The final report is index.html.

### Run fuzzing

1) fuzzing in Linux with [AFL](https://lcamtuf.coredump.cx/afl/)

   Download and install [AFL](http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz).
   Unzip and follow docs\QuickStartGuide.txt.
   Build it with `make`.
   Ensure AFL binary is in PATH environment variable.
   ```
   export AFL_PATH=<AFL_PATH>
   export PATH=$PATH:$AFL_PATH
   ```
   
   Then run commands as root (every time reboot the OS):
   ```
   sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
   cd /sys/devices/system/cpu/
   sudo bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
   ```

   Known issue: Above command cannot run in Windows Linux Subsystem.

   Build cases with AFL toolchain:
   `make fuzzing -f GNUmakefile ARCH=<x64|ia32> TARGET=<DEBUG|RELEASE> TOOLCHAIN=AFL CRYPTO=<mbedtls|openssl> -e WORKSPACE=<openspdm_root_dir>`

   Run cases:
   ```
   mkdir testcase_dir
   mkdir /dev/shm/findings_dir
   cp <seed> testcase_dir
   afl-fuzz -i testcase_dir -o /dev/shm/findings_dir <test_app> @@
   ```
   Note: /dev/shm is tmpfs.

2) fuzzing in Windows with [winafl](https://github.com/googleprojectzero/winafl)

   Clone [winafl](https://github.com/googleprojectzero/winafl).
   Download [DynamoRIO](https://dynamorio.org/).

   Set path `set AFL_PATH=<AFL_PATH>` and `set DRIO_PATH=<DynameRIO_PATH>`.

   NOTE: as known issue https://github.com/googleprojectzero/winafl/issues/145 that cause compatibility issues in recent Windows versions, the author has disabled Drsyms in recent WinAFL builds, if you want you use the newest version, please according to Method.2 to rebuild winafl yourself.

   Build winafl:
   ```
   mkdir [build32|build64]
   cd [build32|build64]
   cmake -G"Visual Studio 16 2019" -A [Win32|x64] .. -DDynamoRIO_DIR=%DRIO_PATH%\cmake -DUSE_DRSYMS=1
   cmake --build . --config Release
   ```

   NOTE: If you get errors where the linker couldn't find certain .lib files. please refer to https://github.com/googleprojectzero/winafl/issues/145 and delete the nonexistent files from "Additional Dependencies".

   Copy all binary under [build32|build64]/bin/Release to [bin32|bin64]. `robocopy /E /is /it [build32|build64]/bin/Release [bin32|bin64]`.

   Build cases with VS2019 toolchain. (non AFL toolchain in Windows):
   `nmake fuzzing ARCH=<x64|ia32> TARGET=<DEBUG|RELEASE> TOOLCHAIN=VS2019 CRYPTO=<mbedtls|openssl> -e WORKSPACE=<openspdm_root_dir>`

   Run cases:
   ```
   cp <test_app> winafl\<bin64|bin32>
   cp <test_app_pdb> winafl\<bin64|bin32>
   cd winafl\<bin64|bin32>
   afl-fuzz.exe -i in -o out -D %DRIO_PATH%\<bin64|bin32> -t 20000 -- -coverage_module <test_app> -fuzz_iterations 1000 -target_module <test_app> -target_method main -nargs 2 -- <test_app> @@
   ```

3) fuzzing in Linux with LLVM [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)

   Ensure LLVM binary in in PATH environment variable.
   ```
   export CLANG_PATH=<LLVM_PATH>/bin
   export ASAN_SYMBOLIZER_PATH=$CLANG_PATH/llvm-symbolizer
   ```

   Build cases with LIBFUZZER toolchain:
   `make fuzzing -f GNUmakefile ARCH=<x64|ia32> TARGET=<DEBUG|RELEASE> TOOLCHAIN=LIBFUZZER CRYPTO=<mbedtls|openssl> -e WORKSPACE=<openspdm_root_dir>`

   Run cases:
   ```
   mkdir NEW_CORPUS_DIR // Copy test seeds to the folder before run test
   <test_app> NEW_CORPUS_DIR -rss_limit_mb=0 -artifact_prefix=<OUTPUT_PATH>
   ```

4) fuzzing in Windows with LLVM [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)

   Note: Please install 64bit exe for x64 build (IA32 build is not supported with LLVM9)

   Ensure LLVM binary in in PATH environment variable.
   ```
   set LLVM_PATH=<LLVM_PATH>
   set PATH=%PATH%;%LLVM_PATH%\bin
   ```

   Build cases with LIBFUZZER toolchain:
   `nmake fuzzing ARCH=x64 TARGET=<DEBUG|RELEASE> TOOLCHAIN=LIBFUZZER CRYPTO=<mbedtls|openssl> -e WORKSPACE=<openspdm_root_dir>`

   Run cases:
   ```
   mkdir NEW_CORPUS_DIR // Copy test seeds to the folder before run test
   <test_app> NEW_CORPUS_DIR -rss_limit_mb=0 -artifact_prefix=<OUTPUT_PATH>
   ```

### Run Symbolic Execution

1) [KLEE](https://klee.github.io/)

   Download and install [KLEE with LLVM9](https://klee.github.io/build-llvm9/). Please follow all 12 steps including optional ones.

   In step 3, constrint solver [STP](http://klee.github.io/build-stp) is recommended here.
   Set size of the stack to a very large value: `$ ulimit -s unlimited`.

   In step 8, below example can be use:
   ```
   $ cmake \
      -DENABLE_SOLVER_STP=ON \
      -DENABLE_POSIX_RUNTIME=ON \
      -DENABLE_KLEE_UCLIBC=ON \
      -DKLEE_UCLIBC_PATH=/home/tiano/env/klee-uclibc \
      -DGTEST_SRC_DIR=/home/tiano/env/googletest-release-1.7.0 \
      -DENABLE_UNIT_TESTS=ON \
      -DLLVM_CONFIG_BINARY=/usr/bin/llvm-config \
      -DLLVMCC=/usr/bin/clang \
      -DLLVMCXX=/usr/bin/clang++
      /home/tiano/env/klee
   ```

   Ensure KLEE binary is in PATH environment variable.
   ```
   export KLEE_SRC_PATH=<KLEE_SOURCE_DIR>
   export KLEE_BIN_PATH=<KLEE_BUILD_DIR>
   export PATH=$KLEE_BIN_PATH:$PATH
   ```

   Build cases in Linux with KLEE toolchain. (KLEE does not support Windows)
   `make -f GNUmakefile ARCH=<x64|ia32> TARGET=<DEBUG|RELEASE> TOOLCHAIN=KLEE CRYPTO=<mbedtls|openssl> -e WORKSPACE=<openspdm_root_dir>`

   Use [KLEE](http://klee.github.io/tutorials) to [generate ktest](https://klee.github.io/tutorials/testing-coreutils/):
   `klee --only-output-states-covering-new <test_app>`

   Transfer .ktest to seed file, which can be used for AFL-fuzzer.
   `python unit_test/fuzzing/Tools/TransferKtestToSeed.py <Arguments>`

   Arguments:
   <KtestFile>                          the path of .ktest file.
   <KtestFile1> <KtestFile2> ...        the paths of .ktest files.
   <KtestFolder>                        the path of folder contains .ktest file.
   <KtestFolder1> <KtestFolder2> ...    the paths of folders contain .ktest file.

### Run Model Checker

1) [CBMC](http://www.cprover.org/cbmc/)

   Install [CBMC tool](http://www.cprover.org/cprover-manual/).
   For Windows, unzip [cbmc-5-10-win](http://www.cprover.org/cbmc/download/cbmc-5-10-win.zip).
   For Linux, unzip [cbmc-5-11-linux-64](http://www.cprover.org/cbmc/download/cbmc-5-11-linux-64.tgz).
   Ensure CBMC executable directory is in PATH environment variable.

   Build cases with CBMC toolchain:

   For Windowns, open visual studio 2019 command prompt at openspdm dir and type `nmake ARCH=ia32 TOOLCHAIN=CBMC TARGET=<DEBUG|RELEASE> CRYPTO=mbedtls -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=ia32 only)

   For Linux, open command prompt at openspdm dir and type `make -f GNUmakefile ARCH=x64 TOOLCHAIN=CBMC TARGET=<DEBUG|RELEASE> CRYPTO=mbedtls -e WORKSPACE=<openspdm_root_dir>`. (ARCH=x64 only)

   The output binary is created by the [goto-cc](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/goto-cc.md).

   For more infomration on how to use [CBMC](https://github.com/diffblue/cbmc/), please refer to [CBMC Manual](https://github.com/diffblue/cbmc/tree/develop/doc/cprover-manual), such as [properties](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/properties.md), [modeling-nondeterminism](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/modeling-nondeterminism.md), [api](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/api.md). Example below:

   Using [goto-instrument](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/goto-instrument.md) static analyzer operates on goto-binaries and generate a modified binary:
   `goto-instrument SpdmRequester.exe SpdmRequester.gb <instrumentation-options>`

   Using [CBMC](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/cbmc-tutorial.md) on the modified binary:
   `cbmc SpdmRequester.gb --show-properties`

### Run Static Analysis

1) Use [Klocwork](https://www.perforce.com/products/klocwork) in windows as an example.

   Install Klocwork and set environment.
   ```
   set KW_HOME=C:\Klocwork
   set KW_ROOT=%KW_HOME%\<version>\projects_root
   set KW_TABLE_ROOT=%KW_HOME%\Tables
   set KW_CONFIG=%KW_ROOT%\projects\workspace\rules\analysis_profile.pconf
   set KW_PROJECT_NAME=openspdm
   ```

   Build openspdm with Klocwork :
   ```
   kwinject --output %KW_ROOT%\%KW_PROJECT_NAME%.out nmake ARCH=<x64|ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<mbedtls|openssl> -e WORKSPACE=<openspdm_root_dir>
   ```

   Collect analysis data :
   ```
   kwservice start
   kwadmin create-project %KW_PROJECT_NAME%
   kwadmin import-config %KW_PROJECT_NAME% %KW_CONFIG%
   kwbuildproject --project %KW_PROJECT_NAME% --tables-directory %KW_TABLE_ROOT%\%KW_PROJECT_NAME% %KW_ROOT%\%KW_PROJECT_NAME%.out --force
   kwadmin load %KW_PROJECT_NAME% %KW_TABLE_ROOT%\%KW_PROJECT_NAME%
   ```

   View report at http://localhost:8080/.
