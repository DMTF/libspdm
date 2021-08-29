cmake_minimum_required(VERSION 2.6)

project("libspdm" C)

#
# Build Configuration Macro Definition
#
MESSAGE("#########################")
MESSAGE("## Build Configuration ##")
MESSAGE("#########################")

SET(ARCH ${ARCH} CACHE STRING "Choose the arch of build: ia32 x64 arm aarch64 riscv32 riscv64 arc" FORCE)
SET(TOOLCHAIN ${TOOLCHAIN} CACHE STRING "Choose the toolchain of build: Windows: VS2015 VS2019 CLANG LIBFUZZER Linux: GCC ARM_GCC AARCH64_GCC RISCV32_GCC RISCV64_GCC ARC_GCC CLANG CBMC AFL KLEE LIBFUZZER" FORCE)
SET(CMAKE_BUILD_TYPE ${TARGET} CACHE STRING "Choose the target of build: Debug Release" FORCE)
SET(CRYPTO ${CRYPTO} CACHE STRING "Choose the crypto of build: mbedtls openssl" FORCE)

SET(LIBSPDM_DIR ${PROJECT_SOURCE_DIR})

#
# OpenSSL specific compiled libraries.
#
SET(COMPILED_LIBCRYPTO_PATH ${COMPILED_LIBCRYPTO_PATH} CACHE STRING "Optionally provide a path to libcrypto" FORCE)
SET(COMPILED_LIBSSL_PATH ${COMPILED_LIBSSL_PATH} CACHE STRING "Optionally provide a path to libssl" FORCE)

if(ARCH STREQUAL "x64")
    MESSAGE("ARCH = x64")
elseif(ARCH STREQUAL "ia32")
    MESSAGE("ARCH = ia32")
elseif(ARCH STREQUAL "arm")
    MESSAGE("ARCH = arm")
elseif(ARCH STREQUAL "aarch64")
    MESSAGE("ARCH = aarch64")
elseif(ARCH STREQUAL "riscv32")
    MESSAGE("ARCH = riscv32")
elseif(ARCH STREQUAL "riscv64")
    MESSAGE("ARCH = riscv64")
elseif(ARCH STREQUAL "arc")
    MESSAGE("ARCH = arc")
elseif(ARCH STREQUAL "nios2")
    MESSAGE("ARCH = nios2")
else()
    MESSAGE(FATAL_ERROR "Unkown ARCH")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "GCC")
        MESSAGE("TOOLCHAIN = GCC")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        MESSAGE("TOOLCHAIN = CLANG")
    elseif(TOOLCHAIN STREQUAL "CBMC")
        MESSAGE("TOOLCHAIN = CBMC")
    elseif(TOOLCHAIN STREQUAL "AFL")
        MESSAGE("TOOLCHAIN = AFL")
    elseif(TOOLCHAIN STREQUAL "KLEE")
        MESSAGE("TOOLCHAIN = KLEE")
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        MESSAGE("TOOLCHAIN = LIBFUZZER")
    elseif(TOOLCHAIN STREQUAL "ARM_GCC")
        MESSAGE("TOOLCHAIN = ARM_GCC")
    elseif(TOOLCHAIN STREQUAL "AARCH64_GCC")
        MESSAGE("TOOLCHAIN = AARCH64_GCC")
    elseif(TOOLCHAIN STREQUAL "RISCV32_GCC")
        MESSAGE("TOOLCHAIN = RISCV32_GCC")
    elseif(TOOLCHAIN STREQUAL "RISCV64_GCC")
        MESSAGE("TOOLCHAIN = RISCV64_GCC")
    elseif(TOOLCHAIN STREQUAL "ARC_GCC")
        MESSAGE("TOOLCHAIN = ARC_GCC")
    elseif(TOOLCHAIN STREQUAL "NIOS2_GCC")
        MESSAGE("TOOLCHAIN = NIOS2_GCC")
    else()
        MESSAGE(FATAL_ERROR "Unkown TOOLCHAIN")
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "VS2015")
        MESSAGE("TOOLCHAIN = VS2015")
    elseif(TOOLCHAIN STREQUAL "VS2019")
        MESSAGE("TOOLCHAIN = VS2019")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        MESSAGE("TOOLCHAIN = CLANG")
    elseif(TOOLCHAIN STREQUAL "CBMC")
        MESSAGE("TOOLCHAIN = CBMC")
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        MESSAGE("TOOLCHAIN = LIBFUZZER")
    else()
        MESSAGE(FATAL_ERROR "Unkown TOOLCHAIN")
    endif()
else()
    MESSAGE(FATAL_ERROR "${CMAKE_SYSTEM_NAME} is not supportted")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    MESSAGE("TARGET = Debug")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    MESSAGE("TARGET = Release")
else()
    MESSAGE(FATAL_ERROR "Unkown build type")
endif()

if(CRYPTO STREQUAL "mbedtls")
    MESSAGE("CRYPTO = mbedtls")
elseif(CRYPTO STREQUAL "openssl")
    MESSAGE("CRYPTO = openssl")
else()
    MESSAGE(FATAL_ERROR "Unkown CRYPTO")
endif()

if(ENABLE_BINARY_BUILD STREQUAL "1")
    if(NOT CRYPTO STREQUAL "Openssl")
        MESSAGE(FATAL_ERROR "enabling binary build not supported for non-Openssl")
    endif()

    if(NOT COMPILED_LIBCRYPTO_PATH)
        MESSAGE(FATAL_ERROR "enabling binary build requires path to libcrypto.")
    endif()

    if(NOT COMPILED_LIBSSL_PATH)
        MESSAGE(FATAL_ERROR "enabling binary build requires path to libssl.")
    endif()

    MESSAGE("ENABLE_BINARY_BUILD=1")
    MESSAGE("COMPILED_LIBCRYPTO_PATH=${COMPILED_LIBCRYPTO_PATH}")
    MESSAGE("COMPILED_LIBSSL_PATH=${COMPILED_LIBSSL_PATH}")

    SET(CRYPTO_LIB_PATHS ${COMPILED_LIBCRYPTO_PATH} ${COMPILED_LIBSSL_PATH})
else()
    SET(CRYPTO_LIB_PATHS ${CRYPTO}lib)
    MESSAGE("ENABLE_BINARY_BUILD=0; Building ${CRYPTO} library from source.")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_EXE_EXPORTS_C_FLAG "")

    if(TOOLCHAIN STREQUAL "GCC")
        SET(CMAKE_C_COMPILER gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -maccumulate-outgoing-args -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR gcc-ar)

        if(NOT CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 9.3)
                SET(CMAKE_C_ARCHIVE_FINISH true)
        endif()

        SET(CMAKE_LINKER gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie --coverage -lgcov -fprofile-arcs -ftest-coverage" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "ARM_GCC")
        SET(CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR arm-linux-gnueabi-gcc-ar)

        SET(CMAKE_LINKER arm-linux-gnueabi-gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie --coverage -lgcov -fprofile-arcs -ftest-coverage" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "AARCH64_GCC")
        SET(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR aarch64-linux-gnu-gcc-ar)

        SET(CMAKE_LINKER aarch64-linux-gnu-gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie --coverage -lgcov -fprofile-arcs -ftest-coverage" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "RISCV32_GCC")
        SET(CMAKE_C_COMPILER riscv32-unknown-linux-gnu-gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR riscv32-unknown-linux-gnu-gcc-ar)

        SET(CMAKE_LINKER riscv32-unknown-linux-gnu-gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie --coverage -lgcov -fprofile-arcs -ftest-coverage" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "RISCV64_GCC")
        SET(CMAKE_C_COMPILER riscv64-linux-gnu-gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR riscv64-linux-gnu-gcc-ar)

        SET(CMAKE_LINKER riscv64-linux-gnu-gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie --coverage -lgcov -fprofile-arcs -ftest-coverage" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "ARC_GCC")
        SET(CMAKE_C_COMPILER arc-linux-gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR arc-linux-gcc-ar)

        SET(CMAKE_LINKER arc-linux-gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie --coverage -lgcov -fprofile-arcs -ftest-coverage" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")


    elseif(TOOLCHAIN STREQUAL "CLANG")
        SET(CMAKE_C_COMPILER clang)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall  -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common  -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO ")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR llvm-ar)

        SET(CMAKE_LINKER clang)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error -no-pie" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "CBMC")
        SET(CMAKE_C_COMPILER goto-cc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -maccumulate-outgoing-args -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare -DCBMC -DDEBUG_ASSERT_CHOICE=0")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_LINKER goto-cc)
        SET(CMAKE_EXE_LINKER_FLAGS "-flto -Wno-error")

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <OBJECTS> -o <TARGET>")

    elseif(TOOLCHAIN STREQUAL "AFL")
        SET(CMAKE_C_COMPILER afl-gcc)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -maccumulate-outgoing-args -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -DUSING_LTO  -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR gcc-ar)

        SET(CMAKE_LINKER gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "-Wno-error -no-pie" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "KLEE")
        SET(CMAKE_C_COMPILER clang)
        SET(CMAKE_C_FLAGS "-g -fno-strict-aliasing -Wall  -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common  -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO  -emit-llvm -DTEST_WITH_KLEE=TRUE -DDEBUG_ASSERT_CHOICE=0")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_C_CREATE_STATIC_LIBRARY "")

        SET(CMAKE_LINKER llvm-link)

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <OBJECTS> -o <TARGET>")

    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        SET(CMAKE_C_COMPILER clang)
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall  -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common  -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -DUSING_LTO  -DTEST_WITH_LIBFUZZER=TRUE -O1 -fsanitize=fuzzer,address")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR llvm-ar)

        SET(CMAKE_LINKER clang)
        SET(CMAKE_EXE_LINKER_FLAGS "-Wno-error -no-pie -fsanitize=fuzzer,address" )

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "NIOS2_GCC")
        SET(CMAKE_C_COMPILER nios2-elf-gcc)
        SET(CMAKE_C_FLAGS "-xc -MP -MMD -pipe -O3  -Wall -Wno-maybe-uninitialized -Wno-unused-but-set-variable -Wno-nonnull-compare -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast  -Wno-builtin-declaration-mismatch  -mno-hw-div -mhw-mul -mno-hw-mulx -mgpopt=global")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")

        SET(CMAKE_AR nios2-elf-ar)

        SET(CMAKE_LINKER nios2-elf-gcc)
        SET(CMAKE_EXE_LINKER_FLAGS "")

        SET(CMAKE_C_LINK_EXECUTABLE "")

    endif()

    if(NOT TOOLCHAIN STREQUAL "NIOS2_GCC")
        SET(CMAKE_C_FLAGS_RELEASE     "-Os")
        SET(CMAKE_C_FLAGS_DEBUG       "-O0")
    endif()

    if(ARCH STREQUAL "x64")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -mcmodel=small")
    elseif(ARCH STREQUAL "ia32")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    endif()

elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "CLANG")
        SET(CMAKE_C_COMPILER clang-cl.exe)
        SET(CMAKE_C_FLAGS "-fno-strict-aliasing -Wall  -Wno-array-bounds -Wno-address  -flto -DUSING_LTO  -D_CRT_SECURE_NO_WARNINGS /w")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "/FIbase.h")
        SET(CMOCKA_FLAGS " -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -Wformat")

        SET(CMAKE_STATIC_LINKER_FLAGS "")

        SET(CMAKE_LINKER lld-link.exe)
        SET(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /IGNORE:4086 /MLLVM:-exception-model=wineh /lldmap /OPT:REF")

        if(ARCH STREQUAL "x64")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64 /LIBPATH:'%VCToolsInstallDir%lib/x64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64'")
        elseif(ARCH STREQUAL "ia32")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386 /LIBPATH:'%VCToolsInstallDir%lib/x86' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86'")
        endif()

        SET(CMAKE_C_FLAGS_RELEASE     "-Oz")
        SET(CMAKE_C_FLAGS_DEBUG       "-O0 -gcodeview")

        SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG:GHASH")

        if(ARCH STREQUAL "x64")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
        elseif(ARCH STREQUAL "ia32")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -march=i586")
        endif()

        SET(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        SET(CMAKE_C_COMPILER clang-cl.exe)
        SET(CMAKE_C_FLAGS "-fno-strict-aliasing -Wall  -Wno-array-bounds -Wno-address  -flto -DUSING_LTO  -D_CRT_SECURE_NO_WARNINGS /w -DTEST_WITH_LIBFUZZER=TRUE -O1 -fsanitize=fuzzer,address")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "/FIbase.h")
        SET(CMOCKA_FLAGS " -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -Wformat")

        SET(CMAKE_STATIC_LINKER_FLAGS "")

        SET(CMAKE_LINKER lld-link.exe)
        SET(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /IGNORE:4086 /MLLVM:-exception-model=wineh /lldmap /OPT:REF")

        if(ARCH STREQUAL "x64")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64 /LIBPATH:'%VCToolsInstallDir%lib/x64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64' /LIBPATH:'%LLVM_PATH%/lib/clang/9.0.0/lib/windows'")
        elseif(ARCH STREQUAL "ia32")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386 /LIBPATH:'%VCToolsInstallDir%lib/x86' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86' /LIBPATH:'%LLVMx86_PATH%/lib/clang/9.0.0/lib/windows'")
        endif()

        SET(CMAKE_C_FLAGS_RELEASE     "-Oz")
        SET(CMAKE_C_FLAGS_DEBUG       "-O0 -gcodeview")

        SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG:GHASH")

        if(ARCH STREQUAL "x64")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
        elseif(ARCH STREQUAL "ia32")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -march=i586")
        endif()

        if(ARCH STREQUAL "x64")
            SET(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib clang_rt.asan_dynamic-x86_64.lib clang_rt.asan_dynamic_runtime_thunk-x86_64.lib clang_rt.fuzzer-x86_64.lib")
        elseif(ARCH STREQUAL "ia32")
            SET(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib clang_rt.asan_dynamic-i386.lib clang_rt.asan_dynamic_runtime_thunk-i386.lib clang_rt.fuzzer-i386.lib")
        endif()

    elseif(TOOLCHAIN STREQUAL "CBMC")
        SET(CMAKE_C_COMPILER goto-cl.exe)
        SET(CMAKE_C_FLAGS "/nologo /WX /W4 /Gs32768 /D UNICODE /Gy /EHs-c- /GR- /GF /Z7 /Oy- /D_CRT_SECURE_NO_WARNINGS /DCBMC_CC")
        SET(MBEDTLS_FLAGS "/wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127")
        SET(OPENSSL_FLAGS "/FIbase.h /wd4090 /wd4132 /wd4244 /wd4245 /wd4267 /wd4306 /wd4310 /wd4700 /wd4389 /wd4702 /wd4706 /wd4819 /wd4013")
        SET(CMOCKA_FLAGS "/wd4204 /wd4133 /wd4267 /wd4701 /wd4702 /wd4703 /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1 /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1 /D _CRT_NONSTDC_NO_WARNINGS=1")

        SET(CMAKE_C_CREATE_STATIC_LIBRARY "")

        SET(CMAKE_LINKER goto-cl.exe)

        SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <OBJECTS>")

        SET(CMAKE_C_FLAGS_RELEASE     "/GL /O1b2s")
        SET(CMAKE_C_FLAGS_DEBUG       "/Od")
    else()
        SET(CMAKE_C_FLAGS "/nologo /WX /W4 /Gs32768 /D UNICODE /Gy /EHs-c- /GR- /GF /Z7 /Gw /Oy- /D_CRT_SECURE_NO_WARNINGS /wd4063")
        SET(MBEDTLS_FLAGS "/wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127")
        SET(OPENSSL_FLAGS "/FIbase.h /wd4090 /wd4132 /wd4244 /wd4245 /wd4267 /wd4306 /wd4310 /wd4700 /wd4389 /wd4702 /wd4706 /wd4819 /wd4013")
        SET(CMOCKA_FLAGS "/wd4204 /wd4133 /wd4267 /wd4701 /wd4702 /wd4703 /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1 /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1 /D _CRT_NONSTDC_NO_WARNINGS=1")

        SET(CMAKE_STATIC_LINKER_FLAGS "/NOLOGO /LTCG")

        SET(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /IGNORE:4086 /MAP /OPT:REF")

        SET(CMAKE_C_FLAGS_RELEASE     "/GL /O1b2s")
        SET(CMAKE_C_FLAGS_DEBUG       "/Od")
        SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG")
        SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG")

        if(ARCH STREQUAL "x64")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64")
        elseif(ARCH STREQUAL "ia32")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386")
        endif()
        SET(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")

    endif()
endif()

if(TOOLCHAIN STREQUAL "VS2015")
    if(ARCH STREQUAL "x64")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCINSTALLDIR%Lib/AMD64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64'")
    elseif(ARCH STREQUAL "ia32")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCINSTALLDIR%Lib' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86'")
    endif()
elseif(TOOLCHAIN STREQUAL "VS2019")
    if(ARCH STREQUAL "x64")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCToolsInstallDir%lib/x64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64'")
    elseif(ARCH STREQUAL "ia32")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCToolsInstallDir%lib/x86' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86'")
    endif()
endif()

SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

ADD_CUSTOM_TARGET(copy_sample_key)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_CUSTOM_COMMAND(TARGET copy_sample_key
                    PRE_BUILD
                    COMMAND cp -r -f ${LIBSPDM_DIR}/unit_test/sample_key/* ${EXECUTABLE_OUTPUT_PATH})
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    STRING(REPLACE "/" "\\" SRC ${LIBSPDM_DIR}/unit_test/sample_key/*)
    STRING(REPLACE "/" "\\" DEST ${EXECUTABLE_OUTPUT_PATH})

    ADD_CUSTOM_COMMAND(TARGET copy_sample_key
                       PRE_BUILD
                       COMMAND xcopy /y /s ${SRC} ${DEST})
endif()

if(CRYPTO STREQUAL "mbedtls")
    ADD_SUBDIRECTORY(os_stub/cryptlib_mbedtls)
elseif(CRYPTO STREQUAL "openssl")
    ADD_SUBDIRECTORY(os_stub/cryptlib_openssl)
endif()

if(NOT ENABLE_BINARY_BUILD STREQUAL "1")
    if(CRYPTO STREQUAL "mbedtls")
        ADD_SUBDIRECTORY(os_stub/mbedtlslib)
    elseif(CRYPTO STREQUAL "openssl")
        ADD_SUBDIRECTORY(os_stub/openssllib)
    endif()
endif()

    ADD_SUBDIRECTORY(library/spdm_common_lib)
    ADD_SUBDIRECTORY(library/spdm_requester_lib)
    ADD_SUBDIRECTORY(library/spdm_responder_lib)
    ADD_SUBDIRECTORY(library/spdm_crypt_lib)
    ADD_SUBDIRECTORY(library/spdm_secured_message_lib)
    ADD_SUBDIRECTORY(library/spdm_transport_mctp_lib)
    ADD_SUBDIRECTORY(library/spdm_transport_pcidoe_lib)
    ADD_SUBDIRECTORY(os_stub/memlib)
    ADD_SUBDIRECTORY(os_stub/debuglib)
    ADD_SUBDIRECTORY(os_stub/debuglib_null)
    ADD_SUBDIRECTORY(os_stub/rnglib)
    ADD_SUBDIRECTORY(os_stub/malloclib)
    ADD_SUBDIRECTORY(os_stub/spdm_device_secret_lib)
    ADD_SUBDIRECTORY(os_stub/spdm_device_secret_lib_null)
    ADD_SUBDIRECTORY(unit_test/spdm_transport_test_lib)
    ADD_SUBDIRECTORY(unit_test/cmockalib)

    ADD_SUBDIRECTORY(unit_test/test_spdm_requester)
    ADD_SUBDIRECTORY(unit_test/test_spdm_responder)
    ADD_SUBDIRECTORY(unit_test/test_crypt)

    ADD_SUBDIRECTORY(unit_test/fuzzing/test_spdm_requester_get_version)
    ADD_SUBDIRECTORY(unit_test/fuzzing/test_spdm_responder_version)

    ADD_SUBDIRECTORY(unit_test/test_size/cryptlib_dummy)
    ADD_SUBDIRECTORY(unit_test/test_size/cryptstublib_dummy)
    ADD_SUBDIRECTORY(unit_test/test_size/intrinsiclib)
    ADD_SUBDIRECTORY(unit_test/test_size/malloclib_null)
    ADD_SUBDIRECTORY(unit_test/test_spdm_common)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "x64")
        ADD_SUBDIRECTORY(unit_test/test_size/test_size_of_spdm_requester)
        ADD_SUBDIRECTORY(unit_test/test_size/test_size_of_spdm_responder)
    endif()
endif()
