cmake_minimum_required(VERSION 3.16)

# The compiler must be selected before project(), which identifies it.
if(NOT CMAKE_TOOLCHAIN_FILE AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/${TOOLCHAIN}.cmake")
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/${TOOLCHAIN}.cmake")
endif()

project("libspdm" C)

file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/VERSION.md CMAKE_INPUT_PROJECT_VERSION)
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" PROJECT_VERSION ${CMAKE_INPUT_PROJECT_VERSION})
set(CMAKE_PROJECT_VERSION ${PROJECT_VERSION})

# VERSION.md tags in-progress entries with a lifecycle marker. Reflect that in
# the produced artifacts (shared lib SONAME / pkg-config 'Version' field) so a
# build is distinguishable from a tagged release of the same X.Y.Z:
#   "(pending and unreleased)" -> X.Y.Z-alpha
#   "(release candidate)"      -> X.Y.Z-rc
if(CMAKE_INPUT_PROJECT_VERSION MATCHES "pending and unreleased")
    set(PROJECT_VERSION "${PROJECT_VERSION}-alpha")
    set(CMAKE_PROJECT_VERSION ${PROJECT_VERSION})
elseif(CMAKE_INPUT_PROJECT_VERSION MATCHES "release candidate")
    set(PROJECT_VERSION "${PROJECT_VERSION}-rc")
    set(CMAKE_PROJECT_VERSION ${PROJECT_VERSION})
endif()

#
# Build Configuration Macro Definition
#
message("#########################")
message("## Build Configuration ##")
message("#########################")

set(CMAKE_GENERATOR ${CMAKE_GENERATOR} CACHE STRING "Choose the generator of cmake")

# Detect ARCH only if not set
if(NOT DEFINED ARCH)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" DETECTED_ARCH)

    if (DETECTED_ARCH STREQUAL "amd64" OR DETECTED_ARCH STREQUAL "x86_64")
        set(DETECTED_ARCH "x64")
    elseif (DETECTED_ARCH STREQUAL "x86" OR DETECTED_ARCH STREQUAL "i386" OR DETECTED_ARCH STREQUAL "i686")
        set(DETECTED_ARCH "ia32")
    endif()

    message(STATUS "Auto-detected ARCH = ${DETECTED_ARCH}")
    set(ARCH "${DETECTED_ARCH}")
endif()

set(ARCH ${ARCH} CACHE STRING "Choose the arch of build: ia32 x64 arm aarch64 riscv32 riscv64 arc loongarch64" FORCE)
set(TOOLCHAIN ${TOOLCHAIN} CACHE STRING "Choose the toolchain of build: Windows: VS2019 VS2022 CLANG ARM_DS2022 LIBFUZZER Linux: GCC ARM_DS2022 ARM_GNU ARM_GNU_BARE_METAL ARM_GCC AARCH64_GCC RISCV_GNU RISCV64_GCC RISCV_XPACK ARC_GCC LOONGARCH64_GNU CLANG AFL LIBFUZZER" FORCE)
set(CMAKE_BUILD_TYPE ${TARGET} CACHE STRING "Choose the target of build: Debug Release" FORCE)
set(CRYPTO ${CRYPTO} CACHE STRING "Choose the crypto of build: mbedtls openssl" FORCE)
set(GCOV ${GCOV} CACHE STRING "Choose the target of Gcov: ON  OFF, and default is OFF" FORCE)
set(STACK_USAGE ${STACK_USAGE} CACHE STRING "Choose the target of STACK_USAGE: ON  OFF, and default is OFF" FORCE)
set(BUILD_LINUX_SHARED_LIB ${BUILD_LINUX_SHARED_LIB} CACHE STRING "Choose if libspdm shared library should be built for linux: ON OFF, and default is OFF" FORCE)
set(X509_IGNORE_CRITICAL ${X509_IGNORE_CRITICAL} CACHE STRING "Choose if libspdm-provided cryptography libraries (OpenSSL and MbedTLS) ignore unsupported critical extensions in certificates : ON OFF, and default is OFF" FORCE)
set(X509_IGNORE_TIME ${X509_IGNORE_TIME} CACHE STRING "Choose if libspdm-provided cryptography libraries (OpenSSL and MbedTLS) ignore the validity period of certificates : ON OFF, and default is OFF" FORCE)
set(DEVICE ${DEVICE} CACHE STRING "Choose the test device: sample tpm, and default is sample" FORCE)

option(LIBSPDM_TPM_SUPPORT "Add TPM support in crypt_ext" OFF)

if(NOT GCOV)
    set(GCOV "OFF")
endif()

if(NOT STACK_USAGE)
    set(STACK_USAGE "OFF")
endif()

if(NOT BUILD_LINUX_SHARED_LIB)
    set(BUILD_LINUX_SHARED_LIB "OFF")
endif()

if(NOT X509_IGNORE_CRITICAL)
    set(X509_IGNORE_CRITICAL "OFF")
endif()

if(NOT X509_IGNORE_TIME)
    set(X509_IGNORE_TIME "OFF")
endif()

if (NOT DEVICE)
    set(DEVICE "sample")
endif()


set(LIBSPDM_DIR ${PROJECT_SOURCE_DIR})
include_directories(
  "${LIBSPDM_DIR}/include"
  "${LIBSPDM_DIR}/os_stub/include"
)

#
# OpenSSL specific compiled libraries.
#
set(COMPILED_LIBCRYPTO_PATH ${COMPILED_LIBCRYPTO_PATH} CACHE STRING "Optionally provide a path to libcrypto" FORCE)
set(COMPILED_LIBSSL_PATH ${COMPILED_LIBSSL_PATH} CACHE STRING "Optionally provide a path to libssl" FORCE)

message("CMAKE_GENERATOR = ${CMAKE_GENERATOR}")
message("DEVICE = ${DEVICE}")

if(ARCH STREQUAL "x64")
    message("ARCH = x64")
elseif(ARCH STREQUAL "x86_64")
    message("ARCH = x64")
elseif(ARCH STREQUAL "ia32")
    message("ARCH = ia32")
elseif(ARCH STREQUAL "arm")
    message("ARCH = arm")
elseif(ARCH STREQUAL "aarch64")
    message("ARCH = aarch64")
elseif(ARCH STREQUAL "ppc64le")
    message("ARCH = ppc64le")
elseif(ARCH STREQUAL "riscv32")
    message("ARCH = riscv32")
elseif(ARCH STREQUAL "riscv64")
    message("ARCH = riscv64")
elseif(ARCH STREQUAL "arc")
    message("ARCH = arc")
elseif(ARCH STREQUAL "nios2")
    message("ARCH = nios2")
elseif(ARCH STREQUAL "loongarch64")
    message("ARCH = loongarch64")
else()
    message(FATAL_ERROR "Unknown ARCH : ${ARCH}")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "GCC")
        message("TOOLCHAIN = GCC")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        message("TOOLCHAIN = CLANG")
    elseif(TOOLCHAIN STREQUAL "AFL")
        message("TOOLCHAIN = AFL")
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        message("TOOLCHAIN = LIBFUZZER")
    elseif(TOOLCHAIN STREQUAL "ARM_DS2022")
        message("TOOLCHAIN = ARM_DS2022")
    elseif(TOOLCHAIN STREQUAL "ARM_GNU")
        message("TOOLCHAIN = ARM_GNU")
    elseif(TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL")
        message("TOOLCHAIN = ARM_GNU_BARE_METAL")
    elseif(TOOLCHAIN STREQUAL "ARM_GCC")
        message("TOOLCHAIN = ARM_GCC")
    elseif(TOOLCHAIN STREQUAL "AARCH64_GCC")
        message("TOOLCHAIN = AARCH64_GCC")
    elseif(TOOLCHAIN STREQUAL "RISCV_GNU")
        message("TOOLCHAIN = RISCV_GNU")
    elseif(TOOLCHAIN STREQUAL "RISCV64_GCC")
        message("TOOLCHAIN = RISCV64_GCC")
    elseif(TOOLCHAIN STREQUAL "RISCV_NONE")
        message("TOOLCHAIN = RISCV_NONE")
    elseif(TOOLCHAIN STREQUAL "RISCV_XPACK")
        message("TOOLCHAIN = RISCV_XPACK")
    elseif(TOOLCHAIN STREQUAL "ARC_GCC")
        message("TOOLCHAIN = ARC_GCC")
    elseif(TOOLCHAIN STREQUAL "LOONGARCH64_GNU")
        message("TOOLCHAIN = LOONGARCH64_GNU")
    elseif(TOOLCHAIN STREQUAL "NIOS2_GCC")
        message("TOOLCHAIN = NIOS2_GCC")
    elseif(TOOLCHAIN STREQUAL "NONE")
        message("TOOLCHAIN = NONE")
    else()
        message(FATAL_ERROR "Unknown TOOLCHAIN")
    endif()
    if(GCOV STREQUAL "ON")
        message("GCOV = ON")
    elseif(GCOV STREQUAL "OFF")
        message("GCOV = OFF")
    else()
        message(FATAL_ERROR "Unknown GCOV switch input")
    endif()
    if(STACK_USAGE STREQUAL "ON")
        message("STACK_USAGE = ON")
    endif()
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    if (TOOLCHAIN STREQUAL "CLANG")
        message("TOOLCHAIN = CLANG")
    else()
        message(FATAL_ERROR "Unknown TOOLCHAIN")
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "GCC")
        message("TOOLCHAIN = GCC")
    elseif(TOOLCHAIN STREQUAL "VS2019")
        message("TOOLCHAIN = VS2019")
    elseif(TOOLCHAIN STREQUAL "VS2022")
        message("TOOLCHAIN = VS2022")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        message("TOOLCHAIN = CLANG")
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        message("TOOLCHAIN = LIBFUZZER")
    elseif(TOOLCHAIN STREQUAL "ARM_DS2022")
        message("TOOLCHAIN = ARM_DS2022")
    else()
        message(FATAL_ERROR "Unknown TOOLCHAIN")
    endif()
else()
    message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} is not supportted")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("TARGET = Debug")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message("TARGET = Release")
else()
    message(FATAL_ERROR "Unknown build type")
endif()

# Configuration definitions for libspdm's own targets. libspdm_configure_targets() at the end of this
# file applies them.
set(LIBSPDM_CONFIG_DEFINITIONS "")

if(CRYPTO STREQUAL "mbedtls")
    message("CRYPTO = mbedtls")
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SM3_256_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_EDDSA_ED25519_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_EDDSA_ED448_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SM2_DSA_P256_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_AEAD_SM4_128_GCM_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_ML_DSA_44_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_ML_DSA_65_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_ML_DSA_87_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_ML_KEM_512_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_ML_KEM_768_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_ML_KEM_1024_SUPPORT=0)
    # mbedtls does not evaluate X.509 nameConstraints (Mbed-TLS/mbedtls#8759).
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SKIP_NAME_CONSTRAINTS_CHECK=1)
elseif(CRYPTO STREQUAL "openssl")
    message("CRYPTO = openssl")
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_AEAD_SM4_128_GCM_SUPPORT=0)
else()
    message(FATAL_ERROR "Unknown CRYPTO")
endif()

if (LIBSPDM_TPM_SUPPORT)
    if (NOT CRYPTO STREQUAL "openssl")
        message(FATAL_ERROR "${CRYPTO} does not support TPM")
    endif ()
    message(STATUS "crypt_ext tpm supported enabled")
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_TPM_SUPPORT=1)
endif()

if (X509_IGNORE_CRITICAL STREQUAL "ON")
    if (CRYPTO STREQUAL "openssl")
        list(APPEND LIBSPDM_CONFIG_DEFINITIONS OPENSSL_IGNORE_CRITICAL=1)
    elseif(CRYPTO STREQUAL "mbedtls")
        list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
    endif()
endif()

if (X509_IGNORE_TIME STREQUAL "ON")
    if (CRYPTO STREQUAL "openssl")
        list(APPEND LIBSPDM_CONFIG_DEFINITIONS OPENSSL_IGNORE_TIME=1)
    elseif(CRYPTO STREQUAL "mbedtls")
        list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_MBEDTLS_X509_IGNORE_TIME)
    endif()
endif()

if(ENABLE_BINARY_BUILD STREQUAL "1")
    if(NOT CRYPTO STREQUAL "openssl")
        message(FATAL_ERROR "enabling binary build not supported for non-openssl")
    endif()

    if(NOT COMPILED_LIBCRYPTO_PATH)
        message(FATAL_ERROR "enabling binary build requires path to libcrypto.")
    endif()

    if(NOT COMPILED_LIBSSL_PATH)
        message(FATAL_ERROR "enabling binary build requires path to libssl.")
    endif()

    # Disable EDDSA when binary builds are enabled. EDDSA may be enabled in the future.
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_EDDSA_ED25519_SUPPORT=0)
    list(APPEND LIBSPDM_CONFIG_DEFINITIONS LIBSPDM_EDDSA_ED448_SUPPORT=0)

    message("ENABLE_BINARY_BUILD=1")
    message("COMPILED_LIBCRYPTO_PATH=${COMPILED_LIBCRYPTO_PATH}")
    message("COMPILED_LIBSSL_PATH=${COMPILED_LIBSSL_PATH}")
    message("Disabling EDDSA support due to ENABLE_BINARY_BUILD=1")

    set(CRYPTO_LIB_PATHS ${COMPILED_LIBCRYPTO_PATH} ${COMPILED_LIBSSL_PATH})

else()
    set(CRYPTO_LIB_PATHS ${CRYPTO}lib)
    message("ENABLE_BINARY_BUILD=0; Building ${CRYPTO} library from source.")
endif()

if(ENABLE_CODEQL STREQUAL "ON")
    message("Enable CodeQL scan.")
endif()

# Warning options for libspdm's own targets. libspdm_configure_targets() at the end of this file
# applies them, so the third-party code that libspdm builds keeps its compiler's default warnings.
# The toolchain blocks below append toolchain-specific options.
if((TOOLCHAIN STREQUAL "ARM_DS2022") OR (TOOLCHAIN STREQUAL "RISCV_NONE") OR (TOOLCHAIN STREQUAL "NONE"))
    # ARM_DS2022 and RISCV_NONE have never enabled warnings, and CI does not build them. NONE
    # takes its flags from the build environment, such as Buildroot or OpenEmbedded.
    set(LIBSPDM_WARNING_OPTIONS "")
elseif(MSVC)
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        # Clang-cl reads -Wall as /Wall, which is -Weverything, so /W3 and /WX stand in for -Wall
        # and -Werror.
        set(LIBSPDM_WARNING_OPTIONS /W3 /WX -Werror-implicit-function-declaration -Wcast-qual)
    else()
        set(LIBSPDM_WARNING_OPTIONS /W4 /WX /wd4100 /wd4127 /wd4701 /wd4703)
    endif()
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(LIBSPDM_WARNING_OPTIONS -Wall -Werror -Werror-implicit-function-declaration -Wcast-qual
        -Wno-maybe-uninitialized)
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(LIBSPDM_WARNING_OPTIONS -Wall -Werror -Werror-implicit-function-declaration -Wcast-qual)
endif()

# GCC 10 and later run the link-time code generation in parallel with -flto=auto. Earlier
# versions only accept -flto.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10)
    set(GCC_LTO_FLAG -flto=auto)
else()
    set(GCC_LTO_FLAG -flto)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(CMAKE_EXE_EXPORTS_C_FLAG "")

    if(TOOLCHAIN STREQUAL "GCC")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables)
        if (ARCH STREQUAL "x64")
            add_compile_options(-mno-red-zone)
        endif()
        if (ARCH STREQUAL "x64" OR ARCH STREQUAL "ia32")
            add_compile_options(-maccumulate-outgoing-args)
        endif()
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            add_compile_options(-g)
        endif()
        if(STACK_USAGE STREQUAL "ON")
            add_compile_options(-fstack-usage)
        else()
            add_compile_options(${GCC_LTO_FLAG})
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        if(NOT CMAKE_C_COMPILER_VERSION VERSION_GREATER 9.2)
                set(CMAKE_C_ARCHIVE_FINISH true)
        endif()

        string(APPEND CMAKE_EXE_LINKER_FLAGS " ${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()
        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "ARM_DS2022")
        if(ARCH STREQUAL "aarch64")
            set(CMAKE_SYSTEM_NAME   Linux)
            set(CMAKE_OBJCOPY       fromelf)

            set(CMAKE_EXECUTABLE_SUFFIX ".elf")
            set(CMAKE_LIBRARY_PATH_FLAG "--userlibpath=")
            add_compile_options(-fno-strict-aliasing  -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables -flto)
            set(CMAKE_C_CREATE_STATIC_LIBRARY "armar -r -s --create <TARGET> <LINK_FLAGS> <OBJECTS>")
            set(CMAKE_SYSTEM_PROCESSOR aarch64v)
            add_compile_options(--target=aarch64-arm-none-eabi)
            set(CMAKE_EXE_LINKER_FLAGS "--target=aarch64-arm-none-eabi -flto -Wl,--undefined=__udivti3")
        elseif(ARCH STREQUAL "arm")
            set(CMAKE_SYSTEM_NAME   Linux)
            set(CMAKE_SYSTEM_PROCESSOR arm)

            set(CMAKE_EXECUTABLE_SUFFIX ".elf")
            add_compile_options(--target=arm-arm-none-eabi -march=armv9-a)
            set(CMAKE_EXE_LINKER_FLAGS "--target=arm-arm-none-eabi -march=armv9-a -Wl,--undefined=__udivti3")
        endif()

        # Link through armclang. CMake's ARMClang rules call armlink, which does not accept the
        # --target and -Wl, options above.
        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_C_COMPILER> <FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

        set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
        set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

    elseif(TOOLCHAIN STREQUAL "ARM_GNU")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")


    elseif(TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL")
        if(DISABLE_LTO STREQUAL "1")
            set(FLTO_COMPILE_OPTS "-fno-lto")
            set(FLTO_LINK_OPTS "-fno-lto")
        else()
            if (DEFINED USING_LTO)
                set(FLTO_COMPILE_OPTS "${GCC_LTO_FLAG}" "-${USING_LTO}")
            else()
                set(FLTO_COMPILE_OPTS "${GCC_LTO_FLAG}")
            endif()
            set(FLTO_LINK_OPTS "${GCC_LTO_FLAG}")
        endif()
        set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${FLTO_COMPILE_OPTS})
        list(APPEND LIBSPDM_WARNING_OPTIONS -Wno-error=format)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            add_compile_options(-g)
        endif()

        string(APPEND CMAKE_EXE_LINKER_FLAGS " ${FLTO_LINK_OPTS}")

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "ARM_GCC")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()
        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "AARCH64_GCC")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "RISCV_GNU")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "RISCV64_GCC")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "RISCV_NONE")
        add_compile_options(-nostdlib -lgcc)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()


        set(MBEDTLS_FLAGS -nostdlib -lgcc)

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "RISCV_XPACK")
        set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        list(APPEND LIBSPDM_WARNING_OPTIONS -Wno-error=format)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()

        string(APPEND CMAKE_EXE_LINKER_FLAGS " ${GCC_LTO_FLAG}")

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "ARC_GCC")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "LOONGARCH64_GNU")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables ${GCC_LTO_FLAG})
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
            add_compile_options(--coverage)
        endif()

        set(CMAKE_EXE_LINKER_FLAGS "${GCC_LTO_FLAG}")
        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "CLANG")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables -flto)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if (ARCH STREQUAL "x64")
            add_compile_options(-mno-red-zone)
        endif()

        string(APPEND CMAKE_EXE_LINKER_FLAGS " -flto")

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "AFL")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -maccumulate-outgoing-args -mno-red-zone -fno-asynchronous-unwind-tables)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        # -O1 may cause fuzzing test buffer overflow, use -O0 as workaround
        # ASSERT_CONFIG=EXIT because the default deadloops, which under a fuzzer pins a core
        # until the timeout and reports a hang instead of the assertion that fired.
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -mno-red-zone -fno-asynchronous-unwind-tables -DTEST_WITH_LIBFUZZER=TRUE -DLIBSPDM_DEBUG_LIBSPDM_ASSERT_CONFIG=3 -O0 -fsanitize=fuzzer,address)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
           add_compile_options(-g)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
        endif()

        string(APPEND CMAKE_EXE_LINKER_FLAGS " -fsanitize=fuzzer,address")
        if(GCOV STREQUAL "ON")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate")
        endif()

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")

    elseif(TOOLCHAIN STREQUAL "NIOS2_GCC")
        add_compile_options(-xc -MP -MMD -pipe -O3)
        list(APPEND LIBSPDM_WARNING_OPTIONS -Wno-unused-but-set-variable -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast)

        set(CMAKE_EXE_LINKER_FLAGS "")

        set(CMAKE_C_LINK_EXECUTABLE "")
    endif()

    if(NOT TOOLCHAIN STREQUAL "NIOS2_GCC")
        set(CMAKE_C_FLAGS_RELEASE     "-Os")
        set(CMAKE_C_FLAGS_DEBUG       "-O0")
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    if (TOOLCHAIN STREQUAL "CLANG")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            add_compile_options(-g -Og)
        endif()

        set(MBEDTLS_FLAGS "")

        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "GCC")
        add_compile_options(-fno-strict-aliasing -ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables)
        if (ARCH STREQUAL "x64")
            add_compile_options(-mno-red-zone)
        endif()
        if (ARCH STREQUAL "x64" OR ARCH STREQUAL "ia32")
            add_compile_options(-maccumulate-outgoing-args)
        endif()
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            add_compile_options(-g)
        endif()
        if(STACK_USAGE STREQUAL "ON")
            add_compile_options(-fstack-usage)
        else()
            add_compile_options(-fno-lto)
        endif()
        if(GCOV STREQUAL "ON")
        add_compile_options(--coverage)
        endif()

        if(NOT CMAKE_C_COMPILER_VERSION VERSION_GREATER 9.2)
                set(CMAKE_C_ARCHIVE_FINISH true)
        endif()

        if(GCOV STREQUAL "ON")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
        endif()
        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group -lbcrypt <LINK_LIBRARIES> -Wl,--end-group")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        add_compile_options(-fno-strict-aliasing -flto -D_CRT_SECURE_NO_WARNINGS)

        set(CMAKE_STATIC_LINKER_FLAGS "")

        set(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /MLLVM:-exception-model=wineh /lldmap /OPT:REF")

        if(ARCH STREQUAL "x64")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64")
        elseif(ARCH STREQUAL "ia32")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386")
        endif()

        # clang-cl ignores -Oz, and -gcodeview turns on debug information only from LLVM 22.
        set(CMAKE_C_FLAGS_RELEASE     "/O1")
        set(CMAKE_C_FLAGS_DEBUG       "/Od /Z7")

        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG:GHASH")

        # CMake selects the DLL C runtime, /MD or /MDd, whose objects name its libraries.
        set(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")

    elseif(TOOLCHAIN STREQUAL "ARM_DS2022")
        set(CMAKE_OBJCOPY       "fromelf.exe")
        set(CMAKE_${lang}_COMPILER_FRONTEND_VARIANT "GNU")
        set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
        set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
        set(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_PATH})
        set(CMAKE_EXECUTABLE_SUFFIX ".elf")

        if (ARCH STREQUAL "arm")
        set(CMAKE_SYSTEM_PROCESSOR ARM)
        add_compile_options(-marm)
        add_compile_options(--target=arm-arm-none-eabi)
        elseif (ARCH STREQUAL "aarch64")
        set(CMAKE_SYSTEM_PROCESSOR aarch64v)
        add_compile_options(--target=aarch64-arm-none-eabi -Wl,--undefined=__udivti3)
        endif()

        set(CMAKE_SYSTEM_NAME Linux )
        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> -o <TARGET> <LINK_LIBRARIES> <OBJECTS>")

    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        add_compile_options(-fno-strict-aliasing -flto -D_CRT_SECURE_NO_WARNINGS -DTEST_WITH_LIBFUZZER=TRUE)

        set(CMAKE_STATIC_LINKER_FLAGS "")

        # clang_rt.fuzzer names the static C runtime, libcmt.lib, which /MD builds must not link.
        set(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /MLLVM:-exception-model=wineh /lldmap /OPT:REF")

        if(ARCH STREQUAL "x64")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64")
        elseif(ARCH STREQUAL "ia32")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386")
        endif()

        # clang-cl ignores -Oz, and -gcodeview turns on debug information only from LLVM 22.
        set(CMAKE_C_FLAGS_RELEASE     "/O1")
        set(CMAKE_C_FLAGS_DEBUG       "/Od /Z7")

        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG:GHASH")

        # The ASan runtime does not support the debug C runtime, so Debug builds also use /MD, whose
        # objects name its libraries.
        set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
        if(ARCH STREQUAL "x64")
            set(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")
            set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES} C:/LLVM/lib/clang/13.0.0/lib/windows/clang_rt.asan_dynamic-x86_64.lib C:/LLVM/lib/clang/13.0.0/lib/windows/clang_rt.asan_dynamic_runtime_thunk-x86_64.lib C:/LLVM/lib/clang/13.0.0/lib/windows/clang_rt.fuzzer-x86_64.lib")
        elseif(ARCH STREQUAL "ia32")
            set(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib clang_rt.asan_dynamic-i386.lib clang_rt.asan_dynamic_runtime_thunk-i386.lib clang_rt.fuzzer-i386.lib")
        endif()

    else()
        # MSVC has no C99 mode, and CMake before 3.19 passes no option for C_STANDARD 11.
        # /utf-8 because cmocka.h is UTF-8, which the system code page may not represent.
        add_compile_options(/std:c11 /utf-8 /nologo /Gs32768 /Gy /GF /Z7 /Gw /Oy- /D_CRT_SECURE_NO_WARNINGS)

        set(CMAKE_STATIC_LINKER_FLAGS "/NOLOGO /LTCG")

        set(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /MAP /OPT:REF")

        set(CMAKE_C_FLAGS_RELEASE     "/GL /O1b2s")
        set(CMAKE_C_FLAGS_DEBUG       "/Od")
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG")
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG")

        if(ARCH STREQUAL "x64")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64")
        elseif(ARCH STREQUAL "ia32")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386")
        endif()
        # CMake selects the DLL C runtime, /MD or /MDd, whose objects name its libraries.
        set(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")

    endif()
endif()

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

add_custom_target(copy_sample_key)

execute_process(COMMAND uname OUTPUT_VARIABLE uname)
if(CMAKE_SYSTEM_NAME MATCHES "Linux" OR uname MATCHES "^MINGW" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_custom_command(TARGET copy_sample_key
                    PRE_BUILD
                    COMMAND cp -r -f ${LIBSPDM_DIR}/unit_test/sample_key/* ${EXECUTABLE_OUTPUT_PATH})
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    string(REPLACE "/" "\\" SRC ${LIBSPDM_DIR}/unit_test/sample_key/*)
    if(CMAKE_GENERATOR MATCHES "^Visual Studio")
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            string(REPLACE "/" "\\" DEST ${EXECUTABLE_OUTPUT_PATH}/Debug)
        else()
            string(REPLACE "/" "\\" DEST ${EXECUTABLE_OUTPUT_PATH}/Release)
        endif()
    else()
        string(REPLACE "/" "\\" DEST ${EXECUTABLE_OUTPUT_PATH})
    endif()
    add_custom_command(TARGET copy_sample_key
                    PRE_BUILD
                    COMMAND xcopy /y /s ${SRC} ${DEST})
endif()

add_custom_target(copy_seed)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" OR uname MATCHES "^MINGW" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_custom_command(TARGET copy_seed
                    PRE_BUILD
                    COMMAND cp -r -f ${LIBSPDM_DIR}/unit_test/fuzzing/seeds ${EXECUTABLE_OUTPUT_PATH}
                    COMMAND cp -r -f ${LIBSPDM_DIR}/unit_test/fuzzing/run_initial_seed.sh ${EXECUTABLE_OUTPUT_PATH})
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    string(REPLACE "/" "\\" SRC ${LIBSPDM_DIR}/unit_test/fuzzing/seeds)
    string(REPLACE "/" "\\" DEST ${EXECUTABLE_OUTPUT_PATH})

    add_custom_command(TARGET copy_seed
                       PRE_BUILD
                       COMMAND xcopy /y /s ${SRC} ${DEST})
endif()

list(APPEND LIBSPDM_CONFIG_DEFINITIONS $<$<CONFIG:Release>:LIBSPDM_DEBUG_ENABLE=0>)

if(ENABLE_CODEQL STREQUAL "ON")
    add_subdirectory(library/spdm_common_lib)
    add_subdirectory(library/spdm_requester_lib)
    add_subdirectory(library/spdm_responder_lib)
    add_subdirectory(library/spdm_crypt_lib)
    add_subdirectory(library/spdm_secured_message_lib)
    add_subdirectory(library/spdm_transport_mctp_lib)
    add_subdirectory(library/spdm_transport_pcidoe_lib)
    add_subdirectory(library/spdm_transport_tcp_lib)
    ADD_SUBDIRECTORY(library/spdm_transport_storage_lib)
    add_subdirectory(os_stub/memlib)
    add_subdirectory(os_stub/debuglib)
    add_subdirectory(os_stub/debuglib_null)
    add_subdirectory(os_stub/rnglib)
    add_subdirectory(os_stub/platform_lib)
    add_subdirectory(os_stub/platform_lib_null)
    add_subdirectory(os_stub/malloclib)
    add_subdirectory(os_stub/spdm_device_secret_lib_${DEVICE})
    add_subdirectory(os_stub/spdm_device_secret_lib_null)
    add_subdirectory(os_stub/spdm_cert_verify_callback_sample)
    add_subdirectory(os_stub/cryptlib_null)
    add_subdirectory(os_stub/cryptlib_mbedtls)
    add_subdirectory(os_stub/cryptlib_openssl)
    add_subdirectory(os_stub/spdm_crypt_ext_lib)
else()
    if(CRYPTO STREQUAL "mbedtls")
        add_subdirectory(os_stub/cryptlib_mbedtls)
    elseif(CRYPTO STREQUAL "openssl")
        add_subdirectory(os_stub/cryptlib_openssl)
    endif()

    if(NOT ENABLE_BINARY_BUILD STREQUAL "1")
        if(CRYPTO STREQUAL "mbedtls")
            add_subdirectory(os_stub/mbedtlslib)
        elseif(CRYPTO STREQUAL "openssl")
            add_subdirectory(os_stub/openssllib)
        endif()
    endif()

        add_subdirectory(library/spdm_common_lib)
        add_subdirectory(library/spdm_requester_lib)
        add_subdirectory(library/spdm_responder_lib)
        add_subdirectory(library/spdm_crypt_lib)
        add_subdirectory(os_stub/spdm_crypt_ext_lib)
        add_subdirectory(library/spdm_secured_message_lib)
        add_subdirectory(library/spdm_transport_mctp_lib)
        add_subdirectory(library/spdm_transport_pcidoe_lib)
        add_subdirectory(library/spdm_transport_tcp_lib)
        ADD_SUBDIRECTORY(library/spdm_transport_storage_lib)
        add_subdirectory(os_stub/memlib)
        add_subdirectory(os_stub/debuglib)
        add_subdirectory(os_stub/debuglib_null)
        add_subdirectory(os_stub/rnglib)
        add_subdirectory(os_stub/platform_lib)
        add_subdirectory(os_stub/platform_lib_null)
        add_subdirectory(os_stub/malloclib)
        add_subdirectory(os_stub/spdm_device_secret_lib_${DEVICE})
        add_subdirectory(os_stub/spdm_device_secret_lib_null)
        add_subdirectory(os_stub/spdm_cert_verify_callback_sample)

        if(NOT DISABLE_TESTS STREQUAL "1")
            add_subdirectory(unit_test/spdm_transport_test_lib)
            add_subdirectory(unit_test/cmockalib)

            if(TOOLCHAIN STREQUAL "ARM_DS2022" OR TOOLCHAIN STREQUAL "ARM_GNU" OR TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL")
            add_subdirectory(os_stub/armbuild_lib)
            endif()

            if(NOT TOOLCHAIN STREQUAL "LIBFUZZER")
            add_subdirectory(unit_test/test_spdm_requester)
            add_subdirectory(unit_test/test_spdm_responder)
            add_subdirectory(unit_test/test_crypt)
            add_subdirectory(unit_test/test_spdm_crypt)
            add_subdirectory(unit_test/test_spdm_fips)
            add_subdirectory(unit_test/test_spdm_secured_message)
            add_subdirectory(unit_test/test_spdm_sample)
            if(LIBSPDM_TPM_SUPPORT)
            add_subdirectory(unit_test/test_spdm_tpm)
            endif()
            endif()

            if((NOT TOOLCHAIN STREQUAL "ARM_DS2022") AND (NOT TOOLCHAIN STREQUAL "RISCV_XPACK"))
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_version)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_version)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_capabilities)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_capabilities)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_negotiate_algorithms)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_algorithms)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_digests)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_digests)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_certificate)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_certificate)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_measurements)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_measurements)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_key_exchange)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_key_exchange)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_finish)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_finish_rsp)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_psk_exchange)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_psk_exchange_rsp)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_heartbeat)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_heartbeat_ack)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_key_update)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_key_update)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_end_session)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_end_session)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_psk_finish_rsp)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_psk_finish)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_challenge)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_challenge_auth)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_encap_challenge_auth)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_encap_challenge)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_encap_certificate)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_encap_get_certificate)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_encap_digests)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_encap_get_digests)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_encap_key_update)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_encap_key_update)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_encap_request)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_encap_response)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_if_ready)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_mctp_encode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_mctp_decode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_pci_doe_encode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_pci_doe_decode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_tcp_encode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_tcp_decode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_storage_encode_message)
            add_subdirectory(unit_test/fuzzing/test_transport/test_spdm_transport_storage_decode_message)
            add_subdirectory(unit_test/fuzzing/test_secured_message/test_spdm_decode_secured_message)
            add_subdirectory(unit_test/fuzzing/test_secured_message/test_spdm_encode_secured_message)
            add_subdirectory(unit_test/fuzzing/test_spdm_crypt/test_x509_certificate_check)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_set_certificate)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_set_certificate)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_csr)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_csr)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_chunk_get)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_chunk_get)
            add_subdirectory(unit_test/fuzzing/test_spdm_common/test_process_opaque_data)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_chunk_send_ack)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_chunk_send)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_supported_event_types)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_event_types)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_vendor_cmds)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_vendor_cmds)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_measurement_extension_log)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_measurement_extension_log)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_get_key_pair_info)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_key_pair_info)
            add_subdirectory(unit_test/fuzzing/test_requester/test_spdm_requester_set_key_pair_info)
            add_subdirectory(unit_test/fuzzing/test_responder/test_spdm_responder_set_key_pair_info_ack)
            endif()

            if(NOT TOOLCHAIN STREQUAL "LIBFUZZER")
            add_subdirectory(unit_test/test_spdm_common)
            endif()

        if(GCOV STREQUAL "OFF")
            if((CMAKE_SYSTEM_NAME MATCHES "Windows" AND ARCH STREQUAL "x64" AND TOOLCHAIN STREQUAL "VS2019") OR
            (CMAKE_SYSTEM_NAME MATCHES "Linux" AND ARCH STREQUAL "x64" AND (TOOLCHAIN STREQUAL "GCC" OR TOOLCHAIN STREQUAL "CLANG")) OR
            (CMAKE_SYSTEM_NAME MATCHES "Linux"  AND TOOLCHAIN STREQUAL "RISCV_XPACK") OR
            (CMAKE_SYSTEM_NAME MATCHES "Linux" AND ARCH STREQUAL "aarch64") OR
            (CMAKE_SYSTEM_NAME MATCHES "Linux" AND ARCH STREQUAL "loongarch64"))
                add_subdirectory(os_stub/cryptlib_null)
                add_subdirectory(unit_test/test_size/cryptstublib_dummy)
                add_subdirectory(unit_test/test_size/intrinsiclib)
                add_subdirectory(unit_test/test_size/malloclib_null)
                add_subdirectory(unit_test/test_size/malloclib_simple)
                add_subdirectory(unit_test/test_size/rnglib_null)
                add_subdirectory(unit_test/test_size/test_size_of_spdm_requester)
                add_subdirectory(unit_test/test_size/test_size_of_spdm_responder)
            endif()
        endif()
    endif()

    if ((BUILD_LINUX_SHARED_LIB STREQUAL "ON") AND (CMAKE_SYSTEM_NAME MATCHES "Linux"))
        set(LIB_NAME "spdm")
        set(CMAKE_PROJECT_NAME "libspdm")
        set(CMAKE_PROJECT_DESCRIPTION "libspdm shared library")

        if(NOT TOOLCHAIN STREQUAL "NONE")
            set(CMAKE_SKIP_BUILD_RPATH FALSE)
            set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
            set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
            set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
        endif()

        add_library(${LIB_NAME} SHARED
            $<TARGET_OBJECTS:spdm_common_lib>
            $<TARGET_OBJECTS:spdm_crypt_lib>
            $<TARGET_OBJECTS:spdm_requester_lib>
            $<TARGET_OBJECTS:spdm_responder_lib>
            $<TARGET_OBJECTS:spdm_secured_message_lib>
            $<TARGET_OBJECTS:spdm_transport_mctp_lib>
            $<TARGET_OBJECTS:spdm_transport_pcidoe_lib>
            $<TARGET_OBJECTS:spdm_transport_tcp_lib>
            $<TARGET_OBJECTS:spdm_transport_storage_lib>
        )

        add_library(${LIB_NAME}_platform SHARED
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:malloclib>
            $<TARGET_OBJECTS:platform_lib>
            $<TARGET_OBJECTS:rnglib>
            $<TARGET_OBJECTS:memlib>
        )

        add_library(${LIB_NAME}_crypto SHARED
            $<TARGET_OBJECTS:spdm_crypt_ext_lib>
            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
        )

	set_target_properties(
           ${LIB_NAME}
	   ${LIB_NAME}_platform
	   ${LIB_NAME}_crypto
	   PROPERTIES
	   VERSION ${PROJECT_VERSION}
	)

        if(CRYPTO STREQUAL "mbedtls")
            set(CRYPTO_DEPS "-lmbedtls -lmbedx509 -lmbedcrypto")
            target_link_libraries(${LIB_NAME}_crypto
                PUBLIC mbedtls
                PUBLIC mbedx509
                PUBLIC mbedcrypto
            )
        elseif(CRYPTO STREQUAL "openssl")
            set(CRYPTO_DEPS "-lssl -lcrypto")
            if((TOOLCHAIN STREQUAL "NONE") AND (ENABLE_BINARY_BUILD STREQUAL "0"))
                target_link_libraries(${LIB_NAME}_crypto
                    PUBLIC openssllib
                    PUBLIC cryptlib_openssl
                )
            else()
                target_link_libraries(${LIB_NAME}_crypto
                    PUBLIC ssl
                    PUBLIC crypto
                )
            endif()
        endif()

        if(LIBSPDM_TPM_SUPPORT)
            # tss2 is internal (tpm.c only, not in the .pc / no header): PRIVATE since libspdm_crypto.so's DT_NEEDED covers consumers
            target_link_libraries(${LIB_NAME}_crypto
                PRIVATE tss2-esys tss2-sys tss2-mu tss2-tctildr tss2-rc
            )
        endif()

        target_link_libraries(${LIB_NAME}
            PUBLIC ${LIB_NAME}_platform
            PUBLIC ${LIB_NAME}_crypto
        )

        install(DIRECTORY include DESTINATION include/libspdm)
        install(DIRECTORY os_stub/include DESTINATION include/libspdm/os_stub)
        # Propagate every libspdm configuration macro (-DLIBSPDM_*) from
        # CMAKE_C_FLAGS, and the Release LIBSPDM_DEBUG_ENABLE=0, to consumers via pkg-config
        string(REGEX MATCHALL "-DLIBSPDM_[A-Za-z0-9_]+(=[^ \t]+)?" LIBSPDM_CONFIG_FLAGS "${CMAKE_C_FLAGS}")
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            list(APPEND LIBSPDM_CONFIG_FLAGS -DLIBSPDM_DEBUG_ENABLE=0)
        endif()
        string(REPLACE ";" " " LIBSPDM_CONFIG_CFLAGS "${LIBSPDM_CONFIG_FLAGS}")
        configure_file(libspdm.pc.in lib/pkgconfig/libspdm.pc @ONLY)
        install(FILES ${CMAKE_BINARY_DIR}/lib/pkgconfig/libspdm.pc DESTINATION lib/pkgconfig/)
        install(TARGETS ${LIB_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(TARGETS ${LIB_NAME}_platform LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(TARGETS ${LIB_NAME}_crypto LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
        # libspdm.so leaves the device-secret symbols undefined by design; the
        # .pc file makes consumers link this static library to provide them.
        install(TARGETS spdm_device_secret_lib_${DEVICE} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()
endif()

# Applies C99, LIBSPDM_WARNING_OPTIONS and LIBSPDM_CONFIG_DEFINITIONS to the targets in a directory
# and its subdirectories, except the third-party code, which keeps its own settings. A target that
# sets its own C_STANDARD or C_EXTENSIONS keeps them. The warning options go first, so that a
# target's own suppressions still take effect.
function(libspdm_configure_targets directory)
    get_property(targets DIRECTORY "${directory}" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(target IN LISTS targets)
        get_property(type TARGET ${target} PROPERTY TYPE)
        if(NOT type MATCHES "^(INTERFACE_LIBRARY|UTILITY)$")
            get_property(options TARGET ${target} PROPERTY COMPILE_OPTIONS)
            set_property(TARGET ${target} PROPERTY COMPILE_OPTIONS ${LIBSPDM_WARNING_OPTIONS} ${options})
            set_property(TARGET ${target} APPEND PROPERTY COMPILE_DEFINITIONS ${LIBSPDM_CONFIG_DEFINITIONS})
            get_property(standard_set TARGET ${target} PROPERTY C_STANDARD SET)
            if(NOT standard_set)
                set_property(TARGET ${target} PROPERTY C_STANDARD 99)
            endif()
            get_property(extensions_set TARGET ${target} PROPERTY C_EXTENSIONS SET)
            if(NOT extensions_set)
                set_property(TARGET ${target} PROPERTY C_EXTENSIONS OFF)
            endif()
        endif()
    endforeach()
    get_property(subdirectories DIRECTORY "${directory}" PROPERTY SUBDIRECTORIES)
    foreach(subdirectory IN LISTS subdirectories)
        if(NOT subdirectory MATCHES "/(os_stub/mbedtlslib|os_stub/openssllib|unit_test/cmockalib)$")
            libspdm_configure_targets("${subdirectory}")
        endif()
    endforeach()
endfunction()

libspdm_configure_targets("${CMAKE_CURRENT_SOURCE_DIR}")
