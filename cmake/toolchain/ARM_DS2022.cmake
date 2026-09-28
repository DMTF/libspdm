# CMake's ARMClang support reads CMAKE_SYSTEM_ARCH, set below, from version 3.19.
if(CMAKE_VERSION VERSION_LESS 3.19)
    message(FATAL_ERROR "ARM_DS2022 requires CMake 3.19 or later")
endif()

# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

if(CMAKE_HOST_WIN32)
    set(CMAKE_C_COMPILER armclang.exe)
    set(CMAKE_AR armar.exe)
    set(CMAKE_LINKER armlink.exe)
else()
    set(CMAKE_C_COMPILER armclang)
    set(CMAKE_AR armar)
    set(CMAKE_LINKER armlink)
endif()

if(ARCH STREQUAL "aarch64")
    set(CMAKE_C_COMPILER_TARGET aarch64-arm-none-eabi)
elseif(ARCH STREQUAL "arm")
    set(CMAKE_C_COMPILER_TARGET arm-arm-none-eabi)
else()
    message(FATAL_ERROR "ARM_DS2022 supports ARCH arm and aarch64")
endif()

# CMake's ARMClang support requires an architecture, for which it adds -march.
set(CMAKE_SYSTEM_ARCH armv8-a)

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ARCH)
