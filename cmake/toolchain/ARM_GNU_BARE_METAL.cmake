# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

if(NOT DEFINED MARCH)
    message(FATAL_ERROR "A target architecture must be set with the -DMARCH option")
endif()

if(ARCH STREQUAL "aarch64")
    set(CMAKE_C_COMPILER aarch64-none-elf-gcc)
    set(CMAKE_AR aarch64-none-elf-gcc-ar)
    set(CMAKE_RANLIB aarch64-none-elf-gcc-ranlib)
    set(CMAKE_LINKER aarch64-none-elf-gcc)
elseif(ARCH STREQUAL "arm")
    set(CMAKE_C_COMPILER arm-none-eabi-gcc)
    set(CMAKE_AR arm-none-eabi-gcc-ar)
    set(CMAKE_RANLIB arm-none-eabi-gcc-ranlib)
    set(CMAKE_LINKER arm-none-eabi-gcc)
endif()

set(CMAKE_C_FLAGS_INIT "-march=${MARCH} --specs=nosys.specs")
set(CMAKE_EXE_LINKER_FLAGS_INIT "--specs=nosys.specs")

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ARCH MARCH)
