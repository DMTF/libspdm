# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER riscv64-elf-gcc)
set(CMAKE_AR riscv64-elf-ar)
set(CMAKE_LINKER riscv64-elf-gcc)

if(ARCH STREQUAL "riscv32")
    set(CMAKE_C_FLAGS_INIT "-march=rv32imac_zicsr -mabi=ilp32")
elseif(ARCH STREQUAL "riscv64")
    set(CMAKE_C_FLAGS_INIT "-march=rv64imac_zicsr -mabi=lp64")
else()
    message(FATAL_ERROR "RISCV_NONE supports ARCH riscv32 and riscv64")
endif()

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ARCH)
