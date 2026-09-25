# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER riscv-none-elf-gcc)
set(CMAKE_AR riscv-none-elf-ar)
set(CMAKE_RANLIB riscv-none-elf-gcc-ranlib)
set(CMAKE_LINKER riscv-none-elf-gcc)

if(ARCH STREQUAL "riscv32")
    set(CMAKE_C_FLAGS_INIT "-march=rv32imafdc_zicsr -mabi=ilp32d")
elseif(ARCH STREQUAL "riscv64")
    set(CMAKE_C_FLAGS_INIT "-march=rv64imafdc_zicsr -mabi=lp64d")
else()
    message(FATAL_ERROR "RISCV_XPACK supports ARCH riscv32 and riscv64")
endif()
set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_C_FLAGS_INIT}")

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ARCH)
