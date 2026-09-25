# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER riscv-none-elf-gcc)
set(CMAKE_AR riscv-none-elf-ar)
set(CMAKE_RANLIB riscv-none-elf-gcc-ranlib)
set(CMAKE_LINKER riscv-none-elf-gcc)
