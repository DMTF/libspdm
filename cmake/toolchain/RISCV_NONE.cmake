# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER riscv64-elf-gcc)
set(CMAKE_AR riscv64-elf-ar)
set(CMAKE_LINKER riscv64-elf-gcc)
