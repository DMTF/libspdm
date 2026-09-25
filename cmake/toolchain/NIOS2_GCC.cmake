# Linking an executable needs target-specific startup code, so compiler checks build a static
# library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER nios2-elf-gcc)
set(CMAKE_AR nios2-elf-ar)
set(CMAKE_LINKER nios2-elf-gcc)

set(CMAKE_C_FLAGS_INIT "-mno-hw-div -mhw-mul -mno-hw-mulx -mgpopt=global")
