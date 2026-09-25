cmake_minimum_required(VERSION 3.16)

# cmocka's cmake_minimum_required() leaves CMP0077 unset, so without this default its option()
# calls would ignore these variables.
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(BUILD_SHARED_LIBS OFF)
set(WITH_EXAMPLES OFF)

# cmocka's configure checks link test programs, which the toolchain blocks' linker flags break (for
# example /NODEFAULTLIB:libcmt.lib for MSVC and -fsanitize=fuzzer for LIBFUZZER), so the checks use
# the cached defaults. cmocka itself is a static library, so it is not linked with them either way.
unset(CMAKE_EXE_LINKER_FLAGS)

# The bare-metal toolchains' compiler checks only compile, so cmocka's checks would find these
# functions, which newlib does not declare.
if(CMAKE_TRY_COMPILE_TARGET_TYPE STREQUAL "STATIC_LIBRARY")
    set(HAVE_SIGLONGJMP OFF CACHE INTERNAL "")
    set(HAVE_CLOCK_GETTIME OFF CACHE INTERNAL "")
endif()

add_subdirectory(cmocka EXCLUDE_FROM_ALL)

# cmocka adds -std=gnu99 only on UNIX. MinGW needs it too, because -std=c99 hides strdup().
if(MINGW)
    target_compile_options(cmocka PRIVATE -std=gnu99)
endif()

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_sources(cmocka PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/strdup.c)
endif()

add_library(cmockalib ALIAS cmocka)
