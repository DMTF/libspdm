cmake_minimum_required(VERSION 3.5)

if(TOOLCHAIN MATCHES "VS")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL-")
endif()

if(TOOLCHAIN MATCHES "CLANG")
    add_compile_options(-Wno-incompatible-library-redeclaration)
endif()

include_directories(${LIBSPDM_DIR}/include)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "RISCV_XPACK")
        set(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
            ashldi3.c
        )
    else()
        set(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
        )
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "x64")
        set(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
        )
    elseif(ARCH STREQUAL "ia32")
        set(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
            ia32/math_div_s64x64.c
            ia32/math_div_s64x64_remainder.c
            ia32/math_div_u64x64.c
            ia32/math_div_u64x64_remainder.c
            ia32/math_ftol.c
            ia32/math_lshift_s64.c
            ia32/math_mult_s64x64.c
            ia32/math_remainder_s64x64.c
            ia32/math_remainder_u64x64.c
            ia32/math_rShift_s64.c
            ia32/math_rShift_u64.c
        )
    endif()
endif()

add_library(intrinsiclib STATIC ${src_intrinsiclib})
