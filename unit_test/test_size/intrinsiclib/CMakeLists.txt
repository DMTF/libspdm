cmake_minimum_required(VERSION 3.5)

if(TOOLCHAIN MATCHES "VS")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL-")
endif()

add_library(intrinsiclib STATIC "")

target_include_directories(intrinsiclib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(intrinsiclib
    PRIVATE
        compiler_stub.c
        memory_intrinsics.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "RISCV_XPACK")
        target_sources(intrinsiclib
            PRIVATE
                ashldi3.c
        )
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "ia32")
        target_sources(intrinsiclib
            PRIVATE
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

if(TOOLCHAIN MATCHES "CLANG")
    target_compile_options(intrinsiclib PRIVATE -Wno-incompatible-library-redeclaration)
endif()
