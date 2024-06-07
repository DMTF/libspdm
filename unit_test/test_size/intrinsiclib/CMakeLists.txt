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
        ${CMAKE_CURRENT_LIST_DIR}/compiler_stub.c
        ${CMAKE_CURRENT_LIST_DIR}/memory_intrinsics.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "RISCV_XPACK")
        target_sources(intrinsiclib
            PRIVATE
                ${CMAKE_CURRENT_LIST_DIR}/ashldi3.c
        )
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "ia32")
        target_sources(intrinsiclib
            PRIVATE
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_div_s64x64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_div_s64x64_remainder.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_div_u64x64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_div_u64x64_remainder.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_ftol.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_lshift_s64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_mult_s64x64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_remainder_s64x64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_remainder_u64x64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_rShift_s64.c
                ${CMAKE_CURRENT_LIST_DIR}/ia32/math_rShift_u64.c
        )
    endif()
endif()

if(TOOLCHAIN MATCHES "CLANG")
    target_compile_options(intrinsiclib PRIVATE -Wno-incompatible-library-redeclaration)
endif()
