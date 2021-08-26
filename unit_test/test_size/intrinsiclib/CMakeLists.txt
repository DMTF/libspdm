cmake_minimum_required(VERSION 2.6)

if(TOOLCHAIN MATCHES "VS")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GL-")
endif()

if(TOOLCHAIN MATCHES "CLANG")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-library-redeclaration")
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(src_intrinsiclib
        copy_mem.c
        memory_intrinsics.c        
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "x64")
        SET(src_intrinsiclib
            copy_mem.c
            memory_intrinsics.c        
        )
    elseif(ARCH STREQUAL "ia32")
        SET(src_intrinsiclib
            copy_mem.c
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

ADD_LIBRARY(intrinsiclib STATIC ${src_intrinsiclib})
