cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT TOOLCHAIN STREQUAL "ARM_CLANG")
SET(src_rnglib
    rng_linux.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
SET(src_rnglib
    rng_win.c
)
else()
SET(src_rnglib
    rng_std.c
)
endif()

ADD_LIBRARY(rnglib STATIC ${src_rnglib})
