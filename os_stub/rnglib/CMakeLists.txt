cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/rnglib
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT TOOLCHAIN STREQUAL "ARM_DS2022")
SET(src_rnglib
    rng_linux.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
SET(src_rnglib
    rng_win.c
)
else()
SET(src_rnglib
    rng_arm_sample.c
)
endif()

ADD_LIBRARY(rnglib STATIC ${src_rnglib})
