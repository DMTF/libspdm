cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

include_directories(${LIBSPDM_DIR}/include

                    ${LIBSPDM_DIR}/os_stub/include
)

set(src_cryptstublib_dummy
    rand_dummy.c
    timeclock_dummy.c
)

add_library(cryptstublib_dummy STATIC ${src_cryptstublib_dummy})
