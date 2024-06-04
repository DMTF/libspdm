cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(${CMOCKA_FLAGS} -DHAVE_SIGNAL_H)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_compile_options(${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF)
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        add_compile_options(/wd4819)
    endif()
endif()

include_directories(${LIBSPDM_DIR}/unit_test/cmockalib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    set(src_CmockaLib
        cmocka/src/cmocka.c
        strdup.c
    )
else()
    set(src_CmockaLib
        cmocka/src/cmocka.c
    )
endif()

add_library(cmockalib STATIC ${src_CmockaLib})
