cmake_minimum_required(VERSION 3.5)

add_library(cmockalib STATIC "")

target_include_directories(cmockalib
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/cmockalib
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
)

target_sources(cmockalib
    PRIVATE
        cmocka/src/cmocka.c
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_sources(cmockalib PRIVATE strdup.c)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_options(cmockalib PRIVATE ${CMOCKA_FLAGS} -DHAVE_SIGNAL_H)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_compile_options(cmockalib PRIVATE ${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF)
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(cmockalib PRIVATE /wd4819)
    endif()
endif()