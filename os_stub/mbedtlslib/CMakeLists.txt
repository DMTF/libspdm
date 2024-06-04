cmake_minimum_required(VERSION 3.5)

if(LIB_INSTALL_DIR)
else()
    set(LIB_INSTALL_DIR lib)
endif()

# Starting Mbed TLS 3.x release, mbedtls/library/CMakeLists.txt has dependency on
# link_to_source() function that is in mbedtls/CMakeLists.txt, so define
# link_to_source here. This shall be later expanded to add a link to the mbedtls
# source file from the build directory if required by libspdm.
function(link_to_source base_name)
endfunction(link_to_source)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/mbedtls/library)

# mbedtls

if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedtls PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
target_include_directories(mbedtls PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include/mbedtls
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(mbedtls PRIVATE /wd4090 /wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127 /wd4204 /wd4702 /wd4200 /wd4389)
    endif()
else()
    target_compile_options(mbedtls PRIVATE -Wno-cast-qual ${MBEDTLS_FLAGS})
endif()
if(ARCH STREQUAL "x64")
    target_compile_definitions(mbedtls PRIVATE -DEFIx64)
elseif(ARCH STREQUAL "ia32")
    target_compile_definitions(mbedtls PRIVATE -DEFI32)
endif()

# mbedx509
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedx509 PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
target_include_directories(mbedx509 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include/mbedtls
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(mbedx509 PRIVATE /wd4090 /wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127 /wd4204 /wd4702 /wd4200 /wd4389)
    endif()
else()
    target_compile_options(mbedx509 PRIVATE -Wno-cast-qual ${MBEDTLS_FLAGS})
endif()
if(ARCH STREQUAL "x64")
    target_compile_definitions(mbedx509 PRIVATE -DEFIx64)
elseif(ARCH STREQUAL "ia32")
    target_compile_definitions(mbedx509 PRIVATE -DEFI32)
endif()

# mbedcrypto
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedcrypto PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
target_include_directories(mbedcrypto PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include/mbedtls
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(mbedcrypto PRIVATE /wd4090 /wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127 /wd4204 /wd4702 /wd4200 /wd4389)
    endif()
else()
    target_compile_options(mbedcrypto PRIVATE -Wno-cast-qual ${MBEDTLS_FLAGS})
endif()
if(ARCH STREQUAL "x64")
    target_compile_definitions(mbedcrypto PRIVATE -DEFIx64)
elseif(ARCH STREQUAL "ia32")
    target_compile_definitions(mbedcrypto PRIVATE -DEFI32)
endif()

add_library(mbedtlslib INTERFACE)
target_link_libraries(mbedtlslib INTERFACE
    mbedx509
    mbedcrypto
)
