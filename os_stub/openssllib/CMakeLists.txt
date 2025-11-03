cmake_minimum_required(VERSION 3.5)

include(ExternalProject)

set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openssl)
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-install)

set(OPENSSL_CONFIGURE_SCRIPT "${OPENSSL_SOURCE_DIR}/Configure")

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "GCC")
        if(ARCH STREQUAL "x64")
            set(OPENSSL_ARCH "mingw64")
        elseif(ARCH STREQUAL "ia32")
            set(OPENSSL_ARCH "mingw")
        else()
            message(FATAL_ERROR "Windows MinGW only supports x64 and ia32 architectures for OpenSSL")
        endif()
    else()
        if(ARCH STREQUAL "x64")
            set(OPENSSL_ARCH "VC-WIN64A")
        elseif(ARCH STREQUAL "ia32")
            set(OPENSSL_ARCH "VC-WIN32")
        else()
            message(FATAL_ERROR "Windows MSVC only supports x64 and ia32 architectures for OpenSSL")
        endif()
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64" OR ARCH STREQUAL "aarch64")
        set(OPENSSL_ARCH "darwin64-arm64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" OR ARCH STREQUAL "x64")
        set(OPENSSL_ARCH "darwin64-x86_64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686" OR ARCH STREQUAL "ia32")
        set(OPENSSL_ARCH "darwin-i386")
    else()
        message(FATAL_ERROR "macOS: Unsupported architecture ${CMAKE_SYSTEM_PROCESSOR} / ARCH ${ARCH} for OpenSSL")
    endif()
else()
    if(ARCH STREQUAL "x64")
        set(OPENSSL_ARCH "linux-x86_64")
    elseif(ARCH STREQUAL "ia32")
        set(OPENSSL_ARCH "linux-generic32")
    elseif(ARCH STREQUAL "aarch64")
        set(OPENSSL_ARCH "linux-aarch64")
    elseif(ARCH STREQUAL "arm")
        set(OPENSSL_ARCH "linux-armv4")
    elseif(ARCH STREQUAL "riscv32")
        set(OPENSSL_ARCH "linux-generic32")
    elseif(ARCH STREQUAL "riscv64")
        set(OPENSSL_ARCH "linux-generic64")
    elseif(ARCH STREQUAL "loongarch64")
        set(OPENSSL_ARCH "linux-generic64")
    else()
        message(FATAL_ERROR "Linux: Unsupported ARCH ${ARCH} for OpenSSL")
    endif()
endif()

# Build shared library when TOOLCHAIN is not NONE, otherwise build static library
if(TOOLCHAIN STREQUAL "NONE")
    set(OPENSSL_SHARED_OPTION "no-shared")
    set(OPENSSL_LIBRARY_TYPE "STATIC")
    message(STATUS "Building OpenSSL as static library (TOOLCHAIN=NONE)")
else()
    set(OPENSSL_SHARED_OPTION "shared")
    set(OPENSSL_LIBRARY_TYPE "SHARED")
    message(STATUS "Building OpenSSL as shared library (TOOLCHAIN=${TOOLCHAIN})")
endif()

set(OPENSSL_CONFIGURE_OPTIONS 
    ${OPENSSL_SHARED_OPTION} no-ssl no-tls no-dtls no-tests
    no-threads no-engine no-capieng no-zlib no-legacy
    --prefix=${OPENSSL_INSTALL_DIR}
    --openssldir=${OPENSSL_INSTALL_DIR}/ssl
)

set(OPENSSL_CC ${CMAKE_C_COMPILER})
set(OPENSSL_CFLAGS "-O2")

    set(OPENSSL_LIB_DIR "${OPENSSL_INSTALL_DIR}/lib")
list(APPEND OPENSSL_CONFIGURE_OPTIONS --libdir=lib)

file(MAKE_DIRECTORY ${OPENSSL_INSTALL_DIR}/include)
file(MAKE_DIRECTORY ${OPENSSL_LIB_DIR})

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(OPENSSL_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build/src/openssl_external-build)

    file(TO_CMAKE_PATH "${OPENSSL_BUILD_DIR}" OPENSSL_BUILD_DIR_NORMALIZED)
    file(TO_CMAKE_PATH "${OPENSSL_SOURCE_DIR}" OPENSSL_SOURCE_DIR_NORMALIZED)

    set(OPENSSL_CONFIGURE_CMD
        ${CMAKE_COMMAND} -E chdir "${OPENSSL_BUILD_DIR_NORMALIZED}"
        perl "${OPENSSL_SOURCE_DIR_NORMALIZED}/Configure" ${OPENSSL_ARCH} ${OPENSSL_CONFIGURE_OPTIONS}
    )
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(OPENSSL_BUILD_CMD make)
        set(OPENSSL_INSTALL_CMD make install_sw)
        if(OPENSSL_LIBRARY_TYPE STREQUAL "SHARED")
            set(OPENSSL_LIB_FILE "${CMAKE_CURRENT_BINARY_DIR}/openssl-build/src/openssl_external-build/libcrypto-3-x64.dll")
            set(OPENSSL_IMPLIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.dll.a")
        else()
        set(OPENSSL_LIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.a")
        endif()
    else()
        # Get parallel build level from CMAKE_BUILD_PARALLEL_LEVEL if set
        # nmake uses /j option (not -j) for parallel builds
        if(DEFINED CMAKE_BUILD_PARALLEL_LEVEL AND CMAKE_BUILD_PARALLEL_LEVEL)
            set(OPENSSL_BUILD_CMD nmake /j${CMAKE_BUILD_PARALLEL_LEVEL})
            set(OPENSSL_INSTALL_CMD nmake /j${CMAKE_BUILD_PARALLEL_LEVEL} install_sw)
        else()
        set(OPENSSL_BUILD_CMD nmake)
        set(OPENSSL_INSTALL_CMD nmake install_sw)
        endif()
        if(OPENSSL_LIBRARY_TYPE STREQUAL "SHARED")
            set(OPENSSL_LIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.lib")
            set(OPENSSL_DLL_FILE "${CMAKE_CURRENT_BINARY_DIR}/openssl-build/src/openssl_external-build/libcrypto-3-x64.dll")
        else()
        set(OPENSSL_LIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.lib")
        endif()
    endif()
else()
    string(REPLACE ";" " " OPENSSL_CONFIGURE_OPTIONS_STR "${OPENSSL_CONFIGURE_OPTIONS}")
    set(OPENSSL_CONFIGURE_CMD
        bash -c "set -e && \
            cd ${OPENSSL_SOURCE_DIR} && \
            make distclean 2>/dev/null || true && \
            cd ${CMAKE_CURRENT_BINARY_DIR}/openssl-build/src/openssl_external-build && \
            CC=${OPENSSL_CC} CFLAGS='${OPENSSL_CFLAGS}' \
            ${OPENSSL_CONFIGURE_SCRIPT} ${OPENSSL_ARCH} ${OPENSSL_CONFIGURE_OPTIONS_STR}"
    )
    set(OPENSSL_BUILD_CMD make)
    set(OPENSSL_INSTALL_CMD make install_sw)
    if(OPENSSL_LIBRARY_TYPE STREQUAL "SHARED")
        if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
            set(OPENSSL_LIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.3.dylib")
        else()
            set(OPENSSL_LIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.so.3")
        endif()
    else()
    set(OPENSSL_LIB_FILE "${OPENSSL_LIB_DIR}/libcrypto.a")
    endif()
endif()

ExternalProject_Add(
    openssl_external
    SOURCE_DIR ${OPENSSL_SOURCE_DIR}
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/openssl-build
    CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_CMD}
    BUILD_COMMAND ${OPENSSL_BUILD_CMD}
    INSTALL_COMMAND ${OPENSSL_INSTALL_CMD}
    BUILD_IN_SOURCE FALSE
    BUILD_ALWAYS FALSE
    USES_TERMINAL_BUILD 1
    USES_TERMINAL_CONFIGURE 1
    USES_TERMINAL_INSTALL 1
    BUILD_BYPRODUCTS
        ${OPENSSL_LIB_FILE}
)

add_library(openssllib ${OPENSSL_LIBRARY_TYPE} IMPORTED GLOBAL)

set_target_properties(openssllib PROPERTIES
    IMPORTED_LOCATION ${OPENSSL_LIB_FILE}
)

# For Windows MSVC shared library, set the import library
if(OPENSSL_LIBRARY_TYPE STREQUAL "SHARED" AND CMAKE_SYSTEM_NAME MATCHES "Windows" AND NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(DEFINED OPENSSL_DLL_FILE)
        set_target_properties(openssllib PROPERTIES
            IMPORTED_LOCATION ${OPENSSL_DLL_FILE}
            IMPORTED_IMPLIB ${OPENSSL_LIB_FILE}
        )
    endif()
endif()

# For Windows MinGW shared library, set the import library
if(OPENSSL_LIBRARY_TYPE STREQUAL "SHARED" AND CMAKE_SYSTEM_NAME MATCHES "Windows" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(DEFINED OPENSSL_IMPLIB_FILE)
        set_target_properties(openssllib PROPERTIES
            IMPORTED_IMPLIB ${OPENSSL_IMPLIB_FILE}
        )
    endif()
endif()

add_dependencies(openssllib openssl_external)

target_include_directories(openssllib
    INTERFACE
        ${OPENSSL_INSTALL_DIR}/include
)

# Ensure OpenSSL include directory takes precedence over system paths
# This is critical when building with TOOLCHAIN=GCC and shared OpenSSL
set_target_properties(openssllib PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ""
    OPENSSL_INSTALL_DIR "${OPENSSL_INSTALL_DIR}"
)

# Link Windows Socket library for MinGW
# OpenSSL's BIO socket functions (bio_sock.c, etc.) require WinSock API
if(CMAKE_SYSTEM_NAME MATCHES "Windows" AND TOOLCHAIN STREQUAL "GCC")
    target_link_libraries(openssllib INTERFACE ws2_32)
endif()

set(OPENSSL_INSTALL_DIR ${OPENSSL_INSTALL_DIR} PARENT_SCOPE)
