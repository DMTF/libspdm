cmake_minimum_required(VERSION 3.5)

set(PUBLIC_HEADERS ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/oqs.h
                   ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/common.h
                   ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/rand/rand.h
                   ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/kem/kem.h
                   ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/sig/sig.h)

set(INTERNAL_HEADERS ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/aes/aes.h
                     ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/rand/rand_nist.h
                     ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/sha2/sha2.h
                     ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/sha3/sha3.h
                     ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/sha3/sha3x4.h)

set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_SOURCE_DIR}/src/kem/ml_kem/kem_ml_kem.h)
set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_SOURCE_DIR}/src/sig/ml_dsa/sig_ml_dsa.h)

include_directories(${CMAKE_CURRENT_LIST_DIR}/include ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common/pqclean_shims)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        add_compile_options(/wd4090 /wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127 /wd4204 /wd4702 /wd4200 /wd4389 /wd4146 /wd4267)
    endif() 
endif()

set(OQS_ENABLE_SIG_ml_dsa_44 1)
set(OQS_ENABLE_SIG_ml_dsa_65 1)
set(OQS_ENABLE_SIG_ml_dsa_87 1)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/liboqs/src/sig/ml_dsa)
set(SIG_OBJS ${SIG_OBJS} ${ML_DSA_OBJS})

set(OQS_ENABLE_KEM_ml_kem_512 1)
set(OQS_ENABLE_KEM_ml_kem_768 1)
set(OQS_ENABLE_KEM_ml_kem_1024 1)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/liboqs/src/kem/ml_kem)
set(KEM_OBJS ${KEM_OBJS} ${ML_KEM_OBJS})

set(OQS_DIST_BUILD 1)
set(OQS_DIST_X86_64_BUILD 1)
set(OQS_ENABLE_SHA3_xkcp_low 1)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/liboqs/src/common)

add_library(oqslib ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/kem/kem.c
                   ${KEM_OBJS}
                   ${CMAKE_CURRENT_LIST_DIR}/liboqs/src/sig/sig.c
                   ${SIG_OBJS}
                   ${COMMON_OBJS})

target_include_directories(oqslib PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)
