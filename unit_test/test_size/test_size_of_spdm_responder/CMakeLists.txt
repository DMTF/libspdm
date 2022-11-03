cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(ARCH STREQUAL "x64")
        SET(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint")
    elseif(ARCH STREQUAL "aarch64")
        if(TOOLCHAIN STREQUAL "ARM_DS2022")
            SET(CMAKE_EXE_LINKER_FLAGS "--target=aarch64-arm-none-eabi -nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__udivti3")
        elseif(TOOLCHAIN STREQUAL "ARM_GNU")
            SET(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint")
        elseif(TOOLCHAIN STREQUAL "AARCH64_GCC")
            SET(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint")
        endif()
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF")
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_size/test_size_of_spdm_responder
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_test_size_of_spdm_responder
    spdm_responder_init.c
    spdm_responder_main.c
    compiler_stub.c
)

SET(test_size_of_spdm_responder_LIBRARY
    memlib
    debuglib_null
    spdm_responder_lib
    spdm_common_lib
#    cryptstublib_dummy
#    ${CRYPTO_LIB_PATHS}
#    cryptlib_${CRYPTO}
#    rnglib_null
    cryptlib_null
    malloclib_null
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_device_secret_lib_null
    intrinsiclib
    platform_lib_null
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    SET(test_size_of_spdm_responder_LIBRARY ${test_size_of_spdm_responder_LIBRARY} armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_size_of_spdm_responder
                   ${src_test_size_of_spdm_responder}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_responder_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
#                   $<TARGET_OBJECTS:cryptstublib_dummy>
#                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
#                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
#                   $<TARGET_OBJECTS:rnglib_null>
                   $<TARGET_OBJECTS:cryptlib_null>
                   $<TARGET_OBJECTS:malloclib_null>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_mctp_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_null>
                   $<TARGET_OBJECTS:intrinsiclib>
                   $<TARGET_OBJECTS:platform_lib>
    )
else()
    ADD_EXECUTABLE(test_size_of_spdm_responder ${src_test_size_of_spdm_responder})
    TARGET_LINK_LIBRARIES(test_size_of_spdm_responder ${test_size_of_spdm_responder_LIBRARY})
endif()


