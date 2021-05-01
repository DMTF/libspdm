cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_EXE_LINKER_FLAGS "-nostdlib -Wl,-n,-q,--gc-sections -Wl,--entry,ModuleEntryPoint")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHIAN MATCHES "VS")
        SET(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF")
    else()
        SET(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /OPT:REF")
    endif()
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_size/test_size_of_spdm_requester
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_test_size_of_spdm_requester
    spdm_requester_authentication.c
    spdm_requester_init.c
    spdm_requester_main.c
    spdm_requester_session.c
)

SET(test_size_of_spdm_requester_LIBRARY
    memlib
    debuglib
    spdm_requester_lib
    spdm_common_lib
    cryptstublib_dummy
    ${CRYPTO}lib
    rnglib
    cryptlib_${CRYPTO}
    malloclib_null
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_device_secret_lib_null
    intrinsiclib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_size_of_spdm_requester
                   ${src_test_size_of_spdm_requester}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_requester_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:cryptstublib_dummy>
                   $<TARGET_OBJECTS:${CRYPTO}lib>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib_null>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_mctp_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_null>
                   $<TARGET_OBJECTS:intrinsiclib>
    )
else()
    ADD_EXECUTABLE(test_size_of_spdm_requester ${src_test_size_of_spdm_requester})
    TARGET_LINK_LIBRARIES(test_size_of_spdm_requester ${test_size_of_spdm_requester_LIBRARY})
endif()


