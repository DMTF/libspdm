cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(ARCH STREQUAL "x64")
        set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__stack_chk_fail")
        if(TOOLCHAIN STREQUAL "CLANG")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}  -Wl,--undefined=memcpy")
        endif()
    elseif(ARCH STREQUAL "aarch64")
        if(TOOLCHAIN STREQUAL "ARM_DS2022")
            set(CMAKE_EXE_LINKER_FLAGS "--target=aarch64-arm-none-eabi -nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__udivti3,--undefined=memcpy")
        elseif(TOOLCHAIN STREQUAL "ARM_GNU" OR TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL")
            set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__udivti3,--undefined=memcpy")
        elseif(TOOLCHAIN STREQUAL "AARCH64_GCC" OR TOOLCHAIN STREQUAL "GCC" OR TOOLCHAIN STREQUAL "CLANG")
            set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__stack_chk_fail,--undefined=__stack_chk_guard,--undefined=memcpy")
        endif()
    elseif(TOOLCHAIN STREQUAL "RISCV_XPACK")
        set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__ashldi3")
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF")
endif()

add_library(test_size_of_spdm_requester STATIC "")

target_include_directories(test_size_of_spdm_requester
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/test_size/test_size_of_spdm_requester
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub/include
)

target_sources(test_size_of_spdm_requester
    PRIVATE
        spdm_requester_authentication.c
        spdm_requester_init.c
        spdm_requester_main.c
        spdm_requester_session.c
        support.c
)

if(TOOLCHAIN STREQUAL "ARM_DS2022" OR TOOLCHAIN STREQUAL "ARM_GNU")
    target_link_libraries(test_size_of_spdm_requester PRIVATE armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    target_link_libraries(test_size_of_spdm_requester
        PRIVATE
            $<TARGET_OBJECTS:memlib>
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:spdm_requester_lib>
            $<TARGET_OBJECTS:spdm_common_lib>
#            $<TARGET_OBJECTS:cryptstublib_dummy>
#            $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
#            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
#            $<TARGET_OBJECTS:rnglib_null>
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
    target_link_libraries(test_size_of_spdm_requester
        PRIVATE
            memlib
            debuglib_null
            spdm_requester_lib
            spdm_common_lib
        #    cryptstublib_dummy
        #    ${CRYPTO_LIB_PATHS}
        #    cryptlib_${CRYPTO}
        #    rnglib_null
            cryptlib_null
            malloclib_simple
            spdm_crypt_lib
            spdm_secured_message_lib
            spdm_transport_mctp_lib
            spdm_device_secret_lib_null
        #    spdm_device_secret_lib_sample
        #    spdm_crypt_ext_lib
            intrinsiclib
            platform_lib_null
    )
endif()
