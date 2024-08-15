cmake_minimum_required(VERSION 3.5)

add_executable(test_spdm_responder)

target_include_directories(test_spdm_responder
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/test_spdm_responder
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_responder
    PRIVATE
        test_spdm_responder.c
        version.c
        capabilities.c
        algorithms.c
        digests.c
        certificate.c
        challenge_auth.c
        measurements.c
        measurement_extension_log.c
        respond_if_ready.c
        key_exchange.c
        finish.c
        psk_exchange.c
        psk_finish.c
        heartbeat.c
        key_update.c
        end_session.c
        vendor_response.c
        encap_get_certificate.c
        encap_get_digests.c
        encap_key_update.c
        encap_challenge.c
        encap_response.c
        supported_event_types.c
        subscribe_event_types_ack.c
        error_test/supported_event_types_err.c
        error_test/subscribe_event_types_ack_err.c
        error_test/vendor_response_err.c
        set_certificate_rsp.c
        csr.c
        receive_send.c
        chunk_get.c
        chunk_send_ack.c
        key_pair_info.c
        set_key_pair_info_ack.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/common.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/event_support.c
)


if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(test_spdm_responder PRIVATE /wd4819)
    endif()
endif()

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_compile_options(test_spdm_responder PRIVATE /wd4819)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    target_link_libraries(test_spdm_responder
        PRIVATE
            $<TARGET_OBJECTS:memlib>
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:spdm_responder_lib>
            $<TARGET_OBJECTS:spdm_common_lib>
            $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
            $<TARGET_OBJECTS:rnglib>
            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
            $<TARGET_OBJECTS:malloclib>
            $<TARGET_OBJECTS:spdm_crypt_lib>
            $<TARGET_OBJECTS:spdm_secured_message_lib>
            $<TARGET_OBJECTS:spdm_device_secret_lib_sample>
            $<TARGET_OBJECTS:spdm_transport_test_lib>
            $<TARGET_OBJECTS:cmockalib>
            $<TARGET_OBJECTS:platform_lib>
    )
else()
    target_link_libraries(test_spdm_responder
        PRIVATE
            memlib
            debuglib
            spdm_requester_lib
            spdm_responder_lib
            spdm_common_lib
            ${CRYPTO_LIB_PATHS}
            rnglib
            cryptlib_${CRYPTO}
            malloclib
            spdm_crypt_lib
            spdm_crypt_ext_lib
            spdm_secured_message_lib
            spdm_device_secret_lib_sample
            spdm_transport_test_lib
            cmockalib
            platform_lib
    )
endif()
