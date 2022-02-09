/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

int spdm_responder_version_test_main(void);
int spdm_responder_capabilities_test_main(void);
int spdm_responder_algorithms_test_main(void);

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
int spdm_responder_digests_test_main(void);
int spdm_responder_certificate_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
int spdm_responder_challenge_auth_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
int spdm_responder_measurements_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
int spdm_responder_respond_if_ready_test_main (void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
int spdm_responder_key_exchange_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

int spdm_responder_finish_test_main(void);

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
int spdm_responder_psk_exchange_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

int spdm_responder_psk_finish_test_main(void);
int spdm_responder_heartbeat_test_main(void);
int spdm_responder_key_update_test_main(void);
int spdm_responder_end_session_test_main(void);

int main(void)
{
    int return_value = 0;

    if (spdm_responder_version_test_main() != 0) {
        return_value = 1;
    }

    if (spdm_responder_capabilities_test_main() != 0) {
        return_value = 1;
    }

    if (spdm_responder_algorithms_test_main() != 0) {
        return_value = 1;
    }

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    if (spdm_responder_digests_test_main() != 0) {
        return_value = 1;
    }

    if (spdm_responder_certificate_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    if (spdm_responder_challenge_auth_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if (spdm_responder_measurements_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    #if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
    if (spdm_responder_respond_if_ready_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (spdm_responder_key_exchange_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (spdm_responder_finish_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    if (spdm_responder_psk_exchange_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    if (spdm_responder_psk_finish_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    if (spdm_responder_heartbeat_test_main() != 0) {
        return_value = 1;
    }

    if (spdm_responder_key_update_test_main() != 0) {
        return_value = 1;
    }

    if (spdm_responder_end_session_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
