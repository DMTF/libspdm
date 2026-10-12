/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"

int libspdm_transport_mctp_test_main(void);
int libspdm_transport_mctp_error_test_main(void);
int libspdm_transport_pci_doe_test_main(void);
int libspdm_transport_pci_doe_error_test_main(void);
int libspdm_transport_tcp_test_main(void);
int libspdm_transport_tcp_error_test_main(void);
int libspdm_transport_storage_test_main(void);
int libspdm_transport_storage_error_test_main(void);

int main(void)
{
    int return_value = 0;

    if (libspdm_transport_mctp_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_transport_mctp_error_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_transport_pci_doe_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_transport_pci_doe_error_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_transport_tcp_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_transport_tcp_error_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_transport_storage_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_transport_storage_error_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
