/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/


extern int libspdm_common_context_data_test_main(void);
extern int libspdm_common_support_test_main(void);

int main(void)
{
    int return_value = 0;

    if (libspdm_common_context_data_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_common_support_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
