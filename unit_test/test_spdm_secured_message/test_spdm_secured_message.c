/**
 * SPDX-FileCopyrightText: 2023-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

extern int libspdm_secured_message_encode_decode_test_main(void);

int main(void)
{
    int return_value = 0;

    if (libspdm_secured_message_encode_decode_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
