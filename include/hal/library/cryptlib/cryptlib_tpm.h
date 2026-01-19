/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CRYPTLIB_TPM_H__
#define __CRYPTLIB_TPM_H__

#include <stdbool.h>

bool libspdm_tpm_device_init();

bool libspdm_tpm_get_private_key(void *handle, void **context);

bool libspdm_tpm_get_public_key(void *handle, void **context);

bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size);

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size);

#endif
