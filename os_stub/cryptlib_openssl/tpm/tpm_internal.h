/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef LIBSPDM_TPM_INTERNAL_H
#define LIBSPDM_TPM_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Validate and copy one TPM NV read response into the aggregate output buffer.
 *
 * This helper is exposed only to permit focused unit testing of response bounds
 * and forward-progress checks without requiring a malformed TPM transport.
 */
bool libspdm_tpm_copy_nv_chunk(uint8_t *buffer, size_t buffer_size,
                               size_t *offset, const uint8_t *chunk,
                               size_t chunk_size, size_t requested_size);

#endif /* LIBSPDM_TPM_INTERNAL_H */
