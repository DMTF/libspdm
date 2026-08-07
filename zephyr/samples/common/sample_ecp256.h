/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#ifndef SAMPLE_ECP256_H
#define SAMPLE_ECP256_H

#include "sample_static_blob_store.h"

extern const struct sample_static_blob sample_ecp256_blobs[];

/**
 * Wall-clock time to report to X.509 validity checks, as Unix seconds:
 * 2025-06-15T00:00:00Z. Well inside the notBefore/notAfter window of
 * the DMTF sample ECDSA-P256 chains above (notBefore ~ 2023,
 * notAfter ~ 2033). Update if the sample certificates are regenerated
 * with a window that no longer contains this value.
 *
 * The samples feed this to libspdm_zephyr_wallclock_set_fixed(). It
 * belongs with the certificates, not with the port: a real device
 * installs its own time source instead (see
 * libspdm/zephyr/include/libspdm/zephyr/wallclock.h).
 */
#define SAMPLE_ECP256_WALLCLOCK_S 1749945600

#endif /* SAMPLE_ECP256_H */
