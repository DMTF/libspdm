/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/**
 * @file
 * Dummy static blob store for the libspdm Zephyr samples.
 */

#ifndef SAMPLE_STATIC_BLOB_STORE_H
#define SAMPLE_STATIC_BLOB_STORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Upper bound on the number of tables that may be registered at once
 *  (e.g. one per algorithm or per role). Override with -D if a sample
 *  needs more.
 */
#ifndef SAMPLE_STATIC_BLOB_MAX_TABLES
#define SAMPLE_STATIC_BLOB_MAX_TABLES 4
#endif

struct sample_static_blob {
    /** Lookup path, e.g. "ecp256/end_responder.key". NULL terminates a table. */
    const char *path;
    const uint8_t *data;
    size_t length;
};

/**
 * Register a NULL-terminated array of blobs. Multiple tables may be
 * registered; lookups walk them in registration order. The pointer must
 * remain valid for the lifetime of the program — typically the blobs
 * live in flash via `static const`.
 *
 * @retval 0          on success
 * @retval -ENOMEM    too many tables registered
 */
int sample_static_blob_register(const struct sample_static_blob *table);

/** Drop all registered tables. */
void sample_static_blob_reset(void);

/**
 * Look up a registered blob by path.
 *
 * @param path Path string to match, as passed to libspdm's
 *             file-oriented device-secret hooks.
 *
 * @return The matching entry, or NULL if no registered table carries
 *         @p path. The returned pointer stays valid as long as the
 *         owning table remains registered.
 */
const struct sample_static_blob *sample_static_blob_find(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SAMPLE_STATIC_BLOB_STORE_H */
