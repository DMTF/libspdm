/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Dummy static blob store: a path -> {pointer, length} lookup over
 * key material compiled into the image. Sample scaffolding only.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/kernel.h>

#include "sample_static_blob_store.h"

static const struct sample_static_blob *tables[SAMPLE_STATIC_BLOB_MAX_TABLES];
static size_t table_count;
static struct k_spinlock blob_lock;

int sample_static_blob_register(const struct sample_static_blob *table)
{
    k_spinlock_key_t key;
    int ret = 0;

    if (table == NULL) {
        return -EINVAL;
    }

    key = k_spin_lock(&blob_lock);
    if (table_count >= SAMPLE_STATIC_BLOB_MAX_TABLES) {
        ret = -ENOMEM;
    } else {
        tables[table_count++] = table;
    }
    k_spin_unlock(&blob_lock, key);
    return ret;
}

void sample_static_blob_reset(void)
{
    k_spinlock_key_t key = k_spin_lock(&blob_lock);

    for (size_t i = 0; i < SAMPLE_STATIC_BLOB_MAX_TABLES; i++) {
        tables[i] = NULL;
    }
    table_count = 0;
    k_spin_unlock(&blob_lock, key);
}

const struct sample_static_blob *sample_static_blob_find(const char *path)
{
    const struct sample_static_blob *match = NULL;
    k_spinlock_key_t key;

    if (path == NULL) {
        return NULL;
    }

    key = k_spin_lock(&blob_lock);
    for (size_t t = 0; t < table_count && match == NULL; t++) {
        const struct sample_static_blob *entry = tables[t];

        if (entry == NULL) {
            continue;
        }
        for (; entry->path != NULL; entry++) {
            if (strcmp(entry->path, path) == 0) {
                match = entry;
                break;
            }
        }
    }
    k_spin_unlock(&blob_lock, key);
    return match;
}
