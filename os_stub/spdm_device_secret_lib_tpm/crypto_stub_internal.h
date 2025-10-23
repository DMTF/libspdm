#ifndef __CRYPTO_SUB_INTERNAL_H__
#define __CRYPTO_SUB_INTERNAL_H__

#include <stdbool.h>

#include "openssllib/openssl/include/openssl/provider.h"
#include "openssllib/openssl/include/openssl/store.h"

void libspdm_tpm_device_init();

bool libspdm_read_private_key_from_tpm(const char *handle, void **context);

#endif
