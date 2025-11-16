/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <openssl/err.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include "hal/library/cryptlib/cryptlib_tpm.h"

#include "key_context.h"

bool g_tpm_device_initialized = false;

static libspdm_key_context *create_key_context(EVP_PKEY *pkey)
{
    libspdm_key_context *context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    context->evp_pkey = pkey;
    return context;
}

static void print_openssl_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "OpenSSL error: %s\n", buf);
    }
}

bool libspdm_tpm_device_init()
{
    OSSL_PROVIDER *tpm_provider = NULL;

    if (g_tpm_device_initialized)
        return true;

    OSSL_PROVIDER_set_default_search_path(NULL, "/usr/lib/aarch64-linux-gnu/ossl-modules/");
    tpm_provider = OSSL_PROVIDER_load(NULL, "tpm2");
    if (tpm_provider == NULL)
    {
        fprintf(stderr, "ERROR: failed to load tpm2\n");
        print_openssl_errors();
        return false;
    }

    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    g_tpm_device_initialized = true;
    return true;
}

static bool get_keyinfo(const char *handle, void **context, int keyinfo_type)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    /* handle must look like: "tpm2tss:0x81010002" */
    store_ctx = OSSL_STORE_open_ex(handle, NULL, "provider=tpm2", NULL, NULL, NULL, NULL, NULL);
    if (!store_ctx)
    {
        return false;
    }

    while ((info = OSSL_STORE_load(store_ctx)) != NULL)
    {
        if (OSSL_STORE_INFO_get_type(info) == keyinfo_type)
        {
            switch (keyinfo_type)
            {
            case OSSL_STORE_INFO_PKEY:
                *context = OSSL_STORE_INFO_get1_PKEY(info);
                break;
            case OSSL_STORE_INFO_PUBKEY:
                *context = OSSL_STORE_INFO_get1_PUBKEY(info);
                break;
            case OSSL_STORE_INFO_CERT:
                *context = OSSL_STORE_INFO_get1_CERT(info);
                break;
            }
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (*context == NULL)
    {
        fprintf(stderr, "no keyinfo %d found on handle %s\n", keyinfo_type, handle);
        return false;
    }

    return true;
}

bool libspdm_tpm_get_private_key(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY))
    {
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

bool libspdm_tpm_get_public_key(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY))
    {
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

bool libspdm_tpm_get_certificate(void *handle, void **context)
{
    return get_keyinfo((const char *)handle, context, OSSL_STORE_INFO_CERT);
}

bool libspdm_tpm_dump_certificate(void *context, void **buffer, size_t *size)
{
    int len = 0;
    len = i2d_X509((X509 *)context, NULL);
    if (len < 0)
        return false;

    void *cert = OPENSSL_malloc(len);
    if (cert == NULL)
    {
        return false;
    }
    *buffer = cert;
    len = i2d_X509((X509 *)context, (unsigned char **)&cert);
    if (len < 0)
    {
        free(*buffer);
        *buffer = NULL;
        return false;
    }
    *size = len;
    return true;
}
