/*
 * TODO: APIs in this file need to be the part of crypto libraries
 */

#include <dlfcn.h>

#include "crypto_stub_internal.h"


bool g_tpm_device_initialized = false;
OSSL_LIB_CTX* g_libctx = NULL;

void libspdm_tpm_device_init() {
    if (g_tpm_device_initialized)
        return;

    g_libctx = OSSL_LIB_CTX_new();

    void *handle = dlopen("tpm2.so", RTLD_GLOBAL | RTLD_NOW);
    if (handle == NULL){
        fprintf(stderr, "dlopen: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    OSSL_provider_init_fn *fun = (OSSL_provider_init_fn *)dlsym(handle, "OSSL_provider_init");
    if (fun == NULL){
        fprintf(stderr, "dlsym: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    if (OSSL_PROVIDER_add_builtin(g_libctx, "tpm2", fun) <= 0){
        fprintf(stderr, "ERROR: failed to add builtin\n");
        exit(EXIT_FAILURE);
    }

    OSSL_PROVIDER *tpm_provider = NULL;

    if ((tpm_provider = OSSL_PROVIDER_load(g_libctx, "tpm2")) == NULL){
        fprintf(stderr, "ERROR: failed to load tpm2\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "SELF TEST %d\n", OSSL_PROVIDER_self_test(tpm_provider));

    fprintf(stdout, "************************************\n"
            " Loaded tpm2 module successfully\n");
    fprintf(stdout, "TPM2: %p\n", (void *)tpm_provider);

    g_tpm_device_initialized = true;
}


bool libspdm_read_private_key_from_tpm(const char *handle, void **context)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    EVP_PKEY *pkey = NULL;

    fprintf(stdout, "IS TPM AVAIABLE %d\n", OSSL_PROVIDER_available(g_libctx, "tpm2"));

    /* handle must look like: "tpm2tss:0x81010002" */
    store_ctx = OSSL_STORE_open_ex("handle:0x81010003", g_libctx, "provider=tpm2", NULL, NULL, NULL, NULL, NULL);
    if (!store_ctx){
        return false;
    }

    while ((info = OSSL_STORE_load(store_ctx)) != NULL)
    {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY){
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (pkey == NULL){
        fprintf(stderr, "no private key found in tpm handle %s\n", handle);
        return false;
    }

    *context = pkey;
    return true;
}
