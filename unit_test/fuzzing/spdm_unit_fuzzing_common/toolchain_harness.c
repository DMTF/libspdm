/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#undef NULL
#include "hal/base.h"
#include "hal/library/memlib.h"
#include "toolchain_harness.h"
#include "library/malloclib.h"

#ifdef TEST_WITH_LIBFUZZER
#include <stdint.h>
#include <stddef.h>
uint8_t req_or_res = 0;
#endif
#ifdef TEST_WITH_KLEE
#include <klee/klee.h>
#endif

uintn libspdm_alignment_size(uintn size, uint8_t req_or_res)
{
    uintn alignment;
    alignment = LIBSPDM_TEST_ALIGNMENT;

    if (((size) & (alignment - 1)) == 3)
        size += 1;
    if (((size) & (alignment - 1)) == 2)
        size += 2;
    if (((size) & (alignment - 1)) == 1)
        size += 3;
    size = size + req_or_res;
    return size;
}

bool libspdm_init_test_buffer(const char *file_name, uintn max_buffer_size,
                              void **test_buffer, uintn *buffer_size)
{
    void *buffer;
    FILE *file;
    uintn file_size;
    uintn BytesRead;
    uint8_t return_status;

    /* 1. Allocate buffer*/
    buffer = malloc(max_buffer_size);
    if (buffer == NULL) {
        return false;
    }

    /* 2. Assign to test_buffer and buffer_size*/
    *test_buffer = buffer;
    if (buffer_size != NULL) {
        *buffer_size = max_buffer_size;
    }

    /* 3. Initialize test_buffer*/
#ifdef TEST_WITH_KLEE
    /* 3.1 For test with KLEE: write symbolic values to test_buffer*/
    klee_make_symbolic((uint8_t *)buffer, max_buffer_size, "buffer");
    return true;
#endif

    file = fopen(file_name, "rb");
    if (file == NULL) {
        fputs("file error", stderr);
        free(buffer);
        exit(1);
    }
    fseek(file, 0, SEEK_END);

    file_size = ftell(file);
    rewind(file);

    file_size = file_size > max_buffer_size ? max_buffer_size : file_size;
    return_status = libspdm_judge_requster_name(file_name);
    if (return_status == 1) {
        *(uint8_t *)buffer = LIBSPDM_TEST_MESSAGE_TYPE_SPDM;
        BytesRead = fread((char *)buffer + 1, 1, file_size, file);
    } else {
        BytesRead = fread((char *)buffer, 1, file_size, file);
    }
    if (BytesRead != file_size) {
        fputs("file error", stderr);
        free(buffer);
        exit(1);
    }
    fclose(file);

    file_size = libspdm_alignment_size(file_size, return_status);

    if (buffer_size != NULL) {
        *buffer_size = file_size;
    }

    return true;
}

uint8_t libspdm_judge_requster_name(const char *file_name)
{
    char *file_p;
    char *requester_name_p;
    char *pSave;
    char flag;
    char requester_name[] = "test_spdm_requester";

    file_p = (char *)file_name;
    requester_name_p = NULL;
    pSave = NULL;

    while (*file_p) {
        if (*file_p == requester_name[0] &&
            strlen(file_p) >= strlen(requester_name)) {
            pSave = file_p;
            requester_name_p = &requester_name[0];
            flag = 1;
            while (*requester_name_p) {
                if (*file_p != *requester_name_p) {
                    flag = 0;
                    break;
                }
                file_p++;
                requester_name_p++;
            }
            if (flag == 1) {
                return 1;
            } else
                file_p = pSave;
        }
        file_p++;
    }
    return 0;
}

#ifdef TEST_WITH_LIBFUZZER
#ifdef TEST_WITH_LIBFUZZERWIN
int LLVMFuzzerTestOneInput(const wint_t *data, size_t size)
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#endif
{
    void *test_buffer;
    uintn max_buffer_size;

    /* 1. Initialize test_buffer*/
    max_buffer_size = libspdm_get_max_buffer_size();
    test_buffer = allocate_zero_pool(max_buffer_size);
    if (test_buffer == NULL) {
        return 0;
    }
    if (size > max_buffer_size) {
        size = max_buffer_size;
    }

    if (req_or_res == 1) {
        *(uint8_t *)test_buffer = LIBSPDM_TEST_MESSAGE_TYPE_SPDM;
        if (size == max_buffer_size) {
            libspdm_copy_mem((uint8_t *)test_buffer + 1, max_buffer_size - 1, data, size - 1);
        } else {
            libspdm_copy_mem((uint8_t *)test_buffer + 1, max_buffer_size - 1, data, size);
        }
    }
    else{
        libspdm_copy_mem(test_buffer, max_buffer_size, data, size);
    }
    size = libspdm_alignment_size(size, req_or_res);
    /* 2. Run test*/
    libspdm_run_test_harness(test_buffer, size);
    /* 3. Clean up*/
    free(test_buffer);
    return 0;
}
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char *file_name;
    if (*argc <= 1) {
        printf("info - missing input file\n");
    }
    else{
        file_name = (*argv)[1];
        req_or_res = libspdm_judge_requster_name(file_name);
    }
    return 0;
}
#else
int main(int argc, char **argv)
{
    bool res;
    void *test_buffer;
    uintn test_buffer_size;
    char *file_name;

    if (argc <= 1) {
        printf("error - missing input file\n");
        exit(1);
    }

    file_name = argv[1];

    /* 1. Initialize test_buffer*/
    res = libspdm_init_test_buffer(file_name, libspdm_get_max_buffer_size(), &test_buffer,
                                   &test_buffer_size);
    if (!res) {
        printf("error - fail to init test buffer\n");
        return 0;
    }
    /* 2. Run test*/
    libspdm_run_test_harness(test_buffer, test_buffer_size);
    /* 3. Clean up*/
    free(test_buffer);
    return 0;
}
#endif
