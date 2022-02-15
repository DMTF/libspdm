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
#endif

#ifdef TEST_WITH_KLEE
#include <klee/klee.h>
#endif

bool init_test_buffer(IN char *file_name, IN uintn max_buffer_size,
                      IN void **test_buffer, OUT uintn *buffer_size)
{
    void *buffer;
    FILE *file;
    uintn file_size;
    uintn BytesRead;
    uintn alignment;
    uint8_t return_status;

    alignment = TEST_ALIGNMENT;

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
    return_status = judge_requster_name(file_name);
    if (return_status == 1) {
        *(uint8_t *)buffer = TEST_MESSAGE_TYPE_SPDM;
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

    if (((file_size) & (alignment - 1)) == 3)
        file_size += 1;
    if (((file_size) & (alignment - 1)) == 2)
        file_size += 2;
    if (((file_size) & (alignment - 1)) == 1)
        file_size += 3;
    file_size = file_size + return_status;

    if (buffer_size != NULL) {
        *buffer_size = file_size;
    }

    return true;
}

uint8_t judge_requster_name(IN char *file_name)
{
    char *file_p = file_name, *requester_name_p = NULL, *pSave = NULL, flag;
    char requester_name[] = "test_spdm_requester";

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
    max_buffer_size = get_max_buffer_size();
    test_buffer = allocate_zero_pool(max_buffer_size);
    if (test_buffer == NULL) {
        return 0;
    }
    if (size > max_buffer_size) {
        size = max_buffer_size;
    }
    copy_mem_s(test_buffer, max_buffer_size, data, size);
    /* 2. Run test*/
    run_test_harness(test_buffer, size);
    /* 3. Clean up*/
    free(test_buffer);
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
    res = init_test_buffer(file_name, get_max_buffer_size(), &test_buffer,
                           &test_buffer_size);
    if (!res) {
        printf("error - fail to init test buffer\n");
        return 0;
    }
    /* 2. Run test*/
    run_test_harness(test_buffer, test_buffer_size);
    /* 3. Clean up*/
    free(test_buffer);
    return 0;
}
#endif
