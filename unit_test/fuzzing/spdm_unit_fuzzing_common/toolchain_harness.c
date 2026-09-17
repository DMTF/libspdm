/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "toolchain_harness.h"
#include "library/malloclib.h"
#include <string.h>

#define LIBSPDM_FUZZ_MIN_INPUT_SIZE 4

#ifdef TEST_WITH_LIBFUZZER
#include <stdint.h>
#include <stddef.h>
#endif
#ifdef TEST_WITH_KLEE
#include <klee/klee.h>
#endif

size_t libspdm_alignment_size(size_t size)
{
    size_t alignment;
    size_t max_buffer_size;

    alignment = LIBSPDM_TEST_ALIGNMENT;
    max_buffer_size = libspdm_get_max_buffer_size();

    /* In the situation where max_buffer_size is not four-byte aligned, reserve sufficient size for the buffer_size */
    if ((size > max_buffer_size - alignment) && (size & (alignment - 1)) != 0) {
        size -= alignment;
    }

    if (((size) & (alignment - 1)) == 3) {
        size += 1;
    }
    if (((size) & (alignment - 1)) == 2) {
        size += 2;
    }
    if (((size) & (alignment - 1)) == 1) {
        size += 3;
    }
    return size;
}

bool libspdm_init_test_buffer(const char *file_name, size_t max_buffer_size,
                              void **test_buffer, size_t *buffer_size)
{
    void *buffer;
    FILE *file;
    size_t file_size;
    size_t aligned_size;
    size_t copy_size;
    size_t BytesRead;

#ifdef TEST_WITH_KLEE
    /* For test with KLEE the whole buffer is symbolic, so it is sized by the caller. */
    buffer = malloc(max_buffer_size);
    if (buffer == NULL) {
        return false;
    }
    *test_buffer = buffer;
    if (buffer_size != NULL) {
        *buffer_size = max_buffer_size;
    }
    klee_make_symbolic((uint8_t *)buffer, max_buffer_size, "buffer");
    return true;
#else

    file = fopen(file_name, "rb");
    if (file == NULL) {
        fputs("file error", stderr);
        exit(1);
    }
    fseek(file, 0, SEEK_END);

    file_size = ftell(file);
    rewind(file);

    if (file_size == 0) {
        printf("\033[1;33m file_size of the seed file is 0, so exit.\033[0m \n");
        fclose(file);
        exit(1);
    }
    if (file_size < LIBSPDM_FUZZ_MIN_INPUT_SIZE) {
        printf("file_size %zu is below the minimum SPDM message size, so exit.\n", file_size);
        fclose(file);
        exit(1);
    }
    file_size = file_size > max_buffer_size ? max_buffer_size : file_size;
    aligned_size = libspdm_alignment_size(file_size);

    /* The allocation is exactly the size that is handed to the code under test, so that a
     * read past the end of the message is a heap overflow that AddressSanitizer reports.
     * Allocating max_buffer_size, as this did previously, keeps every such read inside the
     * allocation and hides the entire class. */
    buffer = malloc(aligned_size);
    if (buffer == NULL) {
        fclose(file);
        return false;
    }
    memset(buffer, 0, aligned_size);

    copy_size = file_size < aligned_size ? file_size : aligned_size;
    BytesRead = fread((char *)buffer, 1, copy_size, file);
    if (BytesRead != copy_size) {
        fputs("file error", stderr);
        free(buffer);
        fclose(file);
        exit(1);
    }
    fclose(file);

    *test_buffer = buffer;
    if (buffer_size != NULL) {
        *buffer_size = aligned_size;
    }

    return true;
#endif
}

#ifdef TEST_WITH_LIBFUZZER
#ifdef TEST_WITH_LIBFUZZERWIN
int LLVMFuzzerTestOneInput(const wint_t *data, size_t size)
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#endif
{
    void *test_buffer;
    size_t max_buffer_size;
    size_t aligned_size;
    size_t copy_size;

    if (size < LIBSPDM_FUZZ_MIN_INPUT_SIZE) {
        return 0;
    }

    max_buffer_size = libspdm_get_max_buffer_size();
    if (size > max_buffer_size) {
        size = max_buffer_size;
    }
    aligned_size = libspdm_alignment_size(size);

    /* Allocate exactly the size that is handed to the code under test. See the comment in
     * libspdm_init_test_buffer for why over-allocating defeats AddressSanitizer here. */
    test_buffer = allocate_zero_pool(aligned_size);
    if (test_buffer == NULL) {
        return 0;
    }

    copy_size = size < aligned_size ? size : aligned_size;
    libspdm_copy_mem(test_buffer, aligned_size, data, copy_size);

    libspdm_run_test_harness(test_buffer, aligned_size);
    free(test_buffer);
    return 0;
}
#else
int main(int argc, char **argv)
{
    bool res;
    void *test_buffer;
    size_t test_buffer_size;
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
