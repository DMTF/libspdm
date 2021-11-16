/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#undef NULL
#include <hal/base.h>
#include <hal/library/memlib.h>
#include "toolchain_harness.h"

#ifdef TEST_WITH_LIBFUZZER
#include <stdint.h>
#include <stddef.h>
#endif

#ifdef TEST_WITH_KLEE
#include <klee/klee.h>
#endif

boolean init_test_buffer(IN char8 *file_name, IN uintn max_buffer_size,
			 IN void **test_buffer, OUT uintn *buffer_size)
{
	void *buffer;
	FILE *file;
	uintn file_size;
	uintn BytesRead;

	// 1. Allocate buffer
	buffer = malloc(max_buffer_size);
	if (buffer == NULL) {
		return FALSE;
	}

	// 2. Assign to test_buffer and buffer_size
	*test_buffer = buffer;
	if (buffer_size != NULL) {
		*buffer_size = max_buffer_size;
	}

	// 3. Initialize test_buffer
#ifdef TEST_WITH_KLEE
	// 3.1 For test with KLEE: write symbolic values to test_buffer
	klee_make_symbolic((uint8_t *)buffer, max_buffer_size, "buffer");
	return TRUE;
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
	BytesRead = fread((void *)buffer, 1, file_size, file);
	if (BytesRead != file_size) {
		fputs("file error", stderr);
		free(buffer);
		exit(1);
	}
	fclose(file);

	if (buffer_size != NULL) {
		*buffer_size = file_size;
	}
	return TRUE;
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

	// 1. Initialize test_buffer
	max_buffer_size = get_max_buffer_size();
	test_buffer = allocate_zero_pool(max_buffer_size);
	if (test_buffer == NULL) {
		return 0;
	}
	if (size > max_buffer_size) {
		size = max_buffer_size;
	}
	copy_mem(test_buffer, data, size);
	// 2. Run test
	run_test_harness(test_buffer, size);
	// 3. Clean up
	free(test_buffer);
	return 0;
}
#else
int main(int argc, char **argv)
{
	boolean res;
	void *test_buffer;
	uintn test_buffer_size;
	char8 *file_name;

	if (argc <= 1) {
		printf("error - missing input file\n");
		exit(1);
	}

	file_name = argv[1];

	// 1. Initialize test_buffer
	res = init_test_buffer(file_name, get_max_buffer_size(), &test_buffer,
			       &test_buffer_size);
	if (!res) {
		printf("error - fail to init test buffer\n");
		return 0;
	}
	// 2. Run test
	run_test_harness(test_buffer, test_buffer_size);
	// 3. Clean up
	free(test_buffer);
	return 0;
}
#endif
