/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"

void dump_hex_str(IN uint8_t *buffer, IN uintn buffer_size)
{
    uintn index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}

void dump_data(IN uint8_t *buffer, IN uintn buffer_size)
{
    uintn index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x ", buffer[index]);
    }
}

void dump_hex(IN uint8_t *data, IN uintn size)
{
    uintn index;
    uintn count;
    uintn left;

#define COLUME_SIZE (16 * 2)

    count = size / COLUME_SIZE;
    left = size % COLUME_SIZE;
    for (index = 0; index < count; index++) {
        printf("%04x: ", (uint32_t)(index * COLUME_SIZE));
        dump_data(data + index * COLUME_SIZE, COLUME_SIZE);
        printf("\n");
    }

    if (left != 0) {
        printf("%04x: ", (uint32_t)(index * COLUME_SIZE));
        dump_data(data + index * COLUME_SIZE, left);
        printf("\n");
    }
}

boolean read_input_file(IN char8 *file_name, OUT void **file_data,
            OUT uintn *file_size)
{
    FILE *fp_in;
    uintn temp_result;

    if ((fp_in = fopen(file_name, "rb")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        *file_data = NULL;
        return FALSE;
    }

    fseek(fp_in, 0, SEEK_END);
    *file_size = ftell(fp_in);

    *file_data = (void *)malloc(*file_size);
    if (NULL == *file_data) {
        printf("No sufficient memory to allocate %s\n", file_name);
        fclose(fp_in);
        return FALSE;
    }

    fseek(fp_in, 0, SEEK_SET);
    temp_result = fread(*file_data, 1, *file_size, fp_in);
    if (temp_result != *file_size) {
        printf("Read input file error %s", file_name);
        free((void *)*file_data);
        fclose(fp_in);
        return FALSE;
    }

    fclose(fp_in);

    return TRUE;
}

boolean write_output_file(IN char8 *file_name, IN void *file_data,
              IN uintn file_size)
{
    FILE *fp_out;

    if ((fp_out = fopen(file_name, "w+b")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        return FALSE;
    }

    if ((fwrite(file_data, 1, file_size, fp_out)) != file_size) {
        printf("Write output file error %s\n", file_name);
        fclose(fp_out);
        return FALSE;
    }

    fclose(fp_out);

    return TRUE;
}
