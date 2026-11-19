/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Coverity Scan model for libspdm. It is not part of the build. Upload it on the project's
 * Analysis Settings tab in Coverity Scan whenever it changes. A model replaces the analysis of
 * the function's own source.
 */

typedef unsigned long size_t;

/*
 * libspdm_zero_mem() writes zeros to the first length bytes. Coverity's derived model has it
 * zero the whole object, so after libspdm_session_info_init() zeroes session_info up to
 * secured_message_context, that pointer appears to be NULL.
 */
void libspdm_zero_mem(void *buffer, size_t length)
{
    __coverity_writeall__(buffer);
}

/* LIBSPDM_ASSERT() calls this in Debug builds. It does not return. */
void libspdm_debug_assert(const char *file_name, size_t line_number, const char *description)
{
    __coverity_panic__();
}
