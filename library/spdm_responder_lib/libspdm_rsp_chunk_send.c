#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CHUNK_CAP

libspdm_return_t libspdm_get_response_chunk_send(void* context,
                                                 size_t request_size,
                                                 const void* request,
                                                 size_t* response_size,
                                                 void* response)
{
    return 0;
}

#endif /* LIBSPDM_ENABLE_CHUNK_CAP */