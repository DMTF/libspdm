/**
 *  Copyright Notice:
 *  Copyright 2022-2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#ifndef REQUESTER_PLATFORMLIB_H
#define REQUESTER_PLATFORMLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
/**
 * Start the watchdog timer for a given session ID.
 *
 * @param  session_id  Indicate the SPDM session ID.
 * @param  timeout     Timeout value, in units of seconds.
 **/
extern bool libspdm_start_watchdog(uint32_t session_id, uint16_t timeout);

/**
 * Stop the watchdog timer for a given session ID.
 *
 * @param  session_id Indicate the SPDM session ID.
 **/
extern bool libspdm_stop_watchdog(uint32_t session_id);

/**
 * Reset the watchdog time for a given session ID.
 *
 * @param  session_id  Indicate the SPDM session ID.
 **/
extern bool libspdm_reset_watchdog(uint32_t session_id);
#endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Stores a certificate chain in non-volatile memory.
 *
 *
 * @param[in]  slot_id          The number of slot for the certificate chain.
 * @param[in]  cert_chain       The pointer for the certificate chain to set.
 * @param[in]  cert_chain_size  The size of the certificate chain to set.
 *
 * @retval true   The certificate chain was successfully written to non-volatile memory.
 * @retval false  Unable to write certificate chain to non-volatile memory.
 **/
extern bool libspdm_write_certificate_to_nvm(uint8_t slot_id, const void * cert_chain,
                                             size_t cert_chain_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#endif /* REQUESTER_PLATFORMLIB_H */
