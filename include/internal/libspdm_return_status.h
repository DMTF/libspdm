/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_RETURN_STATUS_INTERNAL_H__
#define __SPDM_RETURN_STATUS_INTERNAL_H__

/* status codes common to all execution phases*/

typedef size_t return_status;

/**
 * Produces a return_status code with the highest bit set.
 *
 * @param  status_code    The status code value to convert into a warning code.
 *                      status_code must be in the range 0x00000000..0x7FFFFFFF.
 *
 * @return The value specified by status_code with the highest bit set.
 *
 **/
#define ENCODE_ERROR(status_code) ((return_status)(MAX_BIT | (status_code)))

/**
 * Produces a return_status code with the highest bit clear.
 *
 * @param  status_code    The status code value to convert into a warning code.
 *                      status_code must be in the range 0x00000000..0x7FFFFFFF.
 *
 * @return The value specified by status_code with the highest bit clear.
 *
 **/
#define ENCODE_WARNING(status_code) ((return_status)(status_code))

/**
 * Returns true if a specified return_status code is an error code.
 *
 * This function returns true if status_code has the high bit set.  Otherwise, false is returned.
 *
 * @param  status_code    The status code value to evaluate.
 *
 * @retval true          The high bit of status_code is set.
 * @retval false         The high bit of status_code is clear.
 *
 **/
#define RETURN_ERROR(status_code) (((return_status)(status_code) & MAX_BIT) != 0)


/* The operation completed successfully.*/

#define RETURN_SUCCESS 0


/* The image failed to load.*/

#define RETURN_LOAD_ERROR ENCODE_ERROR(1)


/* The parameter was incorrect.*/

#define RETURN_INVALID_PARAMETER ENCODE_ERROR(2)


/* The operation is not supported.*/

#define RETURN_UNSUPPORTED ENCODE_ERROR(3)


/* The buffer was not the proper size for the request.*/

#define RETURN_BAD_BUFFER_SIZE ENCODE_ERROR(4)


/* The buffer was not large enough to hold the requested data.
 * The required buffer size is returned in the appropriate
 * parameter when this error occurs.*/

#define RETURN_BUFFER_TOO_SMALL ENCODE_ERROR(5)


/* There is no data pending upon return.*/

#define RETURN_NOT_READY ENCODE_ERROR(6)


/* The physical device reported an error while attempting the
 * operation.*/

#define RETURN_DEVICE_ERROR ENCODE_ERROR(7)


/* The device can not be written to.*/

#define RETURN_WRITE_PROTECTED ENCODE_ERROR(8)


/* The resource has run out.*/

#define RETURN_OUT_OF_RESOURCES ENCODE_ERROR(9)


/* An inconsistency was detected on the file system causing the
 * operation to fail.*/

#define RETURN_VOLUME_CORRUPTED ENCODE_ERROR(10)


/* There is no more space on the file system.*/

#define RETURN_VOLUME_FULL ENCODE_ERROR(11)


/* The device does not contain any medium to perform the
 * operation.*/

#define RETURN_NO_MEDIA ENCODE_ERROR(12)


/* The medium in the device has changed since the last
 * access.*/

#define RETURN_MEDIA_CHANGED ENCODE_ERROR(13)


/* The item was not found.*/

#define RETURN_NOT_FOUND ENCODE_ERROR(14)


/* Access was denied.*/

#define RETURN_ACCESS_DENIED ENCODE_ERROR(15)


/* The server was not found or did not respond to the request.*/

#define RETURN_NO_RESPONSE ENCODE_ERROR(16)


/* A mapping to the device does not exist.*/

#define RETURN_NO_MAPPING ENCODE_ERROR(17)


/* A timeout time expired.*/

#define RETURN_TIMEOUT ENCODE_ERROR(18)


/* The protocol has not been started.*/

#define RETURN_NOT_STARTED ENCODE_ERROR(19)


/* The protocol has already been started.*/

#define RETURN_ALREADY_STARTED ENCODE_ERROR(20)


/* The operation was aborted.*/

#define RETURN_ABORTED ENCODE_ERROR(21)


/* An ICMP error occurred during the network operation.*/

#define RETURN_ICMP_ERROR ENCODE_ERROR(22)


/* A TFTP error occurred during the network operation.*/

#define RETURN_TFTP_ERROR ENCODE_ERROR(23)


/* A protocol error occurred during the network operation.*/

#define RETURN_PROTOCOL_ERROR ENCODE_ERROR(24)


/* A function encountered an internal version that was
 * incompatible with a version requested by the caller.*/

#define RETURN_INCOMPATIBLE_VERSION ENCODE_ERROR(25)


/* The function was not performed due to a security violation.*/

#define RETURN_SECURITY_VIOLATION ENCODE_ERROR(26)


/* A CRC error was detected.*/

#define RETURN_CRC_ERROR ENCODE_ERROR(27)


/* The beginning or end of media was reached.*/

#define RETURN_END_OF_MEDIA ENCODE_ERROR(28)


/* The end of the file was reached.*/

#define RETURN_END_OF_FILE ENCODE_ERROR(31)


/* The language specified was invalid.*/

#define RETURN_INVALID_LANGUAGE ENCODE_ERROR(32)


/* The security status of the data is unknown or compromised
 * and the data must be updated or replaced to restore a valid
 * security status.*/

#define RETURN_COMPROMISED_DATA ENCODE_ERROR(33)


/* A HTTP error occurred during the network operation.*/

#define RETURN_HTTP_ERROR ENCODE_ERROR(35)


/* The string contained one or more characters that
 * the device could not render and were skipped.*/

#define RETURN_WARN_UNKNOWN_GLYPH ENCODE_WARNING(1)


/* The handle was closed, but the file was not deleted.*/

#define RETURN_WARN_DELETE_FAILURE ENCODE_WARNING(2)


/* The handle was closed, but the data to the file was not
 * flushed properly.*/

#define RETURN_WARN_WRITE_FAILURE ENCODE_WARNING(3)


/* The resulting buffer was too small, and the data was
 * truncated to the buffer size.*/

#define RETURN_WARN_BUFFER_TOO_SMALL ENCODE_WARNING(4)


/* The data has not been updated within the timeframe set by
 * local policy for this type of data.*/

#define RETURN_WARN_STALE_DATA ENCODE_WARNING(5)


/* The resulting buffer contains file system.*/

#define RETURN_WARN_FILE_SYSTEM ENCODE_WARNING(6)

#endif
