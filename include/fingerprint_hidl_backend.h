/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FINGERPRINT_HIDL_BACKEND_H
#define FINGERPRINT_HIDL_BACKEND_H

#include <glib.h>
#include "fingerprint_backend.h"

/**
* Error codes defined by HIDL fingerprint interface
* These map to the Android HIDL fingerprint error codes
*/
typedef enum {
   FINGERPRINT_ERROR_NO_ERROR = 0,       /**< No error occurred */
   FINGERPRINT_ERROR_HW_UNAVAILABLE = 1, /**< Hardware not available */
   FINGERPRINT_ERROR_UNABLE_TO_PROCESS = 2, /**< Unable to process the current image */
   FINGERPRINT_ERROR_TIMEOUT = 3,        /**< Operation timed out */
   FINGERPRINT_ERROR_NO_SPACE = 4,       /**< No space available for operation */
   FINGERPRINT_ERROR_CANCELED = 5,       /**< Operation was canceled */
   FINGERPRINT_ERROR_UNABLE_TO_REMOVE = 6, /**< Unable to remove the referenced fingerprint */
   FINGERPRINT_ERROR_LOCKOUT = 7,        /**< Too many failed attempts, sensor locked */
   FINGERPRINT_ERROR_VENDOR = 8          /**< Vendor-specific error */
} FingerprintError;

/**
* Acquisition status codes defined by HIDL fingerprint interface
* These describe the quality/status of a fingerprint image scan
*/
typedef enum {
   FINGERPRINT_ACQUIRED_GOOD = 0,        /**< Good quality image acquired */
   FINGERPRINT_ACQUIRED_PARTIAL = 1,     /**< Partial/incomplete image acquired */
   FINGERPRINT_ACQUIRED_INSUFFICIENT = 2, /**< Image quality insufficient for processing */
   FINGERPRINT_ACQUIRED_IMAGER_DIRTY = 3, /**< Sensor needs cleaning */
   FINGERPRINT_ACQUIRED_TOO_SLOW = 4,    /**< Finger moved too slowly during scan */
   FINGERPRINT_ACQUIRED_TOO_FAST = 5,    /**< Finger moved too quickly during scan */
   FINGERPRINT_ACQUIRED_VENDOR = 6       /**< Vendor-specific acquisition message */
} FingerprintAcquiredInfo;

/**
* Create a new HIDL backend instance with the specified callbacks
*
* @param callbacks Callback functions to be invoked by the backend
* @return A new FingerprintBackend instance or NULL if creation failed
*/
FingerprintBackend *
fingerprint_hidl_backend_new(FingerprintBackendCallbacks callbacks);

#endif // FINGERPRINT_HIDL_BACKEND_H
