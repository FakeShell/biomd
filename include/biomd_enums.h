/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef BIOMD_ENUMS_H
#define BIOMD_ENUMS_H

/**
 * Biometric state values representing the current operational state
 */
typedef enum {
    STATE_IDLE = 0,         /**< No operation in progress */
    STATE_ENROLLING = 1,    /**< Enrollment in progress */
    STATE_IDENTIFYING = 2   /**< Identification in progress */
} BiometricState;

/**
 * Error codes for biometric operations
 */
typedef enum {
    ERROR_NONE = 0,                 /**< No error */
    ERROR_HW_UNAVAILABLE = 1,       /**< Hardware not available */
    ERROR_UNABLE_TO_PROCESS = 2,    /**< Unable to process the current sample */
    ERROR_TIMEOUT = 3,              /**< Operation timed out */
    ERROR_NO_SPACE = 4,             /**< No space available to store fingerprint */
    ERROR_CANCELED = 5,             /**< Operation was canceled */
    ERROR_REMOVE = 6,               /**< Error removing fingerprint */
    ERROR_LOCKOUT = 7,              /**< Too many failed attempts, device locked */
    ERROR_GENERAL = 8               /**< Generic error */
} BiometricError;

/**
 * Acquisition status codes for fingerprint scanning
 */
typedef enum {
    ACQUISITION_NONE = 0,           /**< No acquisition status */
    ACQUISITION_GOOD = 1,           /**< Good image acquired */
    ACQUISITION_PARTIAL = 2,        /**< Partial image acquired */
    ACQUISITION_INSUFFICIENT = 3,   /**< Image quality insufficient */
    ACQUISITION_IMAGER_DIRTY = 4,   /**< Sensor is dirty */
    ACQUISITION_TOO_SLOW = 5,       /**< Swipe too slow */
    ACQUISITION_TOO_FAST = 6        /**< Swipe too fast */
} BiometricAcquisition;

#endif // BIOMD_ENUMS_H
