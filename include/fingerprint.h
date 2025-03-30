/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <glib.h>
#include <gio/gio.h>
#include "fingerprint_backend.h"

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

/**
 * Initialize the fingerprint subsystem
 * @param connection D-Bus connection to use for communication
 */
void
fingerprint_init(GDBusConnection *connection);

/**
 * Clean up resources used by the fingerprint subsystem
 * @param connection D-Bus connection used for communication
 */
void
fingerprint_cleanup(GDBusConnection *connection);

/**
 * Register the fingerprint object on D-Bus
 * @param connection D-Bus connection to register with
 * @param error Error return location
 * @return ID of the registered object or 0 on failure
 */
guint
fingerprint_register(GDBusConnection *connection, GError **error);

/**
 * Get the current biometric state
 * @return Current state of the fingerprint subsystem
 */
BiometricState
fingerprint_get_state(void);

/**
 * Get the enrollment progress percentage
 * @return Progress value from 0-100
 */
gint
fingerprint_get_enrollment_progress(void);

/**
 * Get the list of enrolled fingerprints
 * @return Array of fingerprint names (caller should not modify or free)
 */
GArray *
fingerprint_get_enrolled_fingers(void);

/**
 * Get the current error information
 * @return Current error status
 */
BiometricError
fingerprint_get_error_info(void);

/**
 * Get the current acquisition information
 * @return Current acquisition status
 */
BiometricAcquisition
fingerprint_get_acquisition_info(void);

/**
 * Set the current biometric state
 * @param state New biometric state
 */
void
fingerprint_set_state(BiometricState state);

/**
 * Set the current enrollment progress
 * @param progress Progress value from 0-100
 */
void
fingerprint_set_enrollment_progress(gint progress);

/**
 * Set the current error information
 * @param error New error status
 */
void
fingerprint_set_error_info(BiometricError error);

/**
 * Set the current acquisition information
 * @param info New acquisition status
 */
void
fingerprint_set_acquisition_info(BiometricAcquisition info);

/**
 * Add a fingerprint to the list of enrolled fingerprints
 * @param finger_name Name to identify the fingerprint
 * @return TRUE on success, FALSE on failure
 */
gboolean
fingerprint_add_enrolled_finger(const gchar *finger_name);

/**
 * Remove a fingerprint from the list of enrolled fingerprints
 * @param finger_name Name of the fingerprint to remove
 * @return TRUE on success, FALSE if not found
 */
gboolean
fingerprint_remove_enrolled_finger(const gchar *finger_name);

/**
 * Map backend-specific error codes to BiometricError
 * @param error Backend error code
 * @return Corresponding BiometricError value
 */
BiometricError
map_error_to_biometric_error(guint32 error);

/**
 * Map backend-specific acquisition codes to BiometricAcquisition
 * @param info Backend acquisition code
 * @return Corresponding BiometricAcquisition value
 */
BiometricAcquisition
map_acquisition_to_biometric_acquisition(guint32 info);

#endif // FINGERPRINT_H
