/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FINGERPRINT_BINDER_HIDL_H
#define FINGERPRINT_BINDER_HIDL_H

#include <glib.h>
#include <gio/gio.h>
#include "fingerprint_hidl_backend.h"

typedef struct _BiomFingerprintHidl BiomFingerprintHidl;

typedef struct {
    /**
     * Called when enrollment progress is made
     * @param user_data User-provided data pointer
     * @param finger_id ID of the finger being enrolled
     * @param group_id Group ID for the fingerprint
     * @param remaining Number of steps remaining for enrollment
     */
    void (*enroll_result)(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining);

    /**
     * Called when fingerprint sample is acquired
     * @param user_data User-provided data pointer
     * @param acquired_info Information about the quality of the acquired sample
     * @param vendor_code Vendor-specific information
     */
    void (*acquired)(gpointer user_data, FingerprintAcquiredInfo acquired_info, guint32 vendor_code);

    /**
     * Called when authentication is successful
     * @param user_data User-provided data pointer
     * @param finger_id ID of the authenticated finger
     * @param group_id Group ID for the fingerprint
     */
    void (*authenticated)(gpointer user_data, guint32 finger_id, guint32 group_id);

    /**
     * Called when an error occurs
     * @param user_data User-provided data pointer
     * @param error_code Error code describing what went wrong
     * @param vendor_code Vendor-specific error information
     */
    void (*error)(gpointer user_data, FingerprintError error_code, guint32 vendor_code);

    /**
     * Called when a fingerprint is removed
     * @param user_data User-provided data pointer
     * @param finger_id ID of the removed finger
     * @param group_id Group ID for the fingerprint
     * @param remaining Number of fingerprints still enrolled
     */
    void (*removed)(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining);

    /**
     * Called when enumerating through enrolled fingerprints
     * @param user_data User-provided data pointer
     * @param finger_id ID of the current finger in enumeration
     * @param group_id Group ID for the fingerprint
     * @param remaining Number of fingerprints remaining to enumerate
     */
    void (*enumerate)(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining);
} FingerprintHidlCallbacks;

/**
 * Initialize the HIDL fingerprint backend
 * @param callbacks Callback functions to be invoked by the backend
 * @param user_data User data to pass to callbacks
 * @return A new BiomFingerprintHidl instance or NULL on failure
 */
BiomFingerprintHidl*
fingerprint_hidl_init(const FingerprintHidlCallbacks *callbacks, gpointer user_data);

/**
 * Check if the HIDL fingerprint hardware is available
 * @param hidl The HIDL instance
 * @return TRUE if available, FALSE otherwise
 */
gboolean
fingerprint_hidl_is_available(BiomFingerprintHidl *hidl);

/**
 * Set up the default configuration for the HIDL backend
 * @param hidl The HIDL instance
 * @return TRUE on success, FALSE on failure
 */
gboolean
fingerprint_hidl_setup(BiomFingerprintHidl *hidl);

/**
 * Start fingerprint enrollment process
 * @param hidl The HIDL instance
 * @param password Password for secure storage
 * @param timeout_sec Timeout in seconds for the operation
 * @return TRUE on successful start, FALSE on failure
 */
gboolean
fingerprint_hidl_perform_enrollment(BiomFingerprintHidl *hidl, const gchar *password, guint32 timeout_sec);

/**
 * Start fingerprint authentication process
 * @param hidl The HIDL instance
 * @return TRUE on successful start, FALSE on failure
 */
gboolean
fingerprint_hidl_perform_authentication(BiomFingerprintHidl *hidl);

/**
 * Cancel current fingerprint operation
 * @param hidl The HIDL instance
 * @return TRUE on successful cancel, FALSE on failure
 */
gboolean
fingerprint_hidl_cancel_operation(BiomFingerprintHidl *hidl);

/**
 * Remove an enrolled fingerprint
 * @param hidl The HIDL instance
 * @param finger_id ID of fingerprint to remove
 * @return TRUE on success, FALSE on failure
 */
gboolean
fingerprint_hidl_remove_fingerprint(BiomFingerprintHidl *hidl, guint32 finger_id);

/**
 * Clean up HIDL resources
 * @param hidl The HIDL instance to clean up
 */
void
fingerprint_hidl_cleanup(BiomFingerprintHidl *hidl);

#endif // FINGERPRINT_BINDER_HIDL_H
