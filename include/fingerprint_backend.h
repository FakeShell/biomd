/**
* SPDX-License-Identifier: GPL-2.0-only
* Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
*/

#ifndef FINGERPRINT_BACKEND_H
#define FINGERPRINT_BACKEND_H

#include <glib.h>

typedef struct _FingerprintBackend FingerprintBackend;

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
   void (*acquired)(gpointer user_data, guint32 acquired_info, guint32 vendor_code);

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
   void (*error)(gpointer user_data, guint32 error_code, guint32 vendor_code);

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

   /** User data passed to callbacks */
   gpointer user_data;
} FingerprintBackendCallbacks;

/**
* Virtual function table for fingerprint backends
* Each backend needs to implement these functions
*/
typedef struct {
   /**
    * Check if the backend hardware is available
    * @param self The backend instance
    * @return TRUE if available, FALSE otherwise
    */
   gboolean (*is_available)(FingerprintBackend *self);

   /**
    * Set up the default configuration for the backend
    * @param self The backend instance
    * @return TRUE on success, FALSE on failure
    */
   gboolean (*setup_default)(FingerprintBackend *self);

   /**
    * Start fingerprint enrollment process
    * @param self The backend instance
    * @param password Password for secure storage
    * @param timeout Timeout in seconds for the operation
    * @return TRUE on successful start, FALSE on failure
    */
   gboolean (*perform_enrollment)(FingerprintBackend *self, const gchar *password, guint32 timeout);

   /**
    * Start fingerprint authentication process
    * @param self The backend instance
    * @return TRUE on successful start, FALSE on failure
    */
   gboolean (*perform_authentication)(FingerprintBackend *self);

   /**
    * Cancel current fingerprint operation
    * @param self The backend instance
    * @return TRUE on successful cancel, FALSE on failure
    */
   gboolean (*cancel_operation)(FingerprintBackend *self);

   /**
    * Remove an enrolled fingerprint
    * @param self The backend instance
    * @param finger_id ID of fingerprint to remove
    * @return TRUE on success, FALSE on failure
    */
   gboolean (*remove_fingerprint)(FingerprintBackend *self, guint32 finger_id);

   /**
    * Clean up backend resources
    * @param self The backend instance
    */
   void (*cleanup)(FingerprintBackend *self);
} FingerprintBackendVTable;

struct _FingerprintBackend {
   FingerprintBackendVTable vtable;     /**< Virtual function table */
   FingerprintBackendCallbacks callbacks; /**< Callback functions */
   gpointer impl_data;                  /**< Implementation-specific data */
};

/**
* Create a new fingerprint backend
* @param vtable Virtual function table for the backend
* @param callbacks Callback functions to be invoked by the backend
* @return A new FingerprintBackend instance or NULL on failure
*/
FingerprintBackend*
fingerprint_backend_new(FingerprintBackendVTable vtable,
                        FingerprintBackendCallbacks callbacks);

/**
* Free resources used by a fingerprint backend
* @param backend The backend to free
*/
void
fingerprint_backend_free(FingerprintBackend *backend);

/**
* Check if the backend hardware is available
* @param backend The backend instance
* @return TRUE if available, FALSE otherwise
*/
static inline gboolean
fingerprint_backend_is_available(FingerprintBackend *backend)
{
   g_return_val_if_fail(backend != NULL, FALSE);
   g_return_val_if_fail(backend->vtable.is_available != NULL, FALSE);
   return backend->vtable.is_available(backend);
}

/**
* Set up the default configuration for the backend
* @param backend The backend instance
* @return TRUE on success, FALSE on failure
*/
static inline gboolean
fingerprint_backend_setup_default(FingerprintBackend *backend)
{
   g_return_val_if_fail(backend != NULL, FALSE);
   g_return_val_if_fail(backend->vtable.setup_default != NULL, FALSE);
   return backend->vtable.setup_default(backend);
}

/**
* Start fingerprint enrollment process
* @param backend The backend instance
* @param password Password for secure storage
* @param timeout Timeout in seconds for the operation
* @return TRUE on successful start, FALSE on failure
*/
static inline gboolean
fingerprint_backend_perform_enrollment(FingerprintBackend *backend,
                                       const gchar *password,
                                       guint32 timeout)
{
   g_return_val_if_fail(backend != NULL, FALSE);
   g_return_val_if_fail(backend->vtable.perform_enrollment != NULL, FALSE);
   return backend->vtable.perform_enrollment(backend, password, timeout);
}

/**
* Start fingerprint authentication process
* @param backend The backend instance
* @return TRUE on successful start, FALSE on failure
*/
static inline gboolean
fingerprint_backend_perform_authentication(FingerprintBackend *backend)
{
   g_return_val_if_fail(backend != NULL, FALSE);
   g_return_val_if_fail(backend->vtable.perform_authentication != NULL, FALSE);
   return backend->vtable.perform_authentication(backend);
}

/**
* Cancel current fingerprint operation
* @param backend The backend instance
* @return TRUE on successful cancel, FALSE on failure
*/
static inline gboolean
fingerprint_backend_cancel_operation(FingerprintBackend *backend)
{
   g_return_val_if_fail(backend != NULL, FALSE);
   g_return_val_if_fail(backend->vtable.cancel_operation != NULL, FALSE);
   return backend->vtable.cancel_operation(backend);
}

/**
* Remove an enrolled fingerprint
* @param backend The backend instance
* @param finger_id ID of fingerprint to remove
* @return TRUE on success, FALSE on failure
*/
static inline gboolean
fingerprint_backend_remove_fingerprint(FingerprintBackend *backend, guint32 finger_id)
{
   g_return_val_if_fail(backend != NULL, FALSE);
   g_return_val_if_fail(backend->vtable.remove_fingerprint != NULL, FALSE);
   return backend->vtable.remove_fingerprint(backend, finger_id);
}

/**
* Clean up backend resources
* @param backend The backend instance
*/
static inline void
fingerprint_backend_cleanup(FingerprintBackend *backend)
{
   g_return_if_fail(backend != NULL);
   g_return_if_fail(backend->vtable.cleanup != NULL);
   backend->vtable.cleanup(backend);
}

#endif // FINGERPRINT_BACKEND_H
