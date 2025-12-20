/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FACE_BACKEND_H
#define FACE_BACKEND_H

#include <glib.h>
#include "biomd_enums.h"

typedef struct _FaceBackend FaceBackend;

typedef struct {
    /**
     * Called when enrollment state changes (backend-specific ENROLLMENT_* numeric value)
     *
     * @param user_data User-provided data pointer
     * @param state EnrollmentState numeric value
     */
    void (*enrollment_state)(gpointer user_data, guint32 state);

    /**
     * Called when enrollment progress changes [0..100]
     *
     * @param user_data User-provided data pointer
     * @param progress Enrollment progress percentage
     */
    void (*enrollment_progress)(gpointer user_data, gint32 progress);

    /**
     * Called when recognition state changes (backend-specific RECOGNITION_* numeric value)
     *
     * @param user_data User-provided data pointer
     * @param state RecognitionState numeric value
     */
    void (*recognition_state)(gpointer user_data, guint32 state);

    /**
     * Called when a backend error occurs
     *
     * @param user_data User-provided data pointer
     * @param error_code Backend-specific error code
     */
    void (*error)(gpointer user_data, guint32 error_code);

    /** User data passed to callbacks */
    gpointer user_data;
} FaceBackendCallbacks;

/**
 * Virtual function table for face backends.
 * Each backend must implement these functions.
 */
typedef struct {
    /**
     * Check if the backend implementation is available.
     *
     * @param self The backend instance
     * @return TRUE if available, FALSE otherwise
     */
    gboolean (*is_available)(FaceBackend *self);

    /**
     * Set up the default configuration for the backend.
     *
     * @param self The backend instance
     * @return TRUE on success, FALSE on failure
     */
    gboolean (*setup_default)(FaceBackend *self);

    /**
     * Start face enrollment process.
     *
     * @param self The backend instance
     * @return TRUE on successful start, FALSE on failure
     */
    gboolean (*start_enrollment)(FaceBackend *self);

    /**
     * Start face recognition process.
     *
     * @param self The backend instance
     * @return TRUE on successful start, FALSE on failure
     */
    gboolean (*start_recognition)(FaceBackend *self);

    /**
     * Cancel current face operation.
     *
     * @param self The backend instance
     * @return TRUE on successful cancel, FALSE on failure
     */
    gboolean (*cancel_operation)(FaceBackend *self);

    /**
     * Submit a frame to the backend using a file descriptor (memfd).
     *
     * @param self The backend instance
     * @param fd Readable file descriptor containing frame bytes
     * @param width Frame width
     * @param height Frame height
     * @param channels Frame channels (e.g. 3)
     * @param format Frame format enum (FACE_FRAME_FORMAT_*)
     *
     * @return TRUE on success, FALSE on failure
     */
    gboolean (*submit_frame)(FaceBackend *self,
                             gint fd,
                             gint width,
                             gint height,
                             gint channels,
                             guint32 format);

    /**
     * Check if a face is enrolled.
     *
     * @param self The backend instance
     * @return TRUE if enrolled, FALSE otherwise
     */
    gboolean (*is_enrolled)(FaceBackend *self);

    /**
     * Remove persistent face data (unenroll).
     *
     * @param self The backend instance
     * @return TRUE if data removed, FALSE otherwise
     */
    gboolean (*remove_face_data)(FaceBackend *self);

    /**
     * Clean up backend resources.
     *
     * @param self The backend instance
     */
    void (*cleanup)(FaceBackend *self);
} FaceBackendVTable;

struct _FaceBackend {
    FaceBackendVTable vtable;          /**< Virtual function table */
    FaceBackendCallbacks callbacks;    /**< Callback functions */
    gpointer impl_data;                /**< Implementation-specific data */
};

/**
 * Create a new face backend.
 *
 * @param vtable Virtual function table for the backend
 * @param callbacks Callback functions to be invoked by the backend
 * @return A new FaceBackend instance or NULL on failure
 */
FaceBackend *
face_backend_new(FaceBackendVTable vtable,
                 FaceBackendCallbacks callbacks);

/**
 * Free resources used by a face backend.
 *
 * @param backend The backend to free
 */
void
face_backend_free(FaceBackend *backend);

/**
 * Check if the backend implementation is available.
 *
 * @param backend The backend instance
 * @return TRUE if available, FALSE otherwise
 */
static inline gboolean
face_backend_is_available(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.is_available != NULL, FALSE);
    return backend->vtable.is_available(backend);
}

/**
 * Set up the default configuration for the backend.
 *
 * @param backend The backend instance
 * @return TRUE on success, FALSE on failure
 */
static inline gboolean
face_backend_setup_default(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.setup_default != NULL, FALSE);
    return backend->vtable.setup_default(backend);
}

/**
 * Start face enrollment process.
 *
 * @param backend The backend instance
 * @return TRUE on successful start, FALSE on failure
 */
static inline gboolean
face_backend_start_enrollment(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.start_enrollment != NULL, FALSE);
    return backend->vtable.start_enrollment(backend);
}

/**
 * Start face recognition process.
 *
 * @param backend The backend instance
 * @return TRUE on successful start, FALSE on failure
 */
static inline gboolean
face_backend_start_recognition(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.start_recognition != NULL, FALSE);
    return backend->vtable.start_recognition(backend);
}

/**
 * Cancel current face operation.
 *
 * @param backend The backend instance
 * @return TRUE on successful cancel, FALSE on failure
 */
static inline gboolean
face_backend_cancel_operation(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.cancel_operation != NULL, FALSE);
    return backend->vtable.cancel_operation(backend);
}

/**
 * Submit a frame to the backend using a file descriptor (memfd).
 *
 * @param backend The backend instance
 * @param fd Readable file descriptor containing frame bytes
 * @param width Frame width
 * @param height Frame height
 * @param channels Frame channels
 * @param format Frame format enum (FACE_FRAME_FORMAT_*)
 * @return TRUE on success, FALSE on failure
 */
static inline gboolean
face_backend_submit_frame(FaceBackend *backend,
                          gint fd,
                          gint width,
                          gint height,
                          gint channels,
                          guint32 format)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.submit_frame != NULL, FALSE);
    return backend->vtable.submit_frame(backend, fd, width, height, channels, format);
}

/**
 * Check if a face is enrolled.
 *
 * @param backend The backend instance
 * @return TRUE if enrolled, FALSE otherwise
 */
static inline gboolean
face_backend_is_enrolled(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    g_return_val_if_fail(backend->vtable.is_enrolled != NULL, FALSE);
    return backend->vtable.is_enrolled(backend);
}

/**
 * Remove persistent face data (unenroll).
 *
 * @param backend The backend instance
 * @return TRUE if removed, FALSE otherwise
 */
static inline gboolean
face_backend_remove_face_data(FaceBackend *backend)
{
    g_return_val_if_fail(backend != NULL, FALSE);
    if (!backend->vtable.remove_face_data)
        return FALSE;
    return backend->vtable.remove_face_data(backend);
}

/**
 * Clean up backend resources.
 *
 * @param backend The backend instance
 */
static inline void
face_backend_cleanup(FaceBackend *backend)
{
    g_return_if_fail(backend != NULL);
    g_return_if_fail(backend->vtable.cleanup != NULL);
    backend->vtable.cleanup(backend);
}

#endif // FACE_BACKEND_H
