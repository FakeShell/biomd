/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri
 */

#ifndef FACE_TENSORFLOW_FART_H
#define FACE_TENSORFLOW_FART_H

#include <glib.h>
#include "face_backend.h"

typedef struct _BiomFaceTensorflowFart BiomFaceTensorflowFart;

/**
 * Face backend operation mode
 */
typedef enum {
    TF_FART_MODE_NONE = 0,       /**< No operation in progress */
    TF_FART_MODE_ENROLL = 1,     /**< Face enrollment in progress */
    TF_FART_MODE_RECOGNIZE = 2   /**< Face recognition in progress */
} FaceTfFartMode;

/**
 * Initialize TensorFlow-backed FART backend.
 *
 * @param detection_model   Path to detection TFLite model
 * @param recognition_model Path to recognition TFLite model
 * @param anti_spoof_model  Optional path to anti-spoof TFLite model
 * @return New backend instance or NULL on failure
 */
BiomFaceTensorflowFart *
face_tensorflow_fart_init(const gchar *detection_model,
                          const gchar *recognition_model,
                          const gchar *anti_spoof_model);

/**
 * Destroy backend instance and free resources.
 *
 * @param self Backend instance
 */
void
face_tensorflow_fart_cleanup(BiomFaceTensorflowFart *self);

/**
 * Check backend availability.
 *
 * @param self Backend instance
 * @return TRUE if available, FALSE otherwise
 */
gboolean
face_tensorflow_fart_is_available(BiomFaceTensorflowFart *self);

/**
 * Perform default backend setup.
 *
 * @param self Backend instance
 * @return TRUE on success, FALSE on failure
 */
gboolean
face_tensorflow_fart_setup(BiomFaceTensorflowFart *self);

/**
 * Start enrollment mode.
 *
 * @param self Backend instance
 * @return TRUE on success, FALSE on failure
 */
gboolean
face_tensorflow_fart_start_enroll(BiomFaceTensorflowFart *self);

/**
 * Start recognition mode.
 *
 * @param self Backend instance
 * @return TRUE on success, FALSE on failure
 */
gboolean
face_tensorflow_fart_start_recognize(BiomFaceTensorflowFart *self);

/**
 * Cancel current operation.
 *
 * @param self Backend instance
 * @return TRUE on success, FALSE on failure
 */
gboolean
face_tensorflow_fart_cancel(BiomFaceTensorflowFart *self);

/**
 * Submit a video frame for processing.
 *
 * @param self      Backend instance
 * @param fd        memfd containing raw frame data
 * @param width     Frame width
 * @param height    Frame height
 * @param channels  Number of channels
 * @param format    Frame format enum (FACE_FRAME_FORMAT_*)
 * @param out_state Latest known backend state
 * @return TRUE if accepted, FALSE on error
 */
gboolean
face_tensorflow_fart_submit_frame(BiomFaceTensorflowFart *self,
                                  gint fd,
                                  gint width,
                                  gint height,
                                  gint channels,
                                  guint32 format,
                                  guint32 *out_state);

/**
 * Check if a face is enrolled.
 *
 * @param self Backend instance
 * @return TRUE if enrolled, FALSE otherwise
 */
gboolean
face_tensorflow_fart_is_enrolled(BiomFaceTensorflowFart *self);

/**
 * Get current backend mode.
 *
 * @param self Backend instance
 * @return 0 = none, 1 = enroll, 2 = recognize
 */
guint32
face_tensorflow_fart_get_mode(BiomFaceTensorflowFart *self);

/**
 * Get last known enrollment progress [0..100].
 *
 * This is updated when enrollment frames are processed.
 *
 * @param self Backend instance
 * @return progress percentage [0..100]
 */
guint32
face_tensorflow_fart_get_enrollment_progress(BiomFaceTensorflowFart *self);

/**
 * Remove face data (enrolled_face.json) from the persistent directory.
 *
 * This deletes /var/lib/biomd/enrolled_face.json and recreates the libfart handle
 *
 * @param self Backend instance
 * @return TRUE if data was removed (or did not exist) and backend is usable, FALSE otherwise
 */
gboolean
face_tensorflow_fart_remove_face_data(BiomFaceTensorflowFart *self);

#endif /* FACE_TENSORFLOW_FART_H */
