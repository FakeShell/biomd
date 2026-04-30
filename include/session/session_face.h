/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef SESSION_FACE_H
#define SESSION_FACE_H

#include <gio/gio.h>

typedef struct _SessionFace SessionFace;

typedef void (*SessionFaceSuccessCb)(gpointer user_data);

/**
 * Create a face session helper.
 *
 * @param system_bus A system-bus connection
 * @param success_cb Called when recognition succeeds
 * @param user_data Passed to callbacks
 * @return A new SessionFace instance or NULL on failure
 */
SessionFace *
session_face_new(GDBusConnection *system_bus,
                 SessionFaceSuccessCb success_cb,
                 gpointer user_data);

/**
 * Free a face helper.
 * @param face Face helper
 */
void
session_face_free(SessionFace *face);

/**
 * Check if face module is usable.
 * @param face Face helper
 * @return TRUE if available, FALSE otherwise
 */
gboolean
session_face_is_available(SessionFace *face);

/**
 * Check if a face is enrolled.
 * @param face Face helper
 * @return TRUE if enrolled, FALSE otherwise
 */
gboolean
session_face_is_enrolled(SessionFace *face);

/**
 * Start face recognition.
 * @param face Face helper
 * @return TRUE if started successfully, FALSE otherwise
 */
gboolean
session_face_start(SessionFace *face);

/**
 * Stop face recognition.
 * @param face Face helper
 */
void
session_face_stop(SessionFace *face);

/**
 * Set whether the face helper should hold/retry the recognition agent.
 * @param face Face helper
 * @param lock_relevant TRUE when screen is off or locked, FALSE when screen is on and unlocked
 */
void
session_face_set_lock_relevant(SessionFace *face,
                               gboolean lock_relevant);

#endif /* SESSION_FACE_H */
