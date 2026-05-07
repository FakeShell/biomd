/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FACE_H
#define FACE_H

#include <glib.h>
#include <gio/gio.h>
#include "biomd_enums.h"

/**
 * Initialize the face subsystem
 * @param connection D-Bus connection to use for communication
 */
void
face_init(GDBusConnection *connection);

/**
 * Clean up resources used by the face subsystem
 * @param connection D-Bus connection used for communication
 */
void
face_cleanup(GDBusConnection *connection);

/**
 * Register the face object on D-Bus
 * @param connection D-Bus connection to register with
 * @param error Error return location
 * @return ID of the registered object or 0 on failure
 */
guint
face_register(GDBusConnection *connection, GError **error);

/**
 * Get the current biometric state
 * @return Current state of the face subsystem
 */
BiometricState
face_get_state(void);

/**
 * Check if a face is enrolled
 * @return TRUE if enrolled, FALSE otherwise
 */
gboolean
face_get_enrolled(void);

/**
 * Get the implementation type
 * @return Implementation type of face subsystem
 */
FaceImplementationType
face_get_implementation_type(void);

#endif // FACE_H
