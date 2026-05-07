/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FACE_FART_BACKEND_H
#define FACE_FART_BACKEND_H

#include <glib.h>
#include <fart/fart_enums.h>
#include "face_backend.h"

/**
 * Create a new FART backend instance with the specified callbacks.
 *
 * This backend is of type "software". Internally it uses the TensorFlow-backed libfart.
 *
 * @param callbacks Callback functions to be invoked by the backend
 * @return A new FaceBackend instance or NULL if creation failed
 */
FaceBackend *
face_fart_backend_new(FaceBackendCallbacks callbacks);

#endif // FACE_FART_BACKEND_H
