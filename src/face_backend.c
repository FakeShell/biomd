/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "face_backend.h"

FaceBackend *
face_backend_new(FaceBackendVTable vtable,
                 FaceBackendCallbacks callbacks)
{
    FaceBackend *backend = g_new0(FaceBackend, 1);
    backend->vtable = vtable;
    backend->callbacks = callbacks;
    return backend;
}

void
face_backend_free(FaceBackend *backend)
{
    if (backend) {
        face_backend_cleanup(backend);
        g_free(backend);
    }
}
