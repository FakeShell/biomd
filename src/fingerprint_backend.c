/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "fingerprint_backend.h"

FingerprintBackend*
fingerprint_backend_new(FingerprintBackendVTable vtable,
                        FingerprintBackendCallbacks callbacks)
{
    FingerprintBackend *backend = g_new0(FingerprintBackend, 1);
    backend->vtable = vtable;
    backend->callbacks = callbacks;
    return backend;
}

void
fingerprint_backend_free(FingerprintBackend *backend)
{
    if (backend) {
        fingerprint_backend_cleanup(backend);
        g_free(backend);
    }
}
