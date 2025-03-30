/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "fingerprint_hidl_backend.h"
#include "fingerprint_binder_hidl.h"
#include <glib.h>

typedef struct {
    BiomFingerprintHidl *hidl;
    GDBusConnection *connection;
} FingerprintHidlData;

static void
hidl_enroll_result_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.enroll_result)
        backend->callbacks.enroll_result(backend->callbacks.user_data, finger_id, group_id, remaining);
}

static void
hidl_acquired_cb(gpointer user_data, FingerprintAcquiredInfo acquired_info, guint32 vendor_code)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.acquired)
        backend->callbacks.acquired(backend->callbacks.user_data, (guint32)acquired_info, vendor_code);
}

static void
hidl_authenticated_cb(gpointer user_data, guint32 finger_id, guint32 group_id)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.authenticated)
        backend->callbacks.authenticated(backend->callbacks.user_data, finger_id, group_id);
}

static void
hidl_error_cb(gpointer user_data, FingerprintError error_code, guint32 vendor_code)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.error)
        backend->callbacks.error(backend->callbacks.user_data, (guint32)error_code, vendor_code);
}

static void
hidl_removed_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.removed)
        backend->callbacks.removed(backend->callbacks.user_data, finger_id, group_id, remaining);
}

static void
hidl_enumerate_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.enumerate)
        backend->callbacks.enumerate(backend->callbacks.user_data, finger_id, group_id, remaining);
}

static gboolean
hidl_is_available(FingerprintBackend *self)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    return data && data->hidl && fingerprint_hidl_is_available(data->hidl);
}

static gboolean
hidl_setup_default(FingerprintBackend *self)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    return data && data->hidl && fingerprint_hidl_setup(data->hidl);
}

static gboolean
hidl_perform_enrollment(FingerprintBackend *self, const gchar *password, guint32 timeout)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    return data && data->hidl && fingerprint_hidl_perform_enrollment(data->hidl, password, timeout);
}

static gboolean
hidl_perform_authentication(FingerprintBackend *self)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    return data && data->hidl && fingerprint_hidl_perform_authentication(data->hidl);
}

static gboolean
hidl_cancel_operation(FingerprintBackend *self)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    return data && data->hidl && fingerprint_hidl_cancel_operation(data->hidl);
}

static gboolean
hidl_remove_fingerprint(FingerprintBackend *self, guint32 finger_id)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    return data && data->hidl && fingerprint_hidl_remove_fingerprint(data->hidl, finger_id);
}

static void
hidl_cleanup(FingerprintBackend *self)
{
    FingerprintHidlData *data = (FingerprintHidlData *)self->impl_data;
    if (data) {
        if (data->hidl)
            fingerprint_hidl_cleanup(data->hidl);
        g_free(data);
        self->impl_data = NULL;
    }
}

FingerprintBackend*
fingerprint_hidl_backend_new(FingerprintBackendCallbacks callbacks)
{
    FingerprintBackendVTable vtable = {
        .is_available = hidl_is_available,
        .setup_default = hidl_setup_default,
        .perform_enrollment = hidl_perform_enrollment,
        .perform_authentication = hidl_perform_authentication,
        .cancel_operation = hidl_cancel_operation,
        .remove_fingerprint = hidl_remove_fingerprint,
        .cleanup = hidl_cleanup
    };

    FingerprintBackend *backend = fingerprint_backend_new(vtable, callbacks);
    if (!backend)
        return NULL;

    FingerprintHidlData *data = g_new0(FingerprintHidlData, 1);
    backend->impl_data = data;

    FingerprintHidlCallbacks hidl_callbacks = {
        .enroll_result = hidl_enroll_result_cb,
        .acquired = hidl_acquired_cb,
        .authenticated = hidl_authenticated_cb,
        .error = hidl_error_cb,
        .removed = hidl_removed_cb,
        .enumerate = hidl_enumerate_cb
    };

    data->hidl = fingerprint_hidl_init(&hidl_callbacks, backend);
    if (!data->hidl) {
        g_warning("Failed to initialize HIDL fingerprint backend");
        fingerprint_backend_free(backend);
        return NULL;
    }

    return backend;
}
