/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "face_fart_backend.h"
#include "face_tensorflow_fart.h"

#include <glib.h>

typedef struct {
    BiomFaceTensorflowFart *tf;
    gint32 last_progress_emitted;
} FaceFartData;

static gboolean
fart_is_available(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    return data && data->tf && face_tensorflow_fart_is_available(data->tf);
}

static gboolean
fart_setup_default(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    return data && data->tf && face_tensorflow_fart_setup(data->tf);
}

static gboolean
fart_start_enrollment(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    if (!data || !data->tf)
        return FALSE;

    data->last_progress_emitted = -1;
    return face_tensorflow_fart_start_enroll(data->tf);
}

static gboolean
fart_start_recognition(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    return data && data->tf && face_tensorflow_fart_start_recognize(data->tf);
}

static gboolean
fart_cancel_operation(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    return data && data->tf && face_tensorflow_fart_cancel(data->tf);
}

static gboolean
fart_submit_frame(FaceBackend *self,
                  gint fd,
                  gint width,
                  gint height,
                  gint channels,
                  guint32 format)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    guint32 state = 0;
    gboolean ok;

    if (!data || !data->tf)
        return FALSE;

    ok = face_tensorflow_fart_submit_frame(data->tf, fd, width, height, channels, format, &state);
    if (!ok)
        return FALSE;

    const FaceTfFartMode mode = (FaceTfFartMode)face_tensorflow_fart_get_mode(data->tf);
    if (mode == TF_FART_MODE_ENROLL) {
        if (self->callbacks.enrollment_progress) {
            gint32 p = face_tensorflow_fart_get_enrollment_progress(data->tf);
            if (p != data->last_progress_emitted) {
                data->last_progress_emitted = p;
                self->callbacks.enrollment_progress(self->callbacks.user_data, p);
            }
        }

        if (self->callbacks.enrollment_state)
            self->callbacks.enrollment_state(self->callbacks.user_data, state);
    } else if (mode == TF_FART_MODE_RECOGNIZE) {
        if (self->callbacks.recognition_state)
            self->callbacks.recognition_state(self->callbacks.user_data, state);
    }

    return TRUE;
}

static gboolean
fart_is_enrolled(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    return data && data->tf && face_tensorflow_fart_is_enrolled(data->tf);
}

static gboolean
fart_remove_face_data(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    if (!data || !data->tf)
        return FALSE;

    data->last_progress_emitted = -1;
    return face_tensorflow_fart_remove_face_data(data->tf);
}

static void
fart_cleanup(FaceBackend *self)
{
    FaceFartData *data = (FaceFartData *)self->impl_data;
    if (data) {
        if (data->tf)
            face_tensorflow_fart_cleanup(data->tf);
        g_free(data);
        self->impl_data = NULL;
    }
}

FaceBackend *
face_fart_backend_new(FaceBackendCallbacks callbacks)
{
    FaceBackendVTable vtable = {
        .is_available = fart_is_available,
        .setup_default = fart_setup_default,
        .start_enrollment = fart_start_enrollment,
        .start_recognition = fart_start_recognition,
        .cancel_operation = fart_cancel_operation,
        .submit_frame = fart_submit_frame,
        .is_enrolled = fart_is_enrolled,
        .remove_face_data = fart_remove_face_data,
        .cleanup = fart_cleanup
    };

    FaceBackend *backend = face_backend_new(vtable, callbacks);
    if (!backend)
        return NULL;

    FaceFartData *data = g_new0(FaceFartData, 1);
    backend->impl_data = data;
    data->last_progress_emitted = -1;

    data->tf = face_tensorflow_fart_init("/usr/share/fart/models/detect-class1.tflite",
                                         "/usr/share/fart/models/mobile_face_net.tflite");

    if (!data->tf) {
        g_warning("Failed to initialize TensorFlow FART backend");
        face_backend_free(backend);
        return NULL;
    }

    return backend;
}
