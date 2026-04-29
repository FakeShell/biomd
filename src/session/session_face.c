/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#define _GNU_SOURCE

#include "session_face.h"
#include "biomd_enums.h"

#include <gst/gst.h>

#include <linux/memfd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <fart/fart_enums.h>

#define BIOMD_SERVICE "io.FuriOS.Biomd"
#define FACE_PATH "/io/FuriOS/Biomd/Face"
#define FACE_IFACE "io.FuriOS.Biomd.Face"
#define FACE_AGENT_IFACE "io.FuriOS.Biomd.Face.Agent"

#define SUBMIT_INTERVAL_MS 200 /* 5 fps */

typedef struct {
    GDBusConnection *bus;
    gchar *agent_path;
} SubmitCallCtx;

struct _SessionFace {
    GDBusConnection *bus;

    gchar *agent_path;

    gboolean available_cached;
    gboolean available_checked;

    gboolean face_enrolled;
    gboolean has_access;
    gboolean recognition_started;
    gboolean in_progress;

    gboolean want_start;

    guint sig_agent_id;
    guint sig_manager_id;

    GstElement *pipeline;
    GstElement *appsink;

    gint64 last_submit_us;

    SessionFaceSuccessCb success_cb;
    gpointer user_data;
};

static const char *
recognition_state_to_string(guint32 state_u32)
{
    RecognitionState state = (RecognitionState)state_u32;

    switch (state) {
        case RECOGNITION_FAIL:
            return "RECOGNITION_FAIL";
        case RECOGNITION_NO_FACE:
            return "RECOGNITION_NO_FACE";
        case RECOGNITION_MULTIPLE_FACES:
            return "RECOGNITION_MULTIPLE_FACES";
        case RECOGNITION_NOT_ENROLLED:
            return "RECOGNITION_NOT_ENROLLED";
        case RECOGNITION_RECOGNIZED:
            return "RECOGNITION_RECOGNIZED";
        case RECOGNITION_NOT_RECOGNIZED:
            return "RECOGNITION_NOT_RECOGNIZED";
        default:
            return "RECOGNITION_UNKNOWN";
    }
}

static int
create_memfd(const char *name)
{
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, (unsigned int)MFD_CLOEXEC);
#else
    (void)name;
    errno = ENOSYS;
    return -1;
#endif
}

static gboolean
face_get_prop_bool(SessionFace *face, const gchar *prop)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GVariant) v = NULL;

    if (!face || !face->bus || !prop)
        return FALSE;

    ret = g_dbus_connection_call_sync(
        face->bus,
        BIOMD_SERVICE,
        FACE_PATH,
        "org.freedesktop.DBus.Properties",
        "Get",
        g_variant_new("(ss)", FACE_IFACE, prop),
        G_VARIANT_TYPE("(v)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Face Get(%s) failed: %s", prop, error->message);
        return FALSE;
    }

    g_variant_get(ret, "(v)", &v);

    if (!g_variant_is_of_type(v, G_VARIANT_TYPE_BOOLEAN))
        return FALSE;

    return g_variant_get_boolean(v);
}

static gint
face_get_prop_int(SessionFace *face, const gchar *prop)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GVariant) v = NULL;

    if (!face || !face->bus || !prop)
        return TYPE_UNKNOWN;

    ret = g_dbus_connection_call_sync(
        face->bus,
        BIOMD_SERVICE,
        FACE_PATH,
        "org.freedesktop.DBus.Properties",
        "Get",
        g_variant_new("(ss)", FACE_IFACE, prop),
        G_VARIANT_TYPE("(v)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Face Get(%s) failed: %s", prop, error->message);
        return TYPE_UNKNOWN;
    }

    g_variant_get(ret, "(v)", &v);

    if (g_variant_is_of_type(v, G_VARIANT_TYPE_INT32))
        return (gint)g_variant_get_int32(v);

    if (g_variant_is_of_type(v, G_VARIANT_TYPE_UINT32))
        return (gint)g_variant_get_uint32(v);

    return TYPE_UNKNOWN;
}

static gboolean
agent_get_prop_bool(SessionFace *face, const gchar *prop)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GVariant) v = NULL;

    if (!face || !face->bus || !face->agent_path || !prop)
        return FALSE;

    ret = g_dbus_connection_call_sync(
        face->bus,
        BIOMD_SERVICE,
        face->agent_path,
        "org.freedesktop.DBus.Properties",
        "Get",
        g_variant_new("(ss)", FACE_AGENT_IFACE, prop),
        G_VARIANT_TYPE("(v)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Face Agent Get(%s) failed: %s", prop, error->message);
        return FALSE;
    }

    g_variant_get(ret, "(v)", &v);

    if (!g_variant_is_of_type(v, G_VARIANT_TYPE_BOOLEAN))
        return FALSE;

    return g_variant_get_boolean(v);
}

static void
submit_frame_done_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    SubmitCallCtx *ctx = user_data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    gboolean accepted = FALSE;

    (void)source_object;

    if (!ctx)
        return;

    ret = g_dbus_connection_call_with_unix_fd_list_finish(
        ctx->bus,
        NULL,
        res,
        &error
    );

    if (error) {
        g_debug("Face SubmitFrame async failed: %s", error->message);
        g_free(ctx->agent_path);
        g_free(ctx);
        return;
    }

    if (!ret) {
        g_debug("Face SubmitFrame async returned NULL");
        g_free(ctx->agent_path);
        g_free(ctx);
        return;
    }

    g_variant_get(ret, "(b)", &accepted);

    if (accepted)
        g_debug("Face SubmitFrame accepted");
    else
        g_debug("Face SubmitFrame rejected");

    g_free(ctx->agent_path);
    g_free(ctx);
}

static void
submit_frame_async(SessionFace *face, int fd, int width, int height, int channels, guint32 format)
{
    GUnixFDList *fd_list = NULL;
    g_autoptr(GError) error = NULL;
    int idx = -1;
    GVariant *params = NULL;
    SubmitCallCtx *ctx = NULL;

    if (!face || !face->bus || !face->agent_path)
        return;

    if (!face->want_start || !face->in_progress)
        return;

    if (!face->has_access)
        return;

    if (!face->recognition_started)
        return;

    fd_list = g_unix_fd_list_new();
    idx = g_unix_fd_list_append(fd_list, fd, &error);

    if (idx < 0) {
        if (error)
            g_debug("g_unix_fd_list_append failed: %s", error->message);
        g_object_unref(fd_list);
        return;
    }

    params = g_variant_new("(hiiiu)", idx, width, height, channels, format);

    ctx = g_new0(SubmitCallCtx, 1);
    ctx->bus = face->bus;
    ctx->agent_path = g_strdup(face->agent_path);

    g_dbus_connection_call_with_unix_fd_list(
        face->bus,
        BIOMD_SERVICE,
        face->agent_path,
        FACE_AGENT_IFACE,
        "SubmitFrame",
        params,
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        fd_list,
        NULL,
        submit_frame_done_cb,
        ctx
    );

    g_object_unref(fd_list);
}

static GstFlowReturn
on_new_sample(GstElement *sink, gpointer user_data)
{
    SessionFace *face = user_data;
    GstSample *sample = NULL;
    GstCaps *caps = NULL;
    GstStructure *st = NULL;
    GstBuffer *buffer = NULL;
    GstMapInfo map;
    gint width = 0;
    gint height = 0;
    gsize expected = 0;
    int memfd = -1;
    ssize_t w = 0;

    if (!face)
        return GST_FLOW_OK;

    if (!face->want_start || !face->in_progress)
        return GST_FLOW_OK;

    if (!face->has_access)
        return GST_FLOW_OK;

    if (!face->recognition_started)
        return GST_FLOW_OK;

    const gint64 now_us = g_get_monotonic_time();
    if (face->last_submit_us != 0) {
        const gint64 min_delta_us = (gint64)SUBMIT_INTERVAL_MS * 1000;
        if ((now_us - face->last_submit_us) < min_delta_us)
            return GST_FLOW_OK;
    }
    face->last_submit_us = now_us;

    g_signal_emit_by_name(sink, "pull-sample", &sample);
    if (!sample)
        return GST_FLOW_OK;

    caps = gst_sample_get_caps(sample);
    if (!caps) {
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    st = gst_caps_get_structure(caps, 0);
    if (!st) {
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    gst_structure_get_int(st, "width", &width);
    gst_structure_get_int(st, "height", &height);

    buffer = gst_sample_get_buffer(sample);
    if (!buffer) {
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    if (!gst_buffer_map(buffer, &map, GST_MAP_READ)) {
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    expected = (gsize)width * (gsize)height * 3;
    if (width <= 0 || height <= 0 || map.size < expected) {
        gst_buffer_unmap(buffer, &map);
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    memfd = create_memfd("face-frame");
    if (memfd < 0) {
        gst_buffer_unmap(buffer, &map);
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    if (ftruncate(memfd, (off_t)expected) != 0) {
        close(memfd);
        gst_buffer_unmap(buffer, &map);
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    w = write(memfd, map.data, expected);
    if (w < 0 || (gsize)w != expected) {
        close(memfd);
        gst_buffer_unmap(buffer, &map);
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    if (lseek(memfd, 0, SEEK_SET) < 0) {
        close(memfd);
        gst_buffer_unmap(buffer, &map);
        gst_sample_unref(sample);
        return GST_FLOW_OK;
    }

    submit_frame_async(face, memfd, width, height, 3, (guint32)FACE_FRAME_FORMAT_BGR);

    close(memfd);
    gst_buffer_unmap(buffer, &map);
    gst_sample_unref(sample);

    return GST_FLOW_OK;
}

static gboolean
setup_pipeline(SessionFace *face)
{
    g_autoptr(GError) error = NULL;
    const char *pipeline_str =
        "droidcamsrc camera_device=1 mode=2 ! queue max-size-buffers=1 leaky=downstream ! "
        "video/x-raw, width=640, height=480 ! videoconvert ! "
        "videoflip video-direction=auto ! video/x-raw, format=BGR ! "
        "appsink name=appsink max-buffers=1 drop=true emit-signals=true sync=false";

    if (!face)
        return FALSE;

    if (face->pipeline)
        return TRUE;

    face->pipeline = gst_parse_launch(pipeline_str, &error);
    if (error || !face->pipeline) {
        if (error)
            g_debug("Face gst_parse_launch failed: %s", error->message);
        return FALSE;
    }

    face->appsink = gst_bin_get_by_name(GST_BIN(face->pipeline), "appsink");
    if (!face->appsink) {
        g_debug("Face: failed to get appsink from pipeline");
        gst_object_unref(face->pipeline);
        face->pipeline = NULL;
        return FALSE;
    }

    g_signal_connect(face->appsink, "new-sample", G_CALLBACK(on_new_sample), face);

    gst_element_set_state(face->pipeline, GST_STATE_PLAYING);
    return TRUE;
}

static void
stop_pipeline(SessionFace *face)
{
    if (!face)
        return;

    if (face->pipeline)
        gst_element_set_state(face->pipeline, GST_STATE_NULL);

    if (face->appsink) {
        gst_object_unref(face->appsink);
        face->appsink = NULL;
    }

    if (face->pipeline) {
        gst_object_unref(face->pipeline);
        face->pipeline = NULL;
    }
}

static gboolean
create_agent(SessionFace *face)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    const gchar *tmp_path = NULL;

    if (!face || !face->bus)
        return FALSE;

    if (face->agent_path)
        return TRUE;

    ret = g_dbus_connection_call_sync(
        face->bus,
        BIOMD_SERVICE,
        FACE_PATH,
        FACE_IFACE,
        "CreateAgent",
        NULL,
        G_VARIANT_TYPE("(o)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Face CreateAgent failed: %s", error->message);
        return FALSE;
    }

    g_variant_get(ret, "(&o)", &tmp_path);
    face->agent_path = g_strdup(tmp_path);
    return TRUE;
}

static gboolean
register_recognition(SessionFace *face)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    gboolean ok = FALSE;

    if (!face || !face->bus || !face->agent_path)
        return FALSE;

    ret = g_dbus_connection_call_sync(
        face->bus,
        BIOMD_SERVICE,
        FACE_PATH,
        FACE_IFACE,
        "RegisterRecognitionAgent",
        g_variant_new("(o)", face->agent_path),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Face RegisterRecognitionAgent failed: %s", error->message);
        return FALSE;
    }

    g_variant_get(ret, "(b)", &ok);
    return ok;
}

static void
agent_cancel(SessionFace *face)
{
    if (!face || !face->bus || !face->agent_path)
        return;

    g_dbus_connection_call(
        face->bus,
        BIOMD_SERVICE,
        face->agent_path,
        FACE_AGENT_IFACE,
        "Cancel",
        NULL,
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        NULL,
        NULL
    );
}

static gboolean
agent_start_recognition(SessionFace *face)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    gboolean ok = FALSE;

    if (!face || !face->bus || !face->agent_path)
        return FALSE;

    ret = g_dbus_connection_call_sync(
        face->bus,
        BIOMD_SERVICE,
        face->agent_path,
        FACE_AGENT_IFACE,
        "StartRecognition",
        NULL,
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Face Agent StartRecognition failed: %s", error->message);
        return FALSE;
    }

    g_variant_get(ret, "(b)", &ok);
    g_debug("Face StartRecognition returned %s", ok ? "true" : "false");
    face->recognition_started = ok;
    return ok;
}

static gboolean
try_start_if_ready(SessionFace *face)
{
    gboolean ok = FALSE;

    if (!face)
        return FALSE;

    if (!face->want_start)
        return FALSE;

    if (!session_face_is_available(face))
        return FALSE;

    if (!session_face_is_enrolled(face))
        return FALSE;

    if (!face->has_access)
        return FALSE;

    if (face->in_progress)
        return TRUE;

    g_debug("Face recognition started");
    ok = agent_start_recognition(face);
    if (!ok) {
        face->recognition_started = FALSE;
        return FALSE;
    }

    ok = setup_pipeline(face);
    if (!ok) {
        agent_cancel(face);
        face->recognition_started = FALSE;
        return FALSE;
    }

    face->in_progress = TRUE;
    g_debug("try_start_if_ready: recognition and pipeline started");
    return TRUE;
}

static void
on_manager_signal(GDBusConnection *c,
                  const gchar *sender_name,
                  const gchar *object_path,
                  const gchar *interface_name,
                  const gchar *signal_name,
                  GVariant *parameters,
                  gpointer user_data)
{
    SessionFace *face = user_data;
    gboolean enrolled = FALSE;

    (void)c;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;

    if (!face)
        return;

    if (g_strcmp0(signal_name, "FaceEnrolledChanged") != 0)
        return;

    g_variant_get(parameters, "(b)", &enrolled);
    face->face_enrolled = enrolled;

    if (face->want_start) {
        face->has_access = agent_get_prop_bool(face, "HasAccess");
        try_start_if_ready(face);
    }
}

static void
on_agent_signal(GDBusConnection *c,
                const gchar *sender_name,
                const gchar *object_path,
                const gchar *interface_name,
                const gchar *signal_name,
                GVariant *parameters,
                gpointer user_data)
{
    SessionFace *face = user_data;
    guint32 state = 0;
    gboolean has_access = FALSE;

    (void)c;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;

    if (!face)
        return;

    if (g_strcmp0(signal_name, "AccessChanged") == 0) {
        g_variant_get(parameters, "(b)", &has_access);
        face->has_access = has_access;

        if (face->has_access) {
            g_debug("Face access granted");
            if (face->want_start)
                try_start_if_ready(face);
        } else {
            g_debug("Face access revoked");
            stop_pipeline(face);
            face->in_progress = FALSE;
            face->recognition_started = FALSE;
            face->last_submit_us = 0;
        }

        return;
    }

    if (g_strcmp0(signal_name, "RecognitionStateChanged") == 0) {
        g_variant_get(parameters, "(u)", &state);
        g_debug("Face RecognitionStateChanged: %u (%s)", state, recognition_state_to_string(state));

        switch ((RecognitionState)state) {
            case RECOGNITION_RECOGNIZED:
                if (face->success_cb)
                    face->success_cb(face->user_data);

                stop_pipeline(face);
                face->in_progress = FALSE;
                face->recognition_started = FALSE;
                face->last_submit_us = 0;

                if (face->has_access)
                    agent_cancel(face);

                face->want_start = FALSE;
                break;

            default:
                break;
        }

        return;
    }
}

SessionFace *
session_face_new(GDBusConnection *system_bus,
                 SessionFaceSuccessCb success_cb,
                 gpointer user_data)
{
    SessionFace *face = NULL;

    if (!system_bus)
        return NULL;

    gst_init(NULL, NULL);

    face = g_new0(SessionFace, 1);
    face->bus = system_bus;
    face->success_cb = success_cb;
    face->user_data = user_data;

    face->sig_agent_id = 0;
    face->sig_manager_id = 0;

    face->available_checked = FALSE;
    face->available_cached = FALSE;

    face->agent_path = NULL;
    face->pipeline = NULL;
    face->appsink = NULL;
    face->last_submit_us = 0;

    face->face_enrolled = FALSE;
    face->has_access = FALSE;
    face->recognition_started = FALSE;
    face->in_progress = FALSE;
    face->want_start = FALSE;

    face->sig_manager_id = g_dbus_connection_signal_subscribe(
        face->bus,
        BIOMD_SERVICE,
        FACE_IFACE,
        "FaceEnrolledChanged",
        FACE_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_manager_signal,
        face,
        NULL
    );

    face->face_enrolled = session_face_is_enrolled(face);

    if (create_agent(face)) {
        face->sig_agent_id = g_dbus_connection_signal_subscribe(
            face->bus,
            BIOMD_SERVICE,
            FACE_AGENT_IFACE,
            NULL,
            face->agent_path,
            NULL,
            G_DBUS_SIGNAL_FLAGS_NONE,
            on_agent_signal,
            face,
            NULL
        );

        if (!register_recognition(face))
            g_debug("Face: failed to register recognition agent at init");
    } else {
        g_debug("Face: failed to create agent at init");
    }

    face->has_access = agent_get_prop_bool(face, "HasAccess");

    return face;
}

void
session_face_free(SessionFace *face)
{
    if (!face)
        return;

    session_face_stop(face);

    if (face->bus) {
        if (face->sig_agent_id) {
            g_dbus_connection_signal_unsubscribe(face->bus, face->sig_agent_id);
            face->sig_agent_id = 0;
        }

        if (face->sig_manager_id) {
            g_dbus_connection_signal_unsubscribe(face->bus, face->sig_manager_id);
            face->sig_manager_id = 0;
        }
    }

    g_clear_pointer(&face->agent_path, g_free);
    g_free(face);
}

gboolean
session_face_is_available(SessionFace *face)
{
    gint impl_type = TYPE_UNKNOWN;

    if (!face)
        return FALSE;

    if (face->available_checked)
        return face->available_cached;

    face->available_checked = TRUE;
    face->available_cached = FALSE;

    impl_type = face_get_prop_int(face, "ImplementationType");
    if (impl_type == TYPE_UNKNOWN) {
        face->available_cached = FALSE;
        return FALSE;
    }

    face->available_cached = TRUE;
    return TRUE;
}

gboolean
session_face_is_enrolled(SessionFace *face)
{
    if (!face)
        return FALSE;

    return face_get_prop_bool(face, "FaceEnrolled");
}

gboolean
session_face_start(SessionFace *face)
{
    if (!face)
        return FALSE;

    if (!session_face_is_available(face))
        return FALSE;

    if (!session_face_is_enrolled(face))
        return FALSE;

    face->want_start = TRUE;

    face->has_access = agent_get_prop_bool(face, "HasAccess");

    if (!face->has_access) {
        g_debug("Face: no access yet");
        return FALSE;
    }

    return try_start_if_ready(face);
}

void
session_face_stop(SessionFace *face)
{
    if (!face)
        return;

    stop_pipeline(face);

    if (face->has_access && (face->recognition_started || face->in_progress))
        agent_cancel(face);

    face->in_progress = FALSE;
    face->recognition_started = FALSE;
    face->last_submit_us = 0;

    face->want_start = FALSE;
}
