/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "session_fingerprint.h"

#define BIOMD_SERVICE "io.FuriOS.Biomd"
#define FINGERPRINT_PATH "/io/FuriOS/Biomd/Fingerprint"
#define FINGERPRINT_IFACE "io.FuriOS.Biomd.Fingerprint"

struct _SessionFingerprint {
    GDBusConnection *bus;
    GDBusProxy *proxy;

    guint sig_identified_id;
    guint sig_error_id;

    gboolean in_progress;

    SessionFingerprintSuccessCb success_cb;
    SessionFingerprintErrorCb error_cb;
    gpointer user_data;
};

static gboolean
fp_ensure_proxy(SessionFingerprint *fp)
{
    g_autoptr(GError) error = NULL;

    if (!fp)
        return FALSE;

    if (fp->proxy)
        return TRUE;

    fp->proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SYSTEM,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        BIOMD_SERVICE,
        FINGERPRINT_PATH,
        FINGERPRINT_IFACE,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to create fingerprint proxy: %s", error->message);
        return FALSE;
    }

    return TRUE;
}

static gboolean
fp_get_bool_prop(SessionFingerprint *fp, const gchar *prop)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GVariant) v = NULL;

    if (!fp || !prop)
        return FALSE;

    if (!fp_ensure_proxy(fp))
        return FALSE;

    ret = g_dbus_proxy_call_sync(
        fp->proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", FINGERPRINT_IFACE, prop),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Fingerprint Get(%s) failed: %s", prop, error->message);
        return FALSE;
    }

    g_variant_get(ret, "(v)", &v);

    if (!g_variant_is_of_type(v, G_VARIANT_TYPE_BOOLEAN))
        return FALSE;

    return g_variant_get_boolean(v);
}

static gchar **
fp_get_strv_prop(SessionFingerprint *fp, const gchar *prop)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GVariant) v = NULL;
    gchar **strv = NULL;
    gsize n = 0;

    if (!fp || !prop)
        return NULL;

    if (!fp_ensure_proxy(fp))
        return NULL;

    ret = g_dbus_proxy_call_sync(
        fp->proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", FINGERPRINT_IFACE, prop),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Fingerprint Get(%s) failed: %s", prop, error->message);
        return NULL;
    }

    g_variant_get(ret, "(v)", &v);

    if (!g_variant_is_of_type(v, G_VARIANT_TYPE_STRING_ARRAY))
        return NULL;

    strv = g_variant_dup_strv(v, &n);
    if (!strv || n == 0) {
        g_strfreev(strv);
        return NULL;
    }

    return strv;
}

static void
on_fp_signal(GDBusConnection *connection,
             const gchar *sender_name,
             const gchar *object_path,
             const gchar *interface_name,
             const gchar *signal_name,
             GVariant *parameters,
             gpointer user_data)
{
    SessionFingerprint *fp = user_data;

    (void)connection;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;

    if (!fp)
        return;

    if (g_strcmp0(signal_name, "Identified") == 0) {
        fp->in_progress = FALSE;

        if (fp->success_cb)
            fp->success_cb(fp->user_data);

        return;
    }

    if (g_strcmp0(signal_name, "ErrorInfoChanged") == 0) {
        gint error_code = 0;
        g_variant_get(parameters, "(i)", &error_code);

        if (fp->error_cb)
            fp->error_cb(error_code, fp->user_data);

        return;
    }
}

SessionFingerprint *
session_fingerprint_new(GDBusConnection *system_bus,
                        SessionFingerprintSuccessCb success_cb,
                        SessionFingerprintErrorCb error_cb,
                        gpointer user_data)
{
    SessionFingerprint *fp = NULL;

    if (!system_bus)
        return NULL;

    fp = g_new0(SessionFingerprint, 1);
    fp->bus = system_bus;
    fp->success_cb = success_cb;
    fp->error_cb = error_cb;
    fp->user_data = user_data;

    fp->sig_identified_id = 0;
    fp->sig_error_id = 0;
    fp->in_progress = FALSE;

    if (!fp_ensure_proxy(fp)) {
        session_fingerprint_free(fp);
        return NULL;
    }

    fp->sig_identified_id = g_dbus_connection_signal_subscribe(
        fp->bus,
        BIOMD_SERVICE,
        FINGERPRINT_IFACE,
        "Identified",
        FINGERPRINT_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_fp_signal,
        fp,
        NULL
    );

    fp->sig_error_id = g_dbus_connection_signal_subscribe(
        fp->bus,
        BIOMD_SERVICE,
        FINGERPRINT_IFACE,
        "ErrorInfoChanged",
        FINGERPRINT_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_fp_signal,
        fp,
        NULL
    );

    return fp;
}

void
session_fingerprint_free(SessionFingerprint *fp)
{
    if (!fp)
        return;

    if (fp->bus) {
        if (fp->sig_identified_id) {
            g_dbus_connection_signal_unsubscribe(fp->bus, fp->sig_identified_id);
            fp->sig_identified_id = 0;
        }

        if (fp->sig_error_id) {
            g_dbus_connection_signal_unsubscribe(fp->bus, fp->sig_error_id);
            fp->sig_error_id = 0;
        }
    }

    g_clear_object(&fp->proxy);
    g_free(fp);
}

gboolean
session_fingerprint_is_available(SessionFingerprint *fp)
{
    if (!fp)
        return FALSE;

    return fp_get_bool_prop(fp, "HardwareAvailable");
}

gboolean
session_fingerprint_has_enrolled(SessionFingerprint *fp)
{
    gchar **fingers = NULL;
    gboolean ok = FALSE;

    if (!fp)
        return FALSE;

    fingers = fp_get_strv_prop(fp, "EnrolledFingers");
    ok = (fingers != NULL);

    g_strfreev(fingers);
    return ok;
}

gboolean
session_fingerprint_start(SessionFingerprint *fp)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    gboolean success = FALSE;

    if (!fp)
        return FALSE;

    if (!fp_ensure_proxy(fp))
        return FALSE;

    if (fp->in_progress)
        return TRUE;

    ret = g_dbus_proxy_call_sync(
        fp->proxy,
        "Identify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Fingerprint Identify failed: %s", error->message);
        fp->in_progress = FALSE;
        return FALSE;
    }

    g_variant_get(ret, "(b)", &success);

    if (success)
        fp->in_progress = TRUE;

    return success;
}

void
session_fingerprint_stop(SessionFingerprint *fp)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) ret = NULL;
    gboolean success = FALSE;

    if (!fp)
        return;

    if (!fp_ensure_proxy(fp))
        return;

    if (!fp->in_progress)
        return;

    ret = g_dbus_proxy_call_sync(
        fp->proxy,
        "StopIdentify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Fingerprint StopIdentify failed: %s", error->message);
        return;
    }

    g_variant_get(ret, "(b)", &success);

    if (success) {
        g_debug("Fingerprint identification stopped successfully");
        fp->in_progress = FALSE;
    } else {
        g_debug("Failed to stop fingerprint identification");
    }
}
