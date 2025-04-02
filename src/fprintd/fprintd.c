/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"
#include "biomd_enums.h"

#define FPRINT_MANAGER_DBUS_NAME       "net.reactivated.Fprint"
#define FPRINT_MANAGER_DBUS_PATH       "/net/reactivated/Fprint/Manager"
#define FPRINT_MANAGER_DBUS_INTERFACE  "net.reactivated.Fprint.Manager"
#define FPRINT_DEVICE_DBUS_PATH        "/net/reactivated/Fprint/Device/0"
#define FPRINT_DEVICE_DBUS_INTERFACE   "net.reactivated.Fprint.Device"

#define BIOMD_DBUS_NAME                "io.FuriOS.Biomd"
#define BIOMD_DBUS_PATH                "/io/FuriOS/Biomd/Fingerprint"
#define BIOMD_DBUS_INTERFACE           "io.FuriOS.Biomd.Fingerprint"

typedef struct {
    GMainLoop *loop;
    GDBusConnection *conn;
    GDBusNodeInfo *manager_introspection_data;
    GDBusNodeInfo *device_introspection_data;
    GDBusProxy *biomd_proxy;
    gboolean enroll_in_progress;
    gboolean verify_in_progress;
    gint enroll_progress;
    gchar *verify_finger;

    BiometricState state;
    BiometricError error_info;
    BiometricAcquisition acquisition_info;
    gboolean hardware_available;
    GStrv enrolled_fingers;
} Fprintd;

static const gchar manager_introspection_xml[] =
    "<node>"
    "  <interface name='net.reactivated.Fprint.Manager'>"
    "    <method name='GetDevices'>"
    "      <arg type='ao' name='devices' direction='out'/>"
    "    </method>"
    "    <method name='GetDefaultDevice'>"
    "      <arg type='o' name='device' direction='out'/>"
    "    </method>"
    "  </interface>"
    "</node>";

static const gchar device_introspection_xml[] =
    "<node>"
    "  <interface name='net.reactivated.Fprint.Device'>"
    "    <property type='s' name='name' access='read'/>"
    "    <property type='i' name='num-enroll-stages' access='read'/>"
    "    <property type='s' name='scan-type' access='read'/>"
    "    <property type='b' name='finger-present' access='read'/>"
    "    <property type='b' name='finger-needed' access='read'/>"
    "    <method name='ListEnrolledFingers'>"
    "      <arg type='s' name='username' direction='in'/>"
    "      <arg type='as' name='fingers' direction='out'/>"
    "    </method>"
    "    <method name='DeleteEnrolledFingers'>"
    "      <arg type='s' name='username' direction='in'/>"
    "    </method>"
    "    <method name='DeleteEnrolledFingers2'>"
    "    </method>"
    "    <method name='DeleteEnrolledFinger'>"
    "      <arg type='s' name='finger_name' direction='in'/>"
    "    </method>"
    "    <method name='Claim'>"
    "      <arg type='s' name='username' direction='in'/>"
    "    </method>"
    "    <method name='Release'>"
    "    </method>"
    "    <method name='VerifyStart'>"
    "      <arg type='s' name='finger_name' direction='in'/>"
    "    </method>"
    "    <method name='VerifyStop'>"
    "    </method>"
    "    <method name='EnrollStart'>"
    "      <arg type='s' name='finger_name' direction='in'/>"
    "    </method>"
    "    <method name='EnrollStop'>"
    "    </method>"
    "    <signal name='VerifyFingerSelected'>"
    "      <arg type='s' name='finger_name'/>"
    "    </signal>"
    "    <signal name='VerifyStatus'>"
    "      <arg type='s' name='result'/>"
    "      <arg type='b' name='done'/>"
    "    </signal>"
    "    <signal name='EnrollStatus'>"
    "      <arg type='s' name='result'/>"
    "      <arg type='b' name='done'/>"
    "    </signal>"
    "  </interface>"
    "</node>";

/* TODO: this is in fingerprint.c too, move shared functions elsewhere */
static gboolean
is_valid_finger_name(const gchar *finger_name)
{
    if (!finger_name)
        return FALSE;

    for (gint i = 0; valid_finger_names[i] != NULL; i++) {
        if (g_strcmp0(finger_name, valid_finger_names[i]) == 0)
            return TRUE;
    }

    return FALSE;
}

static gboolean
check_caller_authorization(GDBusConnection *connection,
                           const gchar *sender,
                           GDBusMethodInvocation *invocation)
{
    g_autoptr(GError) error = NULL;
    guint32 uid = G_MAXUINT32;
    g_autoptr(GDBusProxy) bus_proxy;
    g_autoptr(GVariant) result;

    bus_proxy = g_dbus_proxy_new_sync(
        connection,
        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
        NULL,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        NULL,
        &error);

    if (error != NULL) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_FAILED,
                                              "Failed to create bus proxy: %s",
                                              error->message);
        return FALSE;
    }

    result = g_dbus_proxy_call_sync(
        bus_proxy,
        "GetConnectionUnixUser",
        g_variant_new("(s)", sender),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error);

    if (error != NULL) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_FAILED,
                                              "Failed to get caller credentials: %s",
                                              error->message);
        return FALSE;
    }

    g_variant_get(result, "(u)", &uid);
    if (uid != 0 && uid != 32011) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_ACCESS_DENIED,
                                              "Access denied: only UIDs 0 and 32011 are allowed");
        return FALSE;
    }

    return TRUE;
}

static gboolean
get_property_boolean(GDBusProxy *proxy, const gchar *property_name, gboolean default_value)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value = NULL;
    gboolean retval = default_value;

    result = g_dbus_proxy_call_sync(
        proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", g_dbus_proxy_get_interface_name(proxy), property_name),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to get property %s: %s", property_name, error->message);
        return default_value;
    }

    g_variant_get(result, "(v)", &value);
    retval = g_variant_get_boolean(value);

    return retval;
}

static gint
get_property_int(GDBusProxy *proxy, const gchar *property_name, gint default_value)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value = NULL;
    gint retval = default_value;

    result = g_dbus_proxy_call_sync(
        proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", g_dbus_proxy_get_interface_name(proxy), property_name),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to get property %s: %s", property_name, error->message);
        return default_value;
    }

    g_variant_get(result, "(v)", &value);
    retval = g_variant_get_int32(value);

    return retval;
}

static GStrv
get_property_string_array(GDBusProxy *proxy, const gchar *property_name)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value = NULL;
    GStrv retval = NULL;

    result = g_dbus_proxy_call_sync(
        proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", g_dbus_proxy_get_interface_name(proxy), property_name),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to get property %s: %s", property_name, error->message);
        return g_new0(gchar*, 1);
    }

    g_variant_get(result, "(v)", &value);
    retval = g_variant_dup_strv(value, NULL);

    return retval;
}

static void
emit_verify_finger_selected(Fprintd *self, const gchar *finger_name)
{
    g_debug("Emitting VerifyFingerSelected signal with finger: %s", finger_name);
    g_dbus_connection_emit_signal(
        self->conn,
        NULL,
        FPRINT_DEVICE_DBUS_PATH,
        FPRINT_DEVICE_DBUS_INTERFACE,
        "VerifyFingerSelected",
        g_variant_new("(s)", finger_name),
        NULL
    );
}

static void
emit_verify_status(Fprintd *self, const gchar *result, gboolean done)
{
    g_debug("Emitting VerifyStatus signal with result: %s, done: %d", result, done);
    g_dbus_connection_emit_signal(
        self->conn,
        NULL,
        FPRINT_DEVICE_DBUS_PATH,
        FPRINT_DEVICE_DBUS_INTERFACE,
        "VerifyStatus",
        g_variant_new("(sb)", result, done),
        NULL
    );
}

static void
emit_enroll_status(Fprintd *self, const gchar *result, gboolean done)
{
    g_debug("Emitting EnrollStatus signal with result: %s, done: %d", result, done);
    g_dbus_connection_emit_signal(
        self->conn,
        NULL,
        FPRINT_DEVICE_DBUS_PATH,
        FPRINT_DEVICE_DBUS_INTERFACE,
        "EnrollStatus",
        g_variant_new("(sb)", result, done),
        NULL
    );
}

static gboolean
biomd_identify(Fprintd *self, GError **error)
{
    g_debug("Starting identification");
    g_dbus_proxy_call_sync(
        self->biomd_proxy,
        "Identify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        error
    );

    return (*error == NULL);
}

static gboolean
biomd_stop_identify(Fprintd *self, GError **error)
{
    g_debug("Stopping identification");
    g_dbus_proxy_call_sync(
        self->biomd_proxy,
        "StopIdentify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        error
    );

    return (*error == NULL);
}

static gboolean
biomd_enroll(Fprintd *self, const gchar *finger_name, GError **error)
{
    g_debug("Starting enrollment for finger: %s", finger_name);
    g_dbus_proxy_call_sync(
        self->biomd_proxy,
        "Enroll",
        g_variant_new("(s)", finger_name),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        error
    );

    return (*error == NULL);
}

static gboolean
biomd_stop_enroll(Fprintd *self, GError **error)
{
    g_debug("Stopping enrollment");
    g_dbus_proxy_call_sync(
        self->biomd_proxy,
        "StopEnroll",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        error
    );

    return (*error == NULL);
}

static gboolean
biomd_remove_finger(Fprintd *self, const gchar *finger_name, GError **error)
{
    g_debug("Removing finger: %s", finger_name);
    g_dbus_proxy_call_sync(
        self->biomd_proxy,
        "RemoveFinger",
        g_variant_new("(s)", finger_name),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        error
    );

    return (*error == NULL);
}

static void
update_biomd_properties(Fprintd *self)
{
    if (self->biomd_proxy) {
        self->state = get_property_int(self->biomd_proxy, "State", STATE_IDLE);
        self->error_info = get_property_int(self->biomd_proxy, "ErrorInfo", ERROR_NONE);
        self->acquisition_info = get_property_int(self->biomd_proxy, "AcquisitionInfo", ACQUISITION_NONE);
        self->hardware_available = get_property_boolean(self->biomd_proxy, "HardwareAvailable", FALSE);

        if (self->enrolled_fingers)
            g_strfreev(self->enrolled_fingers);

        self->enrolled_fingers = get_property_string_array(self->biomd_proxy, "EnrolledFingers");
        self->enroll_progress = get_property_int(self->biomd_proxy, "EnrollmentProgress", 0);
    }
}

static void
on_biomd_state_changed(GDBusConnection *connection,
                       const gchar *sender_name,
                       const gchar *object_path,
                       const gchar *interface_name,
                       const gchar *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;
    gint state;

    g_variant_get(parameters, "(i)", &state);
    self->state = state;

    g_debug("Biomd state changed: %d", state);

    if (state == STATE_IDLE) {
        if (self->enroll_in_progress) {
            emit_enroll_status(self, "enroll-stopped", TRUE);
            self->enroll_in_progress = FALSE;
        }

        if (self->verify_in_progress) {
            emit_verify_status(self, "verify-no-match", TRUE);
            self->verify_in_progress = FALSE;
            g_clear_pointer(&self->verify_finger, g_free);
        }
    }
}

static void
on_biomd_identified(GDBusConnection *connection,
                    const gchar *sender_name,
                    const gchar *object_path,
                    const gchar *interface_name,
                    const gchar *signal_name,
                    GVariant *parameters,
                    gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    if (!self->verify_in_progress)
        return;

    const gchar *identified_finger;
    g_variant_get(parameters, "(&s)", &identified_finger);

    g_debug("Identified finger: %s", identified_finger);

    emit_verify_finger_selected(self, identified_finger);

    if (self->verify_finger == NULL || g_strcmp0(identified_finger, self->verify_finger) == 0)
        emit_verify_status(self, "verify-match", TRUE);
    else
        emit_verify_status(self, "verify-no-match", TRUE);

    g_autoptr(GError) error = NULL;
    if (!biomd_stop_identify(self, &error))
        g_warning("Failed to stop identification after result: %s", error->message);

    self->verify_in_progress = FALSE;
    g_clear_pointer(&self->verify_finger, g_free);
}

static void
on_biomd_enroll_progress_changed(GDBusConnection *connection,
                                 const gchar *sender_name,
                                 const gchar *object_path,
                                 const gchar *interface_name,
                                 const gchar *signal_name,
                                 GVariant *parameters,
                                 gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    if (!self->enroll_in_progress)
        return;

    gint progress;
    g_variant_get(parameters, "(i)", &progress);

    g_debug("Enroll progress: %d", progress);
    self->enroll_progress = progress;

    if (progress == 100) {
        emit_enroll_status(self, "enroll-completed", TRUE);
        self->enroll_in_progress = FALSE;
    } else {
        emit_enroll_status(self, "enroll-stage-passed", FALSE);
    }
}

static void
on_biomd_error_info_changed(GDBusConnection *connection,
                            const gchar *sender_name,
                            const gchar *object_path,
                            const gchar *interface_name,
                            const gchar *signal_name,
                            GVariant *parameters,
                            gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    gint error_code;
    g_variant_get(parameters, "(i)", &error_code);

    g_debug("Biomd error info changed: %d", error_code);
    self->error_info = error_code;

    if (self->verify_in_progress) {
        g_autoptr(GError) error = NULL;

        switch (error_code) {
            case ERROR_FINGER_NOT_RECOGNIZED:
                emit_verify_status(self, "verify-no-match", TRUE);
                if (!biomd_stop_identify(self, &error))
                    g_warning("Failed to stop identification after no match: %s", error->message);

                self->verify_in_progress = FALSE;
                g_clear_pointer(&self->verify_finger, g_free);
                break;
            case ERROR_TIMEOUT:
            case ERROR_CANCELED:
                emit_verify_status(self, "verify-disconnected", TRUE);
                if (!biomd_stop_identify(self, &error))
                    g_warning("Failed to stop identification after disconnect: %s", error->message);

                self->verify_in_progress = FALSE;
                g_clear_pointer(&self->verify_finger, g_free);
                break;
            case ERROR_HW_UNAVAILABLE:
            case ERROR_UNABLE_TO_PROCESS:
            case ERROR_LOCKOUT:
            case ERROR_GENERAL:
                emit_verify_status(self, "verify-unknown-error", TRUE);
                if (!biomd_stop_identify(self, &error))
                    g_warning("Failed to stop identification after error: %s", error->message);

                self->verify_in_progress = FALSE;
                g_clear_pointer(&self->verify_finger, g_free);
                break;
        }
    }

    if (self->enroll_in_progress) {
        g_autoptr(GError) error = NULL;
        switch (error_code) {
            case ERROR_TIMEOUT:
            case ERROR_CANCELED:
                emit_enroll_status(self, "enroll-disconnected", TRUE);
                if (!biomd_stop_enroll(self, &error))
                    g_warning("Failed to stop enrollment after disconnect: %s", error->message);

                self->enroll_in_progress = FALSE;
                break;
            case ERROR_UNABLE_TO_PROCESS:
            case ERROR_HW_UNAVAILABLE:
                emit_enroll_status(self, "enroll-unknown-error", TRUE);
                if (!biomd_stop_enroll(self, &error))
                    g_warning("Failed to stop enrollment after error: %s", error->message);

                self->enroll_in_progress = FALSE;
                break;
            case ERROR_NO_SPACE:
                emit_enroll_status(self, "enroll-data-full", TRUE);
                if (!biomd_stop_enroll(self, &error))
                    g_warning("Failed to stop enrollment after no space: %s", error->message);

                self->enroll_in_progress = FALSE;
                break;
            case ERROR_LOCKOUT:
            case ERROR_GENERAL:
                emit_enroll_status(self, "enroll-failed", TRUE);
                if (!biomd_stop_enroll(self, &error))
                    g_warning("Failed to stop enrollment after failure: %s", error->message);

                self->enroll_in_progress = FALSE;
                break;
            /* FINGER_NOT_RECOGNIZED and REMOVE will only happen during verify and remove. this is here just to silence warnings */
            case ERROR_REMOVE:
            case ERROR_FINGER_NOT_RECOGNIZED:
                break;
        }
    }
}

static void
on_biomd_acquisition_info_changed(GDBusConnection *connection,
                                  const gchar *sender_name,
                                  const gchar *object_path,
                                  const gchar *interface_name,
                                  const gchar *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    gint acquisition_info;
    g_variant_get(parameters, "(i)", &acquisition_info);

    g_debug("Biomd acquisition info changed: %d", acquisition_info);
    self->acquisition_info = acquisition_info;

    if (self->enroll_in_progress) {
        switch (acquisition_info) {
            case ACQUISITION_PARTIAL:
                emit_enroll_status(self, "enroll-swipe-too-short", FALSE);
                break;
            case ACQUISITION_INSUFFICIENT:
            case ACQUISITION_IMAGER_DIRTY:
            case ACQUISITION_TOO_SLOW:
                emit_enroll_status(self, "enroll-retry-scan", FALSE);
                break;
            case ACQUISITION_TOO_FAST:
                emit_enroll_status(self, "enroll-swipe-too-fast", FALSE);
                break;
        }
    }
}

static void
on_biomd_enrolled_fingers_changed(GDBusConnection *connection,
                                  const gchar *sender_name,
                                  const gchar *object_path,
                                  const gchar *interface_name,
                                  const gchar *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;
    g_autoptr(GVariant) array_variant;

    if (self->enrolled_fingers)
        g_strfreev(self->enrolled_fingers);

    array_variant = g_variant_get_child_value(parameters, 0);
    self->enrolled_fingers = g_variant_dup_strv(array_variant, NULL);

    g_debug("Enrolled fingers changed");
}

static void
handle_method_call(GDBusConnection *connection,
                   const gchar *sender,
                   const gchar *object_path,
                   const gchar *interface_name,
                   const gchar *method_name,
                   GVariant *parameters,
                   GDBusMethodInvocation *invocation,
                   gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    if (!check_caller_authorization(connection, sender, invocation))
        return;

    g_debug("Method call: %s.%s()", interface_name, method_name);

    if (g_strcmp0(interface_name, FPRINT_MANAGER_DBUS_INTERFACE) == 0) {
        if (g_strcmp0(method_name, "GetDevices") == 0) {
            GVariantBuilder builder;
            g_variant_builder_init(&builder, G_VARIANT_TYPE("ao"));
            g_variant_builder_add(&builder, "o", FPRINT_DEVICE_DBUS_PATH);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(ao)", &builder));
            return;
        } else if (g_strcmp0(method_name, "GetDefaultDevice") == 0) {
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", FPRINT_DEVICE_DBUS_PATH));
            return;
        }
    }

    if (g_strcmp0(interface_name, FPRINT_DEVICE_DBUS_INTERFACE) == 0) {
        if (g_strcmp0(method_name, "ListEnrolledFingers") == 0) {
            const gchar *username;
            g_variant_get(parameters, "(&s)", &username);

            if (self->enrolled_fingers)
                g_strfreev(self->enrolled_fingers);

            self->enrolled_fingers = get_property_string_array(self->biomd_proxy, "EnrolledFingers");

            if (self->enrolled_fingers == NULL || g_strv_length(self->enrolled_fingers) == 0) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.NoEnrolledPrints",
                    "User doesn't have any fingerprints enrolled"
                );
                return;
            }

            GVariantBuilder builder;
            g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));

            for (guint i = 0; self->enrolled_fingers[i] != NULL; i++) {
                g_variant_builder_add(&builder, "s", self->enrolled_fingers[i]);
            }

            g_dbus_method_invocation_return_value(invocation, g_variant_new("(as)", &builder));
            return;
        } else if (g_strcmp0(method_name, "DeleteEnrolledFingers") == 0 ||
                   g_strcmp0(method_name, "DeleteEnrolledFingers2") == 0) {
            if (self->enrolled_fingers)
                g_strfreev(self->enrolled_fingers);

            self->enrolled_fingers = get_property_string_array(self->biomd_proxy, "EnrolledFingers");

            if (self->enrolled_fingers != NULL) {
                for (guint i = 0; self->enrolled_fingers[i] != NULL; i++) {
                    g_autoptr(GError) remove_error = NULL;
                    if (!biomd_remove_finger(self, self->enrolled_fingers[i], &remove_error))
                        g_warning("Failed to remove finger %s: %s", self->enrolled_fingers[i], remove_error->message);
                }
            }

            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        } else if (g_strcmp0(method_name, "DeleteEnrolledFinger") == 0) {
            const gchar *finger_name;
            g_variant_get(parameters, "(&s)", &finger_name);

            if (!is_valid_finger_name(finger_name)) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.InvalidFingername",
                    "Invalid finger name"
                );
                return;
            }

            g_autoptr(GError) error = NULL;
            if (!biomd_remove_finger(self, finger_name, &error)) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.NoEnrolledPrints",
                    "No enrolled prints for this finger"
                );
                return;
            }

            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        } else if (g_strcmp0(method_name, "Claim") == 0 ||
                   g_strcmp0(method_name, "Release") == 0) {
            /* no op. do something? fprintd says polkit */
            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        } else if (g_strcmp0(method_name, "VerifyStart") == 0) {
            const gchar *finger_name;
            g_variant_get(parameters, "(&s)", &finger_name);

            if (self->verify_in_progress) {
                g_autoptr(GError) error = NULL;
                if (!biomd_stop_identify(self, &error))
                    g_warning("Failed to stop identification during VerifyStart: %s", error->message);

                self->verify_in_progress = FALSE;
                g_clear_pointer(&self->verify_finger, g_free);
            }

            if (self->state != STATE_IDLE) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.AlreadyInUse",
                    "Device already in use"
                );
                return;
            }

            g_clear_pointer(&self->verify_finger, g_free);
            self->verify_finger = g_strdup(finger_name);

            if (self->enrolled_fingers)
                g_strfreev(self->enrolled_fingers);

            self->enrolled_fingers = get_property_string_array(self->biomd_proxy, "EnrolledFingers");

            if (self->enrolled_fingers == NULL || g_strv_length(self->enrolled_fingers) == 0) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.NoEnrolledPrints",
                    "User doesn't have any fingerprints enrolled"
                );
                return;
            }

            g_autoptr(GError) error = NULL;
            if (!biomd_identify(self, &error)) {
                g_warning("Failed to start identification: %s", error->message);
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.Internal",
                    "Failed to start verification"
                );
                return;
            }

            self->verify_in_progress = TRUE;
            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        } else if (g_strcmp0(method_name, "VerifyStop") == 0) {
            if (self->verify_in_progress) {
                g_autoptr(GError) error = NULL;
                if (!biomd_stop_identify(self, &error))
                    g_warning("Failed to stop identification during VerifyStop: %s", error->message);

                self->verify_in_progress = FALSE;
                g_clear_pointer(&self->verify_finger, g_free);
            }

            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        } else if (g_strcmp0(method_name, "EnrollStart") == 0) {
            const gchar *finger_name;
            g_variant_get(parameters, "(&s)", &finger_name);

            if (self->enroll_in_progress) {
                g_autoptr(GError) error = NULL;
                if (!biomd_stop_enroll(self, &error))
                    g_warning("Failed to stop enrollment during EnrollStart: %s", error->message);

                self->enroll_in_progress = FALSE;
            }

            if (self->state != STATE_IDLE) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.AlreadyInUse",
                    "Device already in use"
                );
                return;
            }

            if (!is_valid_finger_name(finger_name)) {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.InvalidFingername",
                    "Invalid finger name"
                );
                return;
            }

            g_autoptr(GError) error = NULL;
            if (!biomd_enroll(self, finger_name, &error)) {
                g_warning("Failed to start enrollment: %s", error->message);
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.Internal",
                    "Failed to start enrollment"
                );
                return;
            }

            self->enroll_in_progress = TRUE;
            self->enroll_progress = 0;
            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        } else if (g_strcmp0(method_name, "EnrollStop") == 0) {
            if (self->enroll_in_progress) {
                g_autoptr(GError) error = NULL;
                if (!biomd_stop_enroll(self, &error))
                    g_warning("Failed to stop enrollment during EnrollStop: %s", error->message);

                self->enroll_in_progress = FALSE;
            }

            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        }
    }

    g_dbus_method_invocation_return_error(
        invocation,
        G_DBUS_ERROR,
        G_DBUS_ERROR_UNKNOWN_METHOD,
        "Unknown method: %s.%s",
        interface_name,
        method_name
    );
}

static GVariant *
handle_get_property(GDBusConnection *connection,
                    const gchar *sender,
                    const gchar *object_path,
                    const gchar *interface_name,
                    const gchar *property_name,
                    GError **error,
                    gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    g_debug("Get property: %s.%s", interface_name, property_name);

    if (g_strcmp0(interface_name, FPRINT_DEVICE_DBUS_INTERFACE) == 0) {
        if (g_strcmp0(property_name, "name") == 0) {
            return g_variant_new_string("Biomd");
        } else if (g_strcmp0(property_name, "num-enroll-stages") == 0) {
            return g_variant_new_int32(13);
        } else if (g_strcmp0(property_name, "scan-type") == 0) {
            return g_variant_new_string("press");
        } else if (g_strcmp0(property_name, "finger-present") == 0) {
            gboolean finger_present = (self->acquisition_info == ACQUISITION_GOOD ||
                                       self->acquisition_info == ACQUISITION_PARTIAL);
            return g_variant_new_boolean(finger_present);
        } else if (g_strcmp0(property_name, "finger-needed") == 0) {
            gboolean finger_needed = (self->state == STATE_IDENTIFYING ||
                                      self->state == STATE_ENROLLING);
            return g_variant_new_boolean(finger_needed);
        }
    }

    g_set_error(
        error,
        G_DBUS_ERROR,
        G_DBUS_ERROR_UNKNOWN_PROPERTY,
        "Unknown property: %s.%s",
        interface_name,
        property_name
    );

    return NULL;
}

static const
GDBusInterfaceVTable manager_interface_vtable = {
    .method_call = handle_method_call,
    .get_property = handle_get_property,
    .set_property = NULL
};

static const
GDBusInterfaceVTable device_interface_vtable = {
    .method_call = handle_method_call,
    .get_property = handle_get_property,
    .set_property = NULL
};

static void
on_bus_acquired(GDBusConnection *connection,
                const gchar *name,
                gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;
    g_autoptr(GError) error = NULL;
    guint manager_reg_id, device_reg_id;

    self->conn = connection;

    manager_reg_id = g_dbus_connection_register_object(
        connection,
        FPRINT_MANAGER_DBUS_PATH,
        self->manager_introspection_data->interfaces[0],
        &manager_interface_vtable,
        self,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to register manager interface: %s", error->message);
        g_main_loop_quit(self->loop);
        return;
    }

    g_debug("Manager interface registered (id: %u)", manager_reg_id);

    device_reg_id = g_dbus_connection_register_object(
        connection,
        FPRINT_DEVICE_DBUS_PATH,
        self->device_introspection_data->interfaces[0],
        &device_interface_vtable,
        self,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to register device interface: %s", error->message);
        g_main_loop_quit(self->loop);
        return;
    }

    g_debug("Device interface registered (id: %u)", device_reg_id);

    self->biomd_proxy = g_dbus_proxy_new_sync(
        connection,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_PATH,
        BIOMD_DBUS_INTERFACE,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to create biomd proxy: %s", error->message);
        g_main_loop_quit(self->loop);
        return;
    }

    update_biomd_properties(self);

    g_dbus_connection_signal_subscribe(
        connection,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_INTERFACE,
        "StateChanged",
        BIOMD_DBUS_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_state_changed,
        self,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        connection,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_INTERFACE,
        "Identified",
        BIOMD_DBUS_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_identified,
        self,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        connection,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_INTERFACE,
        "EnrollmentProgressChanged",
        BIOMD_DBUS_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_enroll_progress_changed,
        self,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        connection,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_INTERFACE,
        "ErrorInfoChanged",
        BIOMD_DBUS_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_error_info_changed,
        self,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        connection,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_INTERFACE,
        "AcquisitionInfoChanged",
        BIOMD_DBUS_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_acquisition_info_changed,
        self,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        connection,
        BIOMD_DBUS_NAME,
        BIOMD_DBUS_INTERFACE,
        "EnrolledFingersChanged",
        BIOMD_DBUS_PATH,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_enrolled_fingers_changed,
        self,
        NULL
    );
}

static void
on_name_acquired(GDBusConnection *connection,
                 const gchar *name,
                 gpointer user_data)
{
    g_debug("D-Bus name '%s' acquired", name);
}

static void
on_name_lost(GDBusConnection *connection,
             const gchar *name,
             gpointer user_data)
{
    Fprintd *self = (Fprintd *)user_data;

    g_print("D-Bus name '%s' lost", name);
    g_main_loop_quit(self->loop);
}

int
main(int argc, char *argv[])
{
    Fprintd self = {0};
    guint bus_owner_id;

    self.loop = g_main_loop_new(NULL, FALSE);
    self.enroll_in_progress = FALSE;
    self.verify_in_progress = FALSE;
    self.enroll_progress = 0;
    self.verify_finger = NULL;
    self.state = STATE_IDLE;
    self.error_info = ERROR_NONE;
    self.acquisition_info = ACQUISITION_NONE;
    self.hardware_available = FALSE;
    self.enrolled_fingers = NULL;

    g_autoptr(GError) error = NULL;
    self.manager_introspection_data = g_dbus_node_info_new_for_xml(manager_introspection_xml, &error);
    if (error) {
        g_warning("Failed to parse manager introspection data: %s", error->message);
        return 1;
    }

    error = NULL;
    self.device_introspection_data = g_dbus_node_info_new_for_xml(device_introspection_xml, &error);
    if (error) {
        g_warning("Failed to parse device introspection data: %s", error->message);
        return 1;
    }

    bus_owner_id = g_bus_own_name(
        G_BUS_TYPE_SYSTEM,
        FPRINT_MANAGER_DBUS_NAME,
        G_BUS_NAME_OWNER_FLAGS_NONE,
        on_bus_acquired,
        on_name_acquired,
        on_name_lost,
        &self,
        NULL
    );

    g_main_loop_run(self.loop);

    g_bus_unown_name(bus_owner_id);
    g_main_loop_unref(self.loop);
    g_dbus_node_info_unref(self.manager_introspection_data);
    g_dbus_node_info_unref(self.device_introspection_data);

    if (self.biomd_proxy)
        g_object_unref(self.biomd_proxy);

    g_clear_pointer(&self.verify_finger, g_free);

    if (self.enrolled_fingers)
        g_strfreev(self.enrolled_fingers);

    return 0;
}
