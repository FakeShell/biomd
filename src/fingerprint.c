/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "fingerprint.h"
#include "introspect.h"
#include "database.h"
#include "fpd_compat.h"
#include "fingerprint_hidl_backend.h"

static GDBusNodeInfo *fingerprint_introspection_data = NULL;

typedef struct {
    BiometricState current_state;
    gint enrollment_progress;
    GArray *enrolled_fingers;
    BiometricError error_info;
    BiometricAcquisition acquisition_info;
    FingerprintBackend *backend;
    gboolean backend_available;
    GDBusConnection *connection;
    gchar *enrollment_finger_name;
} BiomFingerprint;

static BiomFingerprint *fingerprint_state = NULL;

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

void
emit_signal_state_changed(GDBusConnection *connection, BiometricState state)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in emit_signal_state_changed");
        return;
    }

    g_dbus_connection_emit_signal(connection,
                                  NULL,
                                  "/org/FuriOS/Biomd/Fingerprint",
                                  "io.FuriOS.Biomd.Fingerprint",
                                  "StateChanged",
                                  g_variant_new("(i)", state),
                                  NULL);
}

void
emit_signal_enrollment_progress_changed(GDBusConnection *connection, gint progress)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in emit_signal_enrollment_progress_changed");
        return;
    }

    g_dbus_connection_emit_signal(connection,
                                  NULL,
                                  "/org/FuriOS/Biomd/Fingerprint",
                                  "io.FuriOS.Biomd.Fingerprint",
                                  "EnrollmentProgressChanged",
                                  g_variant_new("(i)", progress),
                                  NULL);
}

void
emit_signal_enrolled_fingers_changed(GDBusConnection *connection, GArray *fingers)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in emit_signal_enrolled_fingers_changed");
        return;
    }

    if (fingers == NULL) {
        g_warning("Fingers array is NULL in emit_signal_enrolled_fingers_changed");
        return;
    }

    const gchar **strings = g_new0(const gchar *, fingers->len + 1);
    for (guint i = 0; i < fingers->len; i++) {
        strings[i] = g_array_index(fingers, gchar*, i);
        if (strings[i] == NULL)
            strings[i] = "";
    }

    GVariant *variant = g_variant_new("(^as)", strings);
    g_dbus_connection_emit_signal(connection,
                                  NULL,
                                  "/org/FuriOS/Biomd/Fingerprint",
                                  "io.FuriOS.Biomd.Fingerprint",
                                  "EnrolledFingersChanged",
                                  variant,
                                  NULL);
    g_free(strings);
}

void
emit_signal_error_info_changed(GDBusConnection *connection, BiometricError error)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in emit_signal_error_info_changed");
        return;
    }

    g_dbus_connection_emit_signal(connection,
                                  NULL,
                                  "/org/FuriOS/Biomd/Fingerprint",
                                  "io.FuriOS.Biomd.Fingerprint",
                                  "ErrorInfoChanged",
                                  g_variant_new("(i)", error),
                                  NULL);
}

void
emit_signal_acquisition_info_changed(GDBusConnection *connection, BiometricAcquisition info)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in emit_signal_acquisition_info_changed");
        return;
    }

    g_dbus_connection_emit_signal(connection,
                                  NULL,
                                  "/org/FuriOS/Biomd/Fingerprint",
                                  "io.FuriOS.Biomd.Fingerprint",
                                  "AcquisitionInfoChanged",
                                  g_variant_new("(i)", info),
                                  NULL);
}

void
emit_signal_identified(GDBusConnection *connection, const gchar *finger_name)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in emit_signal_identified");
        return;
    }

    if (finger_name == NULL) {
        g_warning("Finger name is NULL in emit_signal_identified");
        return;
    }

    g_dbus_connection_emit_signal(connection,
                                  NULL,
                                  "/org/FuriOS/Biomd/Fingerprint",
                                  "io.FuriOS.Biomd.Fingerprint",
                                  "Identified",
                                  g_variant_new("(s)", finger_name),
                                  NULL);
}

BiometricError
map_error_to_biometric_error(guint32 error)
{
    switch (error) {
        case 0: // FINGERPRINT_ERROR_NO_ERROR
            return ERROR_NONE;
        case 1: // FINGERPRINT_ERROR_HW_UNAVAILABLE
            return ERROR_HW_UNAVAILABLE;
        case 2: // FINGERPRINT_ERROR_UNABLE_TO_PROCESS
            return ERROR_UNABLE_TO_PROCESS;
        case 3: // FINGERPRINT_ERROR_TIMEOUT
            return ERROR_TIMEOUT;
        case 4: // FINGERPRINT_ERROR_NO_SPACE
            return ERROR_NO_SPACE;
        case 5: // FINGERPRINT_ERROR_CANCELED
            return ERROR_CANCELED;
        case 6: // FINGERPRINT_ERROR_UNABLE_TO_REMOVE
            return ERROR_REMOVE;
        case 7: // FINGERPRINT_ERROR_LOCKOUT
            return ERROR_LOCKOUT;
        case 8: // FINGERPRINT_ERROR_VENDOR
        default:
            return ERROR_GENERAL;
    }
}

BiometricAcquisition
map_acquisition_to_biometric_acquisition(guint32 info)
{
    switch (info) {
        case 0: // FINGERPRINT_ACQUIRED_GOOD
            return ACQUISITION_GOOD;
        case 1: // FINGERPRINT_ACQUIRED_PARTIAL
            return ACQUISITION_PARTIAL;
        case 2: // FINGERPRINT_ACQUIRED_INSUFFICIENT
            return ACQUISITION_INSUFFICIENT;
        case 3: // FINGERPRINT_ACQUIRED_IMAGER_DIRTY
            return ACQUISITION_IMAGER_DIRTY;
        case 4: // FINGERPRINT_ACQUIRED_TOO_SLOW
            return ACQUISITION_TOO_SLOW;
        case 5: // FINGERPRINT_ACQUIRED_TOO_FAST
            return ACQUISITION_TOO_FAST;
        case 6: // FINGERPRINT_ACQUIRED_VENDOR
        default:
            return ACQUISITION_INSUFFICIENT;
    }
}

static void
update_enrolled_fingers_from_database(void)
{
    if (fingerprint_state == NULL || fingerprint_state->enrolled_fingers == NULL)
        return;

    for (guint i = 0; i < fingerprint_state->enrolled_fingers->len; i++) {
        g_free(g_array_index(fingerprint_state->enrolled_fingers, gchar*, i));
    }

    g_array_remove_range(fingerprint_state->enrolled_fingers, 0, fingerprint_state->enrolled_fingers->len);

    GArray *db_fingers = database_get_all_fingerprints();
    for (guint i = 0; i < db_fingers->len; i++) {
        gchar *finger_name = g_array_index(db_fingers, gchar*, i);
        gchar *finger_copy = g_strdup(finger_name);
        g_array_append_val(fingerprint_state->enrolled_fingers, finger_copy);
        g_free(finger_name);
    }

    g_array_free(db_fingers, TRUE);
}

static void
backend_enroll_result_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    BiomFingerprint *state = fingerprint_state;
    GDBusConnection *connection = state ? state->connection : NULL;
    if (!state || !connection) {
        g_warning("Invalid state in backend_enroll_result_cb");
        return;
    }

    gint progress = 100 - (remaining * 100 / 20);
    if (progress < 0)
        progress = 0;
    if (progress > 100)
        progress = 100;

    state->enrollment_progress = progress;
    emit_signal_enrollment_progress_changed(connection, progress);

    if (remaining == 0) {
        gchar *finger_name;

        if (state->enrollment_finger_name && state->enrollment_finger_name[0] != '\0') {
            finger_name = g_strdup(state->enrollment_finger_name);
            g_debug("Using requested finger name: %s", finger_name);
        } else {
            gchar *suggested_name = database_get_suggested_finger_name();
            if (suggested_name != NULL) {
                finger_name = suggested_name;
                g_debug("Using suggested finger name: %s", finger_name);
            } else {
                finger_name = g_strdup_printf("finger_%u", finger_id);
                g_debug("Using auto-generated finger name: %s", finger_name);
            }
        }

        database_add_fingerprint(finger_id, finger_name);
        update_enrolled_fingers_from_database();
        emit_signal_enrolled_fingers_changed(connection, state->enrolled_fingers);

        if (state->enrollment_finger_name) {
            g_free(state->enrollment_finger_name);
            state->enrollment_finger_name = NULL;
        }

        state->current_state = STATE_IDLE;
        emit_signal_state_changed(connection, state->current_state);

        g_free(finger_name);
    }
}

static void
backend_authenticated_cb(gpointer user_data, guint32 finger_id, guint32 group_id)
{
    BiomFingerprint *state = fingerprint_state;
    GDBusConnection *connection = state ? state->connection : NULL;
    if (!state || !connection) {
        g_warning("Invalid state in backend_authenticated_cb");
        return;
    }

    if (finger_id != 0) {
        gchar *finger_name = database_get_finger_name(finger_id);
        if (finger_name == NULL) {
            if (check_fingerprint_exists(finger_id)) {
                gchar *legacy_name = get_legacy_fingerprint_name(finger_id);
                if (legacy_name) {
                    g_debug("Using name from legacy database: %s for ID: %u", legacy_name, finger_id);
                    database_add_fingerprint(finger_id, legacy_name);
                    finger_name = g_strdup(legacy_name);
                    g_free(legacy_name);
                } else {
                    finger_name = g_strdup_printf("finger_%u", finger_id);
                    database_add_fingerprint(finger_id, finger_name);
                }
            } else {
                finger_name = g_strdup_printf("finger_%u", finger_id);
                database_add_fingerprint(finger_id, finger_name);
            }
        }

        emit_signal_identified(connection, finger_name);
        g_free(finger_name);
    }

    state->current_state = STATE_IDLE;
    emit_signal_state_changed(connection, state->current_state);
}

static void
backend_acquired_cb(gpointer user_data, guint32 acquired_info, guint32 vendor_code)
{
    BiomFingerprint *state = fingerprint_state;
    GDBusConnection *connection = state ? state->connection : NULL;
    if (!state || !connection) {
        g_warning("Invalid state in backend_acquired_cb");
        return;
    }

    BiometricAcquisition acquisition = map_acquisition_to_biometric_acquisition(acquired_info);
    state->acquisition_info = acquisition;
    emit_signal_acquisition_info_changed(connection, acquisition);
}

static void
backend_error_cb(gpointer user_data, guint32 error_code, guint32 vendor_code)
{
    BiomFingerprint *state = fingerprint_state;
    GDBusConnection *connection = state ? state->connection : NULL;
    if (!state || !connection) {
        g_warning("Invalid state in backend_error_cb");
        return;
    }

    BiometricError error = map_error_to_biometric_error(error_code);
    state->error_info = error;
    emit_signal_error_info_changed(connection, error);

    if (error_code != 0) { // FINGERPRINT_ERROR_NO_ERROR
        state->current_state = STATE_IDLE;
        emit_signal_state_changed(connection, state->current_state);
    }
}

static void
backend_removed_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    BiomFingerprint *state = fingerprint_state;
    GDBusConnection *connection = state ? state->connection : NULL;
    if (!state || !connection) {
        g_warning("Invalid state in backend_removed_cb");
        return;
    }

    if (finger_id != 0) {
        database_remove_fingerprint(finger_id);
        update_enrolled_fingers_from_database();
        emit_signal_enrolled_fingers_changed(connection, state->enrolled_fingers);
    }
}

static void
backend_enumerate_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    BiomFingerprint *state = fingerprint_state;
    GDBusConnection *connection = state ? state->connection : NULL;
    if (!state || !connection) {
        g_warning("Invalid state in backend_enumerate_cb");
        return;
    }

    if (finger_id != 0) {
        gchar *existing_name = database_get_finger_name(finger_id);
        if (existing_name == NULL) {
            if (check_fingerprint_exists(finger_id)) {
                gchar *legacy_name = get_legacy_fingerprint_name(finger_id);
                if (legacy_name) {
                    g_debug("Using name from legacy database: %s for ID: %u", legacy_name, finger_id);
                    database_add_fingerprint(finger_id, legacy_name);
                    g_free(legacy_name);
                } else {
                    gchar *finger_name = g_strdup_printf("finger_%u", finger_id);
                    database_add_fingerprint(finger_id, finger_name);
                    g_free(finger_name);
                }
            } else {
                gchar *finger_name = g_strdup_printf("finger_%u", finger_id);
                database_add_fingerprint(finger_id, finger_name);
                g_free(finger_name);
            }
        } else {
            g_free(existing_name);
        }
    }

    if (remaining == 0) {
        update_enrolled_fingers_from_database();
        if (state->enrolled_fingers && state->enrolled_fingers->len > 0)
            emit_signal_enrolled_fingers_changed(connection, state->enrolled_fingers);
    }
}

static void
handle_fingerprint_method_call(GDBusConnection *connection,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *method_name,
                               GVariant *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer user_data)
{
    BiomFingerprint *self = (BiomFingerprint *)user_data;

    if (g_strcmp0(method_name, "Enroll") == 0) {
        const gchar *finger_name = NULL;
        g_variant_get(parameters, "(&s)", &finger_name);

        if (!is_valid_finger_name(finger_name)) {
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR,
                                                  G_DBUS_ERROR_INVALID_ARGS,
                                                  "Invalid finger name: %s", finger_name ? finger_name : "(null)");
            return;
        }

        gboolean success = FALSE;

        if (self->current_state == STATE_IDLE) {
            self->current_state = STATE_ENROLLING;
            self->enrollment_progress = 0;

            if (self->enrollment_finger_name)
                g_free(self->enrollment_finger_name);
            self->enrollment_finger_name = g_strdup(finger_name);

            emit_signal_state_changed(connection, self->current_state);

            if (self->backend_available && self->backend) {
                g_debug("Starting fingerprint enrollment for finger %s", finger_name);
                success = fingerprint_backend_perform_enrollment(self->backend, "default_password", 60);
            } else {
                g_debug("Backend not available for enrollment");
            }

            if (!success) {
                self->current_state = STATE_IDLE;
                g_free(self->enrollment_finger_name);
                self->enrollment_finger_name = NULL;
                emit_signal_state_changed(connection, self->current_state);
            }
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    } else if (g_strcmp0(method_name, "Identify") == 0) {
        gboolean success = FALSE;

        if (self->current_state == STATE_IDLE) {
            self->current_state = STATE_IDENTIFYING;
            emit_signal_state_changed(connection, self->current_state);

            if (self->backend_available && self->backend) {
                g_debug("Starting fingerprint authentication");
                success = fingerprint_backend_perform_authentication(self->backend);
            } else {
                g_debug("Backend not available for authentication");
            }

            if (!success) {
                self->current_state = STATE_IDLE;
                emit_signal_state_changed(connection, self->current_state);
            }
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    } else if (g_strcmp0(method_name, "StopEnroll") == 0) {
        gboolean success = FALSE;

        if (self->current_state == STATE_ENROLLING) {
            self->current_state = STATE_IDLE;
            self->enrollment_progress = 0;

            if (self->enrollment_finger_name) {
                g_free(self->enrollment_finger_name);
                self->enrollment_finger_name = NULL;
            }

            emit_signal_state_changed(connection, self->current_state);

            if (self->backend_available && self->backend) {
                g_debug("Cancelling fingerprint enrollment");
                success = fingerprint_backend_cancel_operation(self->backend);
            }
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    } else if (g_strcmp0(method_name, "StopIdentify") == 0) {
        gboolean success = FALSE;

        if (self->current_state == STATE_IDENTIFYING) {
            self->current_state = STATE_IDLE;
            emit_signal_state_changed(connection, self->current_state);

            if (self->backend_available && self->backend) {
                g_debug("Cancelling fingerprint authentication");
                success = fingerprint_backend_cancel_operation(self->backend);
            }
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    } else if (g_strcmp0(method_name, "RemoveFinger") == 0) {
        const gchar *finger_name = NULL;
        g_variant_get(parameters, "(&s)", &finger_name);

        if (!is_valid_finger_name(finger_name)) {
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR,
                                                  G_DBUS_ERROR_INVALID_ARGS,
                                                  "Invalid finger name: %s", finger_name ? finger_name : "(null)");
            return;
        }

        gboolean success = FALSE;

        if (g_str_has_prefix(finger_name, "finger_")) {
            guint32 finger_id = (guint32)g_ascii_strtoull(finger_name + 7, NULL, 10);

            if (self->backend_available && self->backend) {
                g_debug("Removing fingerprint: %s (ID: %u)", finger_name, finger_id);
                success = fingerprint_backend_remove_fingerprint(self->backend, finger_id);
            } else {
                g_debug("Backend not available for removal");
                success = fingerprint_remove_enrolled_finger(finger_name);
                if (success)
                    emit_signal_enrolled_fingers_changed(connection, self->enrolled_fingers);
            }
        } else {
            guint32 finger_id = database_get_finger_id(finger_name);
            if (finger_id > 0) {
                if (self->backend_available && self->backend) {
                    g_debug("Removing fingerprint by name: %s (ID: %u)", finger_name, finger_id);
                    success = fingerprint_backend_remove_fingerprint(self->backend, finger_id);
                }
            }

            if (!success) {
                success = fingerprint_remove_enrolled_finger(finger_name);
                if (success)
                    emit_signal_enrolled_fingers_changed(connection, self->enrolled_fingers);
            }
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    } else if (g_strcmp0(method_name, "RenameFinger") == 0) {
        const gchar *old_name = NULL;
        const gchar *new_name = NULL;
        g_variant_get(parameters, "(&s&s)", &old_name, &new_name);

        if (!is_valid_finger_name(old_name)) {
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR,
                                                  G_DBUS_ERROR_INVALID_ARGS,
                                                  "Invalid original finger name: %s", old_name ? old_name : "(null)");
            return;
        }

        if (!is_valid_finger_name(new_name)) {
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR,
                                                  G_DBUS_ERROR_INVALID_ARGS,
                                                  "Invalid new finger name: %s", new_name ? new_name : "(null)");
            return;
        }

        gboolean success = FALSE;

        if (old_name && new_name && database_is_valid_finger_name(new_name)) {
            guint32 finger_id = database_get_finger_id(old_name);
            if (finger_id > 0) {
                success = database_set_finger_name(finger_id, new_name);
                if (success) {
                    update_enrolled_fingers_from_database();
                    emit_signal_enrolled_fingers_changed(connection, self->enrolled_fingers);
                }
            }
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    } else {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_UNKNOWN_METHOD,
                                              "Unknown method: %s", method_name);
    }
}

static GVariant *
handle_fingerprint_get_property(GDBusConnection *connection,
                                const gchar *sender,
                                const gchar *object_path,
                                const gchar *interface_name,
                                const gchar *property_name,
                                GError **error,
                                gpointer user_data)
{
    BiomFingerprint *self = (BiomFingerprint *)user_data;

    if (g_strcmp0(property_name, "State") == 0) {
        return g_variant_new_int32(self->current_state);
    } else if (g_strcmp0(property_name, "EnrollmentProgress") == 0) {
        return g_variant_new_int32(self->enrollment_progress);
    } else if (g_strcmp0(property_name, "EnrolledFingers") == 0) {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));

        if (self->enrolled_fingers) {
            for (guint i = 0; i < self->enrolled_fingers->len; i++) {
                const gchar *name = g_array_index(self->enrolled_fingers, gchar*, i);
                if (name != NULL)
                    g_variant_builder_add(&builder, "s", name);
            }
        }

        return g_variant_builder_end(&builder);
    } else if (g_strcmp0(property_name, "ErrorInfo") == 0) {
        return g_variant_new_int32(self->error_info);
    } else if (g_strcmp0(property_name, "AcquisitionInfo") == 0) {
        return g_variant_new_int32(self->acquisition_info);
    } else if (g_strcmp0(property_name, "HardwareAvailable") == 0) {
        return g_variant_new_boolean(self->backend_available);
    } else if (g_strcmp0(property_name, "ValidFingerNames") == 0) {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));

        for (gint i = 0; valid_finger_names[i] != NULL; i++) {
            g_variant_builder_add(&builder, "s", valid_finger_names[i]);
        }

        return g_variant_builder_end(&builder);
    } else {
        g_set_error(error,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_UNKNOWN_PROPERTY,
                    "Unknown property: %s", property_name);
        return NULL;
    }
}

static gboolean
handle_fingerprint_set_property(GDBusConnection *connection,
                                const gchar *sender,
                                const gchar *object_path,
                                const gchar *interface_name,
                                const gchar *property_name,
                                GVariant *value,
                                GError **error,
                                gpointer user_data)
{
    g_set_error(error,
                G_DBUS_ERROR,
                G_DBUS_ERROR_PROPERTY_READ_ONLY,
                "Property %s is not writable", property_name);
    return FALSE;
}

static const GDBusInterfaceVTable fingerprint_interface_vtable = {
    handle_fingerprint_method_call,
    handle_fingerprint_get_property,
    handle_fingerprint_set_property
};

guint
fingerprint_register(GDBusConnection *connection, GError **error)
{
    if (connection == NULL) {
        g_warning("Connection is NULL in fingerprint_register");
        g_set_error(error,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_FAILED,
                    "Connection is NULL");
        return 0;
    }

    if (fingerprint_introspection_data == NULL) {
        g_warning("Fingerprint introspection data not initialized");
        g_set_error(error,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_FAILED,
                    "Fingerprint introspection data not initialized");
        return 0;
    }

    return g_dbus_connection_register_object(
        connection,
        "/org/FuriOS/Biomd/Fingerprint",
        fingerprint_introspection_data->interfaces[0],
        &fingerprint_interface_vtable,
        fingerprint_state,
        NULL,
        error);
}

BiometricState
fingerprint_get_state(void)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_get_state");
        return STATE_IDLE;
    }

    return fingerprint_state->current_state;
}

gint
fingerprint_get_enrollment_progress(void)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_get_enrollment_progress");
        return 0;
    }

    return fingerprint_state->enrollment_progress;
}

GArray *
fingerprint_get_enrolled_fingers(void)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_get_enrolled_fingers");
        return NULL;
    }

    return fingerprint_state->enrolled_fingers;
}

BiometricError
fingerprint_get_error_info(void)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_get_error_info");
        return ERROR_NONE;
    }

    return fingerprint_state->error_info;
}

BiometricAcquisition
fingerprint_get_acquisition_info(void)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_get_acquisition_info");
        return ACQUISITION_NONE;
    }

    return fingerprint_state->acquisition_info;
}

void
fingerprint_set_state(BiometricState state)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_set_state");
        return;
    }

    fingerprint_state->current_state = state;
}

void
fingerprint_set_enrollment_progress(gint progress)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_set_enrollment_progress");
        return;
    }

    fingerprint_state->enrollment_progress = progress;
}

void
fingerprint_set_error_info(BiometricError error)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_set_error_info");
        return;
    }

    fingerprint_state->error_info = error;
}

void
fingerprint_set_acquisition_info(BiometricAcquisition info)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_set_acquisition_info");
        return;
    }

    fingerprint_state->acquisition_info = info;
}

gboolean
fingerprint_add_enrolled_finger(const gchar *finger_name)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_add_enrolled_finger");
        return FALSE;
    }

    if (fingerprint_state->enrolled_fingers == NULL) {
        g_warning("Enrolled fingers array is NULL in fingerprint_add_enrolled_finger");
        return FALSE;
    }

    if (finger_name == NULL) {
        g_warning("Finger name is NULL in fingerprint_add_enrolled_finger");
        return FALSE;
    }

    for (guint i = 0; i < fingerprint_state->enrolled_fingers->len; i++) {
        if (g_strcmp0(g_array_index(fingerprint_state->enrolled_fingers, gchar*, i), finger_name) == 0)
            return FALSE;
    }

    gchar *finger_copy = g_strdup(finger_name);
    g_array_append_val(fingerprint_state->enrolled_fingers, finger_copy);
    return TRUE;
}

gboolean
fingerprint_remove_enrolled_finger(const gchar *finger_name)
{
    if (fingerprint_state == NULL) {
        g_warning("fingerprint_state is NULL in fingerprint_remove_enrolled_finger");
        return FALSE;
    }

    if (fingerprint_state->enrolled_fingers == NULL) {
        g_warning("Enrolled fingers array is NULL in fingerprint_remove_enrolled_finger");
        return FALSE;
    }

    if (finger_name == NULL) {
        g_warning("Finger name is NULL in fingerprint_remove_enrolled_finger");
        return FALSE;
    }

    for (guint i = 0; i < fingerprint_state->enrolled_fingers->len; i++) {
        if (g_strcmp0(g_array_index(fingerprint_state->enrolled_fingers, gchar*, i), finger_name) == 0) {
            g_free(g_array_index(fingerprint_state->enrolled_fingers, gchar*, i));
            g_array_remove_index(fingerprint_state->enrolled_fingers, i);

            guint32 finger_id = database_get_finger_id(finger_name);
            if (finger_id > 0)
                database_remove_fingerprint(finger_id);

            return TRUE;
        }
    }

    return FALSE;
}

void
fingerprint_init(GDBusConnection *connection)
{
    GError *error = NULL;

    if (!database_init())
        g_warning("Failed to initialize fingerprint database");

    fingerprint_state = g_new0(BiomFingerprint, 1);
    fingerprint_state->current_state = STATE_IDLE;
    fingerprint_state->enrollment_progress = 0;
    fingerprint_state->error_info = ERROR_NONE;
    fingerprint_state->acquisition_info = ACQUISITION_NONE;
    fingerprint_state->enrolled_fingers = g_array_new(TRUE, TRUE, sizeof(gchar*));
    fingerprint_state->backend_available = FALSE;
    fingerprint_state->backend = NULL;
    fingerprint_state->connection = connection;
    fingerprint_state->enrollment_finger_name = NULL;

    fingerprint_introspection_data = g_dbus_node_info_new_for_xml(fingerprint_introspection_xml, &error);
    if (error != NULL) {
        g_warning("Parsing Fingerprint introspection XML: %s", error->message);
        g_error_free(error);
    }

    FingerprintBackendCallbacks callbacks = {
        .enroll_result = backend_enroll_result_cb,
        .acquired = backend_acquired_cb,
        .authenticated = backend_authenticated_cb,
        .error = backend_error_cb,
        .removed = backend_removed_cb,
        .enumerate = backend_enumerate_cb,
        .user_data = NULL
    };

    fingerprint_state->backend = fingerprint_hidl_backend_new(callbacks);

    if (fingerprint_state->backend) {
        fingerprint_state->backend_available = fingerprint_backend_is_available(fingerprint_state->backend);

        if (fingerprint_state->backend_available) {
            g_debug("Fingerprint backend initialized successfully");
            fingerprint_backend_setup_default(fingerprint_state->backend);
        } else {
            g_warning("Fingerprint backend not available");
        }
    } else {
        g_warning("Failed to initialize fingerprint backend");
    }

    update_enrolled_fingers_from_database();
}

void
fingerprint_cleanup(GDBusConnection *connection)
{
    if (fingerprint_state && fingerprint_state->backend) {
        fingerprint_backend_free(fingerprint_state->backend);
        fingerprint_state->backend = NULL;
    }

    if (fingerprint_introspection_data != NULL) {
        g_dbus_node_info_unref(fingerprint_introspection_data);
        fingerprint_introspection_data = NULL;
    }

    if (fingerprint_state != NULL) {
        if (fingerprint_state->enrolled_fingers != NULL) {
            for (guint i = 0; i < fingerprint_state->enrolled_fingers->len; i++) {
                g_free(g_array_index(fingerprint_state->enrolled_fingers, gchar*, i));
            }

            g_array_free(fingerprint_state->enrolled_fingers, TRUE);
            fingerprint_state->enrolled_fingers = NULL;
        }

        if (fingerprint_state->enrollment_finger_name) {
            g_free(fingerprint_state->enrollment_finger_name);
            fingerprint_state->enrollment_finger_name = NULL;
        }

        g_free(fingerprint_state);
        fingerprint_state = NULL;
    }

    database_cleanup();
}
