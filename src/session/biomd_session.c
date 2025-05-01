/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include <glib.h>
#include <gio/gio.h>
#include <batman/wlrdisplay.h>
#include "biomd_enums.h"

typedef struct {
    GDBusConnection *connection;
    GDBusProxy *login1_manager_proxy;
    GDBusProxy *session_proxy;
    GDBusProxy *secrets_proxy;
    GDBusProxy *biomd_proxy;

    guint properties_changed_id;
    guint identified_signal_id;
    guint error_info_changed_id;

    gchar *session_id;
    gboolean in_progress;
} BiometricSession;

static void
setup_dbus_connection(BiometricSession *session);

static gboolean
is_keyring_locked(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value_variant = NULL;
    gboolean is_locked = FALSE;

    if (session->secrets_proxy == NULL) {
        session->secrets_proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SESSION,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets/collection/login",
            "org.freedesktop.DBus.Properties",
            NULL,
            &error
        );

        if (error) {
            g_warning("Failed to create secrets proxy: %s", error->message);
            return FALSE;
        }
    }

    result = g_dbus_proxy_call_sync(
        session->secrets_proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", "org.freedesktop.Secret.Collection", "Locked"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to get property Locked: %s", error->message);
        return FALSE;
    }

    g_variant_get(result, "(v)", &value_variant);
    is_locked = g_variant_get_boolean(value_variant);

    return is_locked;
}

static gint
wlrdisplay_status(void)
{
    gint result = get_wlroots_screen_status();
    return result != 0;
}

static void
send_feedback(const gchar *event)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GDBusProxy) feedbackd_proxy = NULL;
    g_autoptr(GVariant) result = NULL;

    feedbackd_proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SESSION,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "org.sigxcpu.Feedback",
        "/org/sigxcpu/Feedback",
        "org.sigxcpu.Feedback",
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to create feedbackd proxy: %s", error->message);
        return;
    }

    result = g_dbus_proxy_call_sync(
        feedbackd_proxy,
        "TriggerFeedback",
        g_variant_new("(ssa{sv}i)", "biomd-session", event, NULL, -1),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error)
        g_warning("Failed to trigger feedback: %s", error->message);
}

static gchar *
get_session_id(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariantIter) iter = NULL;
    g_autofree gchar *found_session_id = NULL;
    gchar *session_id = NULL;
    guint32 uid;
    gchar *username = NULL;
    gchar *seat = NULL;
    gchar *path = NULL;
    g_autofree gchar *object_path = NULL;
    g_autoptr(GDBusProxy) session_proxy = NULL;
    g_autoptr(GError) proxy_error = NULL;
    g_autoptr(GError) tty_error = NULL;
    g_autoptr(GVariant) tty_prop = NULL;
    g_autoptr(GVariant) tty_variant = NULL;
    const gchar *tty = NULL;

    while (TRUE) {
        error = NULL;

        if (session->login1_manager_proxy == NULL) {
            session->login1_manager_proxy = g_dbus_proxy_new_for_bus_sync(
                G_BUS_TYPE_SYSTEM,
                G_DBUS_PROXY_FLAGS_NONE,
                NULL,
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                NULL,
                &error
            );

            if (error) {
                g_warning("Login1 service not available, retrying in 1 second: %s", error->message);
                sleep(1);
                continue;
            }
        }

        error = NULL;
        reply = g_dbus_proxy_call_sync(
            session->login1_manager_proxy,
            "ListSessions",
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            &error
        );

        if (error) {
            g_warning("D-Bus call failed: %s, retrying in 1 second", error->message);
            sleep(1);
            continue;
        }

        g_variant_get(reply, "(a(susso))", &iter);
        found_session_id = NULL;
        session_id = NULL;
        username = NULL;
        seat = NULL;
        path = NULL;

        while (g_variant_iter_next(iter, "(susso)", &session_id, &uid, &username, &seat, &path)) {
            object_path = g_strdup(path);
            proxy_error = NULL;

            session_proxy = g_dbus_proxy_new_for_bus_sync(
                G_BUS_TYPE_SYSTEM,
                G_DBUS_PROXY_FLAGS_NONE,
                NULL,
                "org.freedesktop.login1",
                object_path,
                "org.freedesktop.DBus.Properties",
                NULL,
                &proxy_error
            );

            if (proxy_error) {
                g_warning("Failed to create session proxy: %s", proxy_error->message);
                g_free(session_id);
                g_free(username);
                g_free(seat);
                continue;
            }

            tty_error = NULL;
            tty_prop = g_dbus_proxy_call_sync(
                session_proxy,
                "Get",
                g_variant_new("(ss)", "org.freedesktop.login1.Session", "TTY"),
                G_DBUS_CALL_FLAGS_NONE,
                -1,
                NULL,
                &tty_error
            );

            if (tty_error) {
                g_warning("Failed to get TTY property: %s", tty_error->message);
                g_free(session_id);
                g_free(username);
                g_free(seat);
                continue;
            }

            tty_variant = NULL;
            g_variant_get(tty_prop, "(v)", &tty_variant);
            tty = g_variant_get_string(tty_variant, NULL);

            if (g_strcmp0(tty, "tty7") == 0) {
                g_debug("Found tty7 session: %s", session_id);
                found_session_id = g_strdup(session_id);
                g_free(session_id);
                g_free(username);
                g_free(seat);
                break;
            }

            g_free(session_id);
            g_free(username);
            g_free(seat);
        }

        if (found_session_id)
            return g_steal_pointer(&found_session_id);

        g_debug("No tty7 session found, retrying in 1 second");
        sleep(1);
    }
}

static gboolean
is_screen_locked(BiometricSession *session)
{
    g_autofree gchar *session_path = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value_variant = NULL;
    gboolean is_locked = FALSE;

    if (session->session_id == NULL)
        session->session_id = get_session_id(session);

    if (session->session_proxy == NULL) {
        session_path = g_strdup_printf("/org/freedesktop/login1/session/%s", session->session_id);

        session->session_proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SYSTEM,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "org.freedesktop.login1",
            session_path,
            "org.freedesktop.DBus.Properties",
            NULL,
            &error
        );

        if (error) {
            g_warning("Failed to create session proxy: %s", error->message);

            g_free(session->session_id);
            session->session_id = get_session_id(session);
            return FALSE;
        }
    }

    result = g_dbus_proxy_call_sync(
        session->session_proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", "org.freedesktop.login1.Session", "LockedHint"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to get property LockedHint: %s", error->message);

        g_debug("Session is invalid when getting LockedHint, reloading session id");
        g_clear_object(&session->session_proxy);
        g_free(session->session_id);

        session->session_id = get_session_id(session);

        if (session->session_id != NULL) {
            g_debug("New session id: %s", session->session_id);

            session_path = g_strdup_printf("/org/freedesktop/login1/session/%s", session->session_id);
            session->session_proxy = g_dbus_proxy_new_for_bus_sync(
                G_BUS_TYPE_SYSTEM,
                G_DBUS_PROXY_FLAGS_NONE,
                NULL,
                "org.freedesktop.login1",
                session_path,
                "org.freedesktop.DBus.Properties",
                NULL,
                &error
            );

            if (error) {
                g_warning("Failed to create session proxy after refresh: %s", error->message);
                return FALSE;
            }

            g_clear_error(&error);
            result = g_dbus_proxy_call_sync(
                session->session_proxy,
                "org.freedesktop.DBus.Properties.Get",
                g_variant_new("(ss)", "org.freedesktop.login1.Session", "LockedHint"),
                G_DBUS_CALL_FLAGS_NONE,
                -1,
                NULL,
                &error
            );

            if (error) {
                g_warning("Failed to get property LockedHint after session refresh: %s", error->message);
                return FALSE;
            }
        } else {
            g_debug("New session id is NULL");
            return FALSE;
        }
    }

    g_variant_get(result, "(v)", &value_variant);
    is_locked = g_variant_get_boolean(value_variant);

    return is_locked;
}

static gint
unlock_session(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GError) retry_error = NULL;
    g_autoptr(GVariant) retry_result = NULL;

    if (session->login1_manager_proxy == NULL) {
        session->login1_manager_proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SYSTEM,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            NULL,
            &error
        );

        if (error) {
            g_warning("Failed to create login1 manager proxy: %s", error->message);
            return 1;
        }
    }

    result = g_dbus_proxy_call_sync(
        session->login1_manager_proxy,
        "UnlockSession",
        g_variant_new("(s)", session->session_id),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("DBus call failed: %s", error->message);

        if (strstr(error->message, "No session") && strstr(error->message, "known")) {
            g_warning("Session ID invalid, re-probing for a new session ID.");
            g_free(session->session_id);
            session->session_id = get_session_id(session);

            retry_result = g_dbus_proxy_call_sync(
                session->login1_manager_proxy,
                "UnlockSession",
                g_variant_new("(s)", session->session_id),
                G_DBUS_CALL_FLAGS_NONE,
                -1,
                NULL,
                &retry_error
            );

            if (retry_error) {
                g_warning("Retrying DBus call failed: %s", retry_error->message);
                return 1;
            }
        } else {
            return 1;
        }
    }

    return 0;
}

static gboolean
biomd_stop_identify(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    gboolean success = FALSE;

    g_debug("Stopping identification process...");

    if (session->biomd_proxy == NULL) {
        g_autoptr(GError) proxy_error = NULL;

        g_debug("Biomd proxy is null, recreating dbus proxy");

        session->biomd_proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SYSTEM,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "io.FuriOS.Biomd",
            "/io/FuriOS/Biomd/Fingerprint",
            "io.FuriOS.Biomd.Fingerprint",
            NULL,
            &proxy_error
        );

        if (proxy_error) {
            g_warning("Failed to create biomd proxy: %s", proxy_error->message);
            return FALSE;
        }
    }

    result = g_dbus_proxy_call_sync(
        session->biomd_proxy,
        "StopIdentify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("StopIdentify method failed: %s", error->message);
        return FALSE;
    }

    g_variant_get(result, "(b)", &success);

    if (success) {
        g_debug("Successfully stopped identify operation");
        session->in_progress = FALSE;
    }

    return success;
}

static gchar **
get_enrolled_fingers(BiometricSession *session, gsize *num_fingers)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) enrolled_fingers_variant = NULL;
    gchar **fingers = NULL;

    if (session->biomd_proxy == NULL) {
        g_autoptr(GError) proxy_error = NULL;

        g_debug("Biomd proxy is null, recreating dbus proxy");

        session->biomd_proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SYSTEM,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "io.FuriOS.Biomd",
            "/io/FuriOS/Biomd/Fingerprint",
            "io.FuriOS.Biomd.Fingerprint",
            NULL,
            &proxy_error
        );

        if (proxy_error) {
            g_warning("Failed to create biomd proxy: %s", proxy_error->message);
            *num_fingers = 0;
            return NULL;
        }
    }

    result = g_dbus_proxy_call_sync(
        session->biomd_proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", "io.FuriOS.Biomd.Fingerprint", "EnrolledFingers"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to get EnrolledFingers property: %s", error->message);
        *num_fingers = 0;
        return NULL;
    }

    g_variant_get(result, "(v)", &enrolled_fingers_variant);
    fingers = g_variant_dup_strv(enrolled_fingers_variant, num_fingers);

    return fingers;
}

static gboolean
has_enrolled_fingers(BiometricSession *session)
{
    gsize num_fingers = 0;
    gchar **fingers = get_enrolled_fingers(session, &num_fingers);
    gboolean has_fingers = (fingers != NULL && num_fingers > 0);

    g_strfreev(fingers);
    return has_fingers;
}

static gboolean
biomd_identify(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    gboolean success = FALSE;

    g_debug("Starting finger identification...");

    if (session->biomd_proxy == NULL) {
        g_autoptr(GError) proxy_error = NULL;

        g_debug("Biomd proxy is null, recreating dbus proxy");

        session->biomd_proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SYSTEM,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "io.FuriOS.Biomd",
            "/io/FuriOS/Biomd/Fingerprint",
            "io.FuriOS.Biomd.Fingerprint",
            NULL,
            &proxy_error
        );

        if (proxy_error) {
            g_warning("Failed to create biomd proxy: %s", proxy_error->message);
            session->in_progress = FALSE;
            return FALSE;
        }
    }

    /* Check if there are any enrolled fingers */
    if (!has_enrolled_fingers(session)) {
        g_debug("No fingerprints enrolled, skipping identification");
        session->in_progress = FALSE;
        return FALSE;
    }

    /* Proceed with identification */
    result = g_dbus_proxy_call_sync(
        session->biomd_proxy,
        "Identify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_warning("Identify method failed: %s", error->message);
        session->in_progress = FALSE;
        return FALSE;
    }

    g_variant_get(result, "(b)", &success);

    if (!success) {
        g_warning("Identify method reported failure");
        session->in_progress = FALSE;
    } else {
        g_debug("Identify started successfully");
    }

    return success;
}

static void
restart_identify(BiometricSession *session)
{
    g_debug("Stopping current identification and starting a new one...");

    if (!has_enrolled_fingers(session)) {
        g_debug("No fingerprints enrolled, skipping identification");
        biomd_stop_identify(session);
        session->in_progress = FALSE;
        return;
    }

    if (biomd_stop_identify(session)) {
        session->in_progress = TRUE;
        biomd_identify(session);
    } else {
        g_warning("Failed to stop identification, not restarting");
    }
}

static void
on_biomd_signal(GDBusConnection *connection, const gchar *sender_name,
                const gchar *object_path, const gchar *interface_name,
                const gchar *signal_name, GVariant *parameters,
                gpointer user_data)
{
    BiometricSession *session = (BiometricSession *)user_data;

    if (g_strcmp0(signal_name, "Identified") == 0) {
        const gchar *finger_name;
        g_variant_get(parameters, "(s)", &finger_name);
        g_debug("Identified finger: %s", finger_name);

        gboolean keyring_locked = is_keyring_locked(session);
        gboolean screen_locked = is_screen_locked(session);

        if (wlrdisplay_status() == 0 && screen_locked && !keyring_locked) {
            send_feedback("button-released");
            unlock_session(session);
        } else {
            if (keyring_locked)
                g_debug("Keyring is still locked, discarding fingerprint request");
            if (!screen_locked)
                g_debug("Screen is unlocked, discarding fingerprint request");
            if (wlrdisplay_status() != 0)
                g_debug("Display is off, discarding fingerprint request");
        }

        session->in_progress = FALSE;
    } else if (g_strcmp0(signal_name, "ErrorInfoChanged") == 0) {
        gint error_code;
        g_variant_get(parameters, "(i)", &error_code);

        const gchar *error_info = "UNKNOWN_ERROR";
        switch (error_code) {
            case ERROR_NONE: error_info = "ERROR_NONE"; break;
            case ERROR_HW_UNAVAILABLE: error_info = "ERROR_HW_UNAVAILABLE"; break;
            case ERROR_UNABLE_TO_PROCESS: error_info = "ERROR_UNABLE_TO_PROCESS"; break;
            case ERROR_TIMEOUT: error_info = "ERROR_TIMEOUT"; break;
            case ERROR_NO_SPACE: error_info = "ERROR_NO_SPACE"; break;
            case ERROR_CANCELED: error_info = "ERROR_CANCELED"; break;
            case ERROR_REMOVE: error_info = "ERROR_REMOVE"; break;
            case ERROR_LOCKOUT: error_info = "ERROR_LOCKOUT"; break;
            case ERROR_GENERAL: error_info = "ERROR_GENERAL"; break;
            case ERROR_FINGER_NOT_RECOGNIZED: error_info = "ERROR_FINGER_NOT_RECOGNIZED"; break;
            default: error_info = "ERROR_UNKNOWN"; break;
        }

        g_debug("Error info: %s", error_info);
        gboolean screen_locked = is_screen_locked(session);

        if (error_code == ERROR_FINGER_NOT_RECOGNIZED && wlrdisplay_status() == 0 && screen_locked) {
            send_feedback("window-close");
        } else if (error_code == ERROR_CANCELED && wlrdisplay_status() != 0) {
            g_debug("Operation canceled and display is off. Stopping attempts.");
            session->in_progress = FALSE;
            biomd_stop_identify(session);
        } else if (error_code == ERROR_CANCELED && wlrdisplay_status() == 0 && screen_locked) {
            g_debug("Fingerprint timed out. Waiting for finger identification again...");
            restart_identify(session);
        } else {
            if (!screen_locked)
                g_debug("Operation canceled and display is unlocked. Stopping attempts.");
            session->in_progress = FALSE;
            biomd_stop_identify(session);
        }
    }
}

static void
start_unlock_attempt(BiometricSession *session)
{
    if (session->in_progress) {
        g_debug("Unlock attempt already in progress, stopping and restarting...");
        restart_identify(session);
        return;
    }

    if (!has_enrolled_fingers(session)) {
        g_debug("No fingerprints enrolled, skipping identification");
        biomd_stop_identify(session);
        session->in_progress = FALSE;
        return;
    }

    session->in_progress = TRUE;
    biomd_identify(session);
}

static void
on_properties_changed(GDBusConnection *connection, const gchar *sender_name,
                      const gchar *object_path, const gchar *interface_name,
                      const gchar *signal_name, GVariant *parameters,
                      gpointer user_data)
{
    BiometricSession *session = (BiometricSession *)user_data;
    const gchar *changed_interface;
    GVariant *changed_properties;
    const gchar **invalidated_properties;
    GVariantIter iter;
    const gchar *key;
    GVariant *value;
    g_autofree gchar *new_session_id = NULL;
    gboolean active;
    gboolean idle_hint;

    g_variant_get(parameters, "(&s@a{sv}^a&s)",
                  &changed_interface,
                  &changed_properties,
                  &invalidated_properties);

    if (g_strcmp0(changed_interface, "org.freedesktop.login1.Session") == 0) {
        g_variant_iter_init(&iter, changed_properties);
        while (g_variant_iter_next(&iter, "{&sv}", &key, &value)) {
            if (g_strcmp0(key, "Active") == 0) {
                active = g_variant_get_boolean(value);
                g_debug("Active state changed: %d", active);

                if (!active) {
                    g_debug("Session became inactive, searching for new active session...");
                    sleep(10);

                    do {
                        new_session_id = get_session_id(session);
                        if (g_strcmp0(new_session_id, session->session_id) == 0) {
                            g_debug("Got the same session ID, waiting 1 second before retrying...");
                            g_free(new_session_id);
                            new_session_id = NULL;
                            sleep(1);
                        }
                    } while (new_session_id && g_strcmp0(new_session_id, session->session_id) == 0);

                    if (new_session_id) {
                        g_debug("Found new session: %s, updating listener...", new_session_id);

                        g_free(session->session_id);
                        session->session_id = g_steal_pointer(&new_session_id);

                        if (session->session_proxy) {
                            g_object_unref(session->session_proxy);
                            session->session_proxy = NULL;
                        }

                        setup_dbus_connection(session);
                    }
                }
            } else if (g_strcmp0(key, "IdleHint") == 0) {
                idle_hint = g_variant_get_boolean(value);
                g_debug("IdleHint changed: %d", idle_hint);

                if (idle_hint) {
                    g_debug("Device became idle, stopping any ongoing identification");
                    biomd_stop_identify(session);
                } else {
                    g_debug("Screen is on, starting unlock attempt");
                    start_unlock_attempt(session);
                }
            }

            g_variant_unref(value);
        }
    }

    g_variant_unref(changed_properties);
}

static void
cleanup_signal_subscriptions(BiometricSession *session)
{
    if (session->connection != NULL) {
        if (session->properties_changed_id > 0) {
            g_debug("Unsubscribing from PropertiesChanged signal (ID: %u)", session->properties_changed_id);
            g_dbus_connection_signal_unsubscribe(session->connection, session->properties_changed_id);
            session->properties_changed_id = 0;
        }

        if (session->identified_signal_id > 0) {
            g_debug("Unsubscribing from Identified signal (ID: %u)", session->identified_signal_id);
            g_dbus_connection_signal_unsubscribe(session->connection, session->identified_signal_id);
            session->identified_signal_id = 0;
        }

        if (session->error_info_changed_id > 0) {
            g_debug("Unsubscribing from ErrorInfoChanged signal (ID: %u)", session->error_info_changed_id);
            g_dbus_connection_signal_unsubscribe(session->connection, session->error_info_changed_id);
            session->error_info_changed_id = 0;
        }
    }
}

static void
setup_dbus_connection(BiometricSession *session)
{
    g_autofree gchar *session_path = NULL;
    g_autofree gchar *subscription_path = NULL;
    g_autoptr(GError) error = NULL;

    cleanup_signal_subscriptions(session);

    session_path = g_strdup_printf("/org/freedesktop/login1/session/%s", session->session_id);

    g_debug("Setting up D-Bus connection for session path: %s", session_path);

    if (session->session_proxy != NULL) {
        g_object_unref(session->session_proxy);
        session->session_proxy = NULL;
    }

    session->session_proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SYSTEM,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "org.freedesktop.login1",
        session_path,
        "org.freedesktop.DBus.Properties",
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to create session proxy: %s", error->message);
        return;
    }

    session->secrets_proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SESSION,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets/collection/login",
        "org.freedesktop.DBus.Properties",
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to create secrets proxy: %s", error->message);
        error = NULL;
    }

    if (session->connection == NULL) {
        session->connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
        if (error) {
            g_warning("Failed to get system bus: %s", error->message);
            return;
        }
    }

    if (session->biomd_proxy != NULL) {
        g_object_unref(session->biomd_proxy);
        session->biomd_proxy = NULL;
    }

    session->biomd_proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SYSTEM,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "io.FuriOS.Biomd",
        "/io/FuriOS/Biomd/Fingerprint",
        "io.FuriOS.Biomd.Fingerprint",
        NULL,
        &error
    );

    if (error) {
        g_warning("Failed to create biomd proxy: %s", error->message);
        error = NULL;
    }

    subscription_path = g_strdup_printf("/org/freedesktop/login1/session/%s", session->session_id);

    session->properties_changed_id = g_dbus_connection_signal_subscribe(
        session->connection,
        "org.freedesktop.login1",
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        subscription_path,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        (GDBusSignalCallback)on_properties_changed,
        session,
        NULL
    );

    g_debug("Subscribed to PropertiesChanged signal for session (ID: %u)", session->properties_changed_id);

    session->identified_signal_id = g_dbus_connection_signal_subscribe(
        session->connection,
        "io.FuriOS.Biomd",
        "io.FuriOS.Biomd.Fingerprint",
        "Identified",
        "/io/FuriOS/Biomd/Fingerprint",
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_signal,
        session,
        NULL
    );

    session->error_info_changed_id = g_dbus_connection_signal_subscribe(
        session->connection,
        "io.FuriOS.Biomd",
        "io.FuriOS.Biomd.Fingerprint",
        "ErrorInfoChanged",
        "/io/FuriOS/Biomd/Fingerprint",
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_biomd_signal,
        session,
        NULL
    );

    g_debug("Connected to session %s for property changes", session->session_id);
}

int
main(int argc, char *argv[])
{
    g_log_set_handler(NULL, G_LOG_LEVEL_MASK, g_log_default_handler, NULL);

    BiometricSession *session = g_new0(BiometricSession, 1);
    session->in_progress = FALSE;

    session->properties_changed_id = 0;
    session->identified_signal_id = 0;
    session->error_info_changed_id = 0;

    session->session_id = get_session_id(session);

    setup_dbus_connection(session);

    g_debug("Initial listener setup complete for session: %s", session->session_id);

    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);

    g_main_loop_unref(loop);
    if (session->login1_manager_proxy)
        g_object_unref(session->login1_manager_proxy);
    if (session->session_proxy)
        g_object_unref(session->session_proxy);
    if (session->secrets_proxy)
        g_object_unref(session->secrets_proxy);
    if (session->biomd_proxy)
        g_object_unref(session->biomd_proxy);

    g_free(session->session_id);
    g_free(session);

    return 0;
}
