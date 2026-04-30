/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "biomd_enums.h"
#include "session_fingerprint.h"
#include "session_face.h"
#include "logind.h"

typedef struct {
    GDBusConnection *connection;
    GDBusProxy *login1_manager_proxy;
    GDBusProxy *session_proxy;
    GDBusProxy *secrets_proxy;

    guint properties_changed_id;

    gchar *session_id;

    gboolean unlock_in_progress;
    gboolean unlocked_this_attempt;

    SessionFingerprint *fingerprint;
    SessionFace *face;

    LogindMonitor *logind;
} BiometricSession;

static void
setup_dbus_connection(BiometricSession *session);

static gboolean
screen_is_on(BiometricSession *session)
{
    LogindScreenState s = logind_monitor_get_screen_state(session->logind);
    return (s != LOGIND_SCREEN_OFF);
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

static gboolean
is_keyring_locked(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value_variant = NULL;
    gboolean is_locked = FALSE;

    if (!session)
        return FALSE;

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
                g_free(path);
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
                g_free(path);
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
                g_free(path);
                break;
            }

            g_free(session_id);
            g_free(username);
            g_free(seat);
            g_free(path);
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

    if (!session)
        return FALSE;

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

static void
unlock_session(BiometricSession *session)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GError) retry_error = NULL;
    g_autoptr(GVariant) retry_result = NULL;

    if (!session)
        return;

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
            return;
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
                return;
            }
        }
    }
}

static gboolean
face_agent_should_be_held(BiometricSession *session)
{
    if (!session)
        return FALSE;

    return !screen_is_on(session) || is_screen_locked(session);
}

static void
update_face_agent_policy(BiometricSession *session)
{
    if (!session || !session->face)
        return;

    session_face_set_lock_relevant(session->face,
                                   face_agent_should_be_held(session));
}

static void
stop_all_biometrics(BiometricSession *session)
{
    if (!session)
        return;

    if (session->fingerprint)
        session_fingerprint_stop(session->fingerprint);

    if (session->face)
        session_face_stop(session->face);

    session->unlock_in_progress = FALSE;
}

static void
maybe_unlock_now(BiometricSession *session)
{
    gboolean keyring_locked = FALSE;
    gboolean screen_locked = FALSE;

    if (!session)
        return;

    if (session->unlocked_this_attempt)
        return;

    keyring_locked = is_keyring_locked(session);
    screen_locked = is_screen_locked(session);

    if (screen_is_on(session) && screen_locked && !keyring_locked) {
        session->unlocked_this_attempt = TRUE;
        send_feedback("button-released");
        unlock_session(session);
        stop_all_biometrics(session);
        update_face_agent_policy(session);
    }
}

static void
on_fingerprint_success(gpointer user_data)
{
    BiometricSession *session = user_data;

    if (!session)
        return;

    g_debug("Fingerprint success");
    maybe_unlock_now(session);
}

static void
on_fingerprint_error(gint error_code, gpointer user_data)
{
    BiometricSession *session = user_data;
    gboolean screen_locked = FALSE;

    if (!session)
        return;

    g_debug("Fingerprint error: %d", error_code);

    screen_locked = is_screen_locked(session);

    if (error_code == ERROR_FINGER_NOT_RECOGNIZED && screen_is_on(session) && screen_locked) {
        send_feedback("window-close");
        return;
    }

    if (error_code == ERROR_CANCELED && !screen_is_on(session)) {
        g_debug("Fingerprint canceled and display off, stopping attempts.");
        stop_all_biometrics(session);
        return;
    }
}

static void
on_face_success(gpointer user_data)
{
    BiometricSession *session = user_data;

    if (!session)
        return;

    g_debug("Face success");
    maybe_unlock_now(session);
}

static void
start_unlock_attempt(BiometricSession *session)
{
    gboolean fp_ok = FALSE;
    gboolean face_ok = FALSE;

    if (!session)
        return;

    if (session->unlock_in_progress) {
        g_debug("Unlock attempt already in progress");
        return;
    }

    session->unlocked_this_attempt = FALSE;
    session->unlock_in_progress = TRUE;

    update_face_agent_policy(session);

    if (session->fingerprint) {
        if (session_fingerprint_is_available(session->fingerprint) &&
            session_fingerprint_has_enrolled(session->fingerprint)) {
            fp_ok = session_fingerprint_start(session->fingerprint);
        } else {
            g_debug("Fingerprint not usable, ignoring for unlock attempt");
        }
    }

    if (session->face) {
        if (session_face_is_available(session->face) &&
            session_face_is_enrolled(session->face)) {
            face_ok = session_face_start(session->face);
        } else {
            g_debug("Face not usable, ignoring for unlock attempt");
        }
    }

    if (!fp_ok && !face_ok) {
        g_debug("No biometric module started");
        session->unlock_in_progress = FALSE;
        session->unlocked_this_attempt = FALSE;
    }
}

static void
cleanup_signal_subscriptions(BiometricSession *session)
{
    if (!session)
        return;

    if (session->connection != NULL) {
        if (session->properties_changed_id > 0) {
            g_debug("Unsubscribing from PropertiesChanged signal (ID: %u)", session->properties_changed_id);
            g_dbus_connection_signal_unsubscribe(session->connection, session->properties_changed_id);
            session->properties_changed_id = 0;
        }
    }
}

static void
on_properties_changed(GDBusConnection *connection,
                      const gchar *sender_name,
                      const gchar *object_path,
                      const gchar *interface_name,
                      const gchar *signal_name,
                      GVariant *parameters,
                      gpointer user_data)
{
    BiometricSession *session = user_data;
    const gchar *changed_interface = NULL;
    GVariant *changed_properties = NULL;
    g_autofree const gchar **invalidated_properties = NULL;
    GVariantIter iter;
    const gchar *key = NULL;
    GVariant *value = NULL;
    g_autofree gchar *new_session_id = NULL;
    gboolean active = FALSE;
    gboolean idle_hint = FALSE;

    (void)connection;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;
    (void)signal_name;

    if (!session)
        return;

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

                update_face_agent_policy(session);

                if (!active) {
                    g_debug("Session became inactive, searching for new active session...");
                    stop_all_biometrics(session);
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
                        update_face_agent_policy(session);
                    }
                }
            } else if (g_strcmp0(key, "IdleHint") == 0) {
                idle_hint = g_variant_get_boolean(value);
                g_debug("IdleHint changed: %d", idle_hint);

                update_face_agent_policy(session);

                if (idle_hint) {
                    g_debug("Device became idle, stopping any ongoing identification");
                    stop_all_biometrics(session);
                } else {
                    g_debug("Device active, starting unlock attempt");
                    start_unlock_attempt(session);
                }

                update_face_agent_policy(session);
            }

            g_variant_unref(value);
        }
    }

    g_variant_unref(changed_properties);
}

static void
setup_dbus_connection(BiometricSession *session)
{
    g_autofree gchar *session_path = NULL;
    g_autofree gchar *subscription_path = NULL;
    g_autoptr(GError) error = NULL;

    if (!session)
        return;

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

    if (session->secrets_proxy != NULL) {
        g_object_unref(session->secrets_proxy);
        session->secrets_proxy = NULL;
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

    if (session->fingerprint == NULL) {
        session->fingerprint = session_fingerprint_new(session->connection,
                                                       on_fingerprint_success,
                                                       on_fingerprint_error,
                                                       session);
        if (session->fingerprint == NULL)
            g_warning("Failed to create fingerprint helper");
    }

    if (session->face == NULL) {
        session->face = session_face_new(session->connection,
                                         on_face_success,
                                         session);
        if (session->face == NULL)
            g_warning("Failed to create face helper");

        update_face_agent_policy(session);
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
    g_debug("Connected to session %s for property changes", session->session_id);

    update_face_agent_policy(session);
}

int
main(void)
{
    GMainLoop *loop = NULL;
    BiometricSession *session = NULL;

    session = g_new0(BiometricSession, 1);

    session->unlock_in_progress = FALSE;
    session->unlocked_this_attempt = FALSE;

    session->properties_changed_id = 0;

    session->logind = logind_monitor_new(NULL, NULL);

    session->session_id = get_session_id(session);

    setup_dbus_connection(session);

    g_debug("Initial listener setup complete for session: %s", session->session_id);

    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);

    g_main_loop_unref(loop);

    stop_all_biometrics(session);

    if (session->fingerprint)
        session_fingerprint_free(session->fingerprint);

    if (session->face)
        session_face_free(session->face);

    if (session->login1_manager_proxy)
        g_object_unref(session->login1_manager_proxy);

    if (session->session_proxy)
        g_object_unref(session->session_proxy);

    if (session->secrets_proxy)
        g_object_unref(session->secrets_proxy);

    if (session->connection)
        g_object_unref(session->connection);

    if (session->logind)
        logind_monitor_free(session->logind);

    g_free(session->session_id);
    g_free(session);

    return 0;
}
