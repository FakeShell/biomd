/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#define PAM_SM_AUTH
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <gio/gio.h>
#include <glib.h>
#include "biomd_enums.h"

typedef struct {
    pam_handle_t *pamh;
    GDBusConnection *connection;
    GDBusProxy *biomd_proxy;
    GDBusProxy *biomd_fingerprint_proxy;
    int debug;

    /* 0 = pending, 1 = success, -1 = failure */
    volatile int auth_status;
    volatile char *finger_name;
} BiometricAuth;

static BiometricAuth *g_auth = NULL;

static int
is_flag_set(const char **flags, int argc, const char *flag)
{
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(flags[i], flag) == 0)
            return 1;
    }

    return 0;
}

static GVariant *
get_dbus_property(GDBusProxy *proxy, const char *property)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    GVariant *value = NULL;

    result = g_dbus_proxy_call_sync(
        proxy,
        "org.freedesktop.DBus.Properties.Get",
        g_variant_new("(ss)", g_dbus_proxy_get_interface_name(proxy), property),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Failed to get property %s: %s", property, error->message);
        return NULL;
    }

    g_variant_get(result, "(v)", &value);
    return value;
}

static int
get_int_property(GDBusProxy *proxy, const char *property, int default_value)
{
    g_autoptr(GVariant) value = NULL;
    int result = default_value;

    value = get_dbus_property(proxy, property);
    if (value)
        result = g_variant_get_int32(value);

    return result;
}

static gboolean
get_bool_property(GDBusProxy *proxy, const char *property, gboolean default_value)
{
    g_autoptr(GVariant) value = NULL;
    gboolean result = default_value;

    value = get_dbus_property(proxy, property);
    if (value)
        result = g_variant_get_boolean(value);

    return result;
}

static GStrv
get_string_array_property(GDBusProxy *proxy, const char *property)
{
    g_autoptr(GVariant) value = NULL;
    GStrv result = NULL;

    value = get_dbus_property(proxy, property);
    if (value)
        result = g_variant_dup_strv(value, NULL);

    return result;
}

static void
on_identified_signal(GDBusConnection *connection, const gchar *sender_name,
                     const gchar *object_path, const gchar *interface_name,
                     const gchar *signal_name, GVariant *parameters,
                     gpointer user_data)
{
    const gchar *finger_name;

    g_variant_get(parameters, "(s)", &finger_name);

    if (g_auth && g_auth->debug)
        g_debug("Biomd identified finger: %s", finger_name);

    if (g_auth) {
        if (g_auth->finger_name)
            free((void*)g_auth->finger_name);

        g_auth->finger_name = strdup(finger_name);
        g_auth->auth_status = 1;
    }
}

static void
on_error_signal(GDBusConnection *connection, const gchar *sender_name,
                const gchar *object_path, const gchar *interface_name,
                const gchar *signal_name, GVariant *parameters,
                gpointer user_data)
{
    int error_code;
    const gchar *error_info = "UNKNOWN_ERROR";

    g_variant_get(parameters, "(i)", &error_code);

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
    }

    if (g_auth && g_auth->debug)
        g_debug("Biomd error: %s (%d)", error_info, error_code);

    if (error_code != ERROR_FINGER_NOT_RECOGNIZED &&
        error_code != ERROR_TIMEOUT &&
        error_code != ERROR_CANCELED) {
        if (g_auth)
            g_auth->auth_status = -1;
    }
}

static void
on_state_changed(GDBusConnection *connection, const gchar *sender_name,
                 const gchar *object_path, const gchar *interface_name,
                 const gchar *signal_name, GVariant *parameters,
                 gpointer user_data)
{
    int state;

    g_variant_get(parameters, "(i)", &state);

    if (g_auth && g_auth->debug)
        g_debug("Biomd state changed to: %d", state);

    // If state changes to IDLE unexpectedly, it might mean the operation
    // was canceled or timed out without us getting another signal
    if (state == STATE_IDLE && g_auth && g_auth->auth_status == 0)
        g_auth->auth_status = -1;
}

static void
display_prompt(pam_handle_t *pamh, const char *message)
{
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    const struct pam_conv *conv;
    int retval;

    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS || conv == NULL || conv->conv == NULL)
        return;

    msg.msg_style = PAM_TEXT_INFO;
    msg.msg = (char *)message;
    msgp = &msg;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || resp == NULL)
        return;

    if (resp->resp)
        free(resp->resp);

    free(resp);
}

static gboolean
check_biomd_service(BiometricAuth *auth)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    gboolean ping_result = FALSE;

    if (auth->biomd_proxy == NULL) {
        g_debug("Biomd proxy is NULL");
        return FALSE;
    }

    result = g_dbus_proxy_call_sync(
        auth->biomd_proxy,
        "Ping",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Failed to ping Biomd service: %s", error->message);
        return FALSE;
    }

    g_variant_get(result, "(b)", &ping_result);

    if (auth->debug)
        g_debug("Biomd service ping result: %s", ping_result ? "success" : "failure");

    return ping_result;
}

static void
process_events_briefly(void)
{
    GMainContext *context = g_main_context_default();

    while (g_main_context_iteration(context, FALSE)) {
        // Continue processing events
    }
}

static int
init_biomd_proxy(BiometricAuth *auth)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    int state;
    gboolean success;
    gboolean hardware_available;

    g_auth = auth;

    auth->connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) {
        g_debug("Failed to get system bus: %s", error->message);
        g_auth = NULL;
        return PAM_AUTHINFO_UNAVAIL;
    }

    auth->biomd_proxy = g_dbus_proxy_new_sync(
        auth->connection,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "io.FuriOS.Biomd",
        "/io/FuriOS/Biomd",
        "io.FuriOS.Biomd",
        NULL,
        &error
    );

    if (error) {
        g_debug("Failed to create biomd manager proxy: %s", error->message);
        g_object_unref(auth->connection);
        auth->connection = NULL;
        g_auth = NULL;
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (!check_biomd_service(auth)) {
        g_debug("Biomd service is not responding");
        g_object_unref(auth->biomd_proxy);
        auth->biomd_proxy = NULL;
        g_object_unref(auth->connection);
        auth->connection = NULL;
        g_auth = NULL;
        return PAM_AUTHINFO_UNAVAIL;
    }

    auth->biomd_fingerprint_proxy = g_dbus_proxy_new_sync(
        auth->connection,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "io.FuriOS.Biomd",
        "/io/FuriOS/Biomd/Fingerprint",
        "io.FuriOS.Biomd.Fingerprint",
        NULL,
        &error
    );

    if (error) {
        g_debug("Failed to create biomd fingerprint proxy: %s", error->message);
        g_object_unref(auth->biomd_proxy);
        auth->biomd_proxy = NULL;
        g_object_unref(auth->connection);
        auth->connection = NULL;
        g_auth = NULL;
        return PAM_AUTHINFO_UNAVAIL;
    }

    hardware_available = get_bool_property(auth->biomd_fingerprint_proxy, "HardwareAvailable", FALSE);
    if (!hardware_available) {
        g_debug("Fingerprint hardware is not available");
        g_object_unref(auth->biomd_fingerprint_proxy);
        auth->biomd_fingerprint_proxy = NULL;
        g_object_unref(auth->biomd_proxy);
        auth->biomd_proxy = NULL;
        g_object_unref(auth->connection);
        auth->connection = NULL;
        g_auth = NULL;
        return PAM_AUTHINFO_UNAVAIL;
    }

    state = get_int_property(auth->biomd_fingerprint_proxy, "State", -1);
    if (state == STATE_IDENTIFYING) {
        if (auth->debug)
            g_debug("Fingerprint service is already in identifying state, stopping it first");

        error = NULL;
        result = g_dbus_proxy_call_sync(
            auth->biomd_fingerprint_proxy,
            "StopIdentify",
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            &error
        );

        if (error) {
            g_debug("Failed to stop existing identification: %s", error->message);
            g_object_unref(auth->biomd_fingerprint_proxy);
            auth->biomd_fingerprint_proxy = NULL;
            g_object_unref(auth->biomd_proxy);
            auth->biomd_proxy = NULL;
            g_object_unref(auth->connection);
            auth->connection = NULL;
            g_auth = NULL;
            return PAM_AUTHINFO_UNAVAIL;
        }

        g_variant_get(result, "(b)", &success);

        if (!success) {
            g_debug("Failed to stop existing identification");
            g_object_unref(auth->biomd_fingerprint_proxy);
            auth->biomd_fingerprint_proxy = NULL;
            g_object_unref(auth->biomd_proxy);
            auth->biomd_proxy = NULL;
            g_object_unref(auth->connection);
            auth->connection = NULL;
            g_auth = NULL;
            return PAM_AUTHINFO_UNAVAIL;
        }

        usleep(100000);
        process_events_briefly();

        state = get_int_property(auth->biomd_fingerprint_proxy, "State", -1);
    }

    if (state != STATE_IDLE) {
        g_debug("Fingerprint service is not in idle state (current state: %d)", state);
        g_object_unref(auth->biomd_fingerprint_proxy);
        auth->biomd_fingerprint_proxy = NULL;
        g_object_unref(auth->biomd_proxy);
        auth->biomd_proxy = NULL;
        g_object_unref(auth->connection);
        auth->connection = NULL;
        g_auth = NULL;
        return PAM_AUTHINFO_UNAVAIL;
    }

    g_dbus_connection_signal_subscribe(
        auth->connection,
        "io.FuriOS.Biomd",
        "io.FuriOS.Biomd.Fingerprint",
        "Identified",
        "/io/FuriOS/Biomd/Fingerprint",
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_identified_signal,
        NULL,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        auth->connection,
        "io.FuriOS.Biomd",
        "io.FuriOS.Biomd.Fingerprint",
        "ErrorInfoChanged",
        "/io/FuriOS/Biomd/Fingerprint",
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_error_signal,
        NULL,
        NULL
    );

    g_dbus_connection_signal_subscribe(
        auth->connection,
        "io.FuriOS.Biomd",
        "io.FuriOS.Biomd.Fingerprint",
        "StateChanged",
        "/io/FuriOS/Biomd/Fingerprint",
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_state_changed,
        NULL,
        NULL
    );

    return PAM_SUCCESS;
}

static void
cleanup_biomd(BiometricAuth *auth)
{
    g_autoptr(GVariant) result = NULL;
    int state;

    if (auth->biomd_fingerprint_proxy) {
        state = get_int_property(auth->biomd_fingerprint_proxy, "State", -1);
        if (state == STATE_IDENTIFYING) {
            result = g_dbus_proxy_call_sync(
                auth->biomd_fingerprint_proxy,
                "StopIdentify",
                NULL,
                G_DBUS_CALL_FLAGS_NONE,
                -1,
                NULL,
                NULL
            );
        }

        g_object_unref(auth->biomd_fingerprint_proxy);
        auth->biomd_fingerprint_proxy = NULL;
    }

    if (auth->biomd_proxy) {
        g_object_unref(auth->biomd_proxy);
        auth->biomd_proxy = NULL;
    }

    if (auth->connection) {
        g_object_unref(auth->connection);
        auth->connection = NULL;
    }

    if (auth->finger_name) {
        free((void*)auth->finger_name);
        auth->finger_name = NULL;
    }

    g_auth = NULL;
}

static gboolean
user_has_fingerprints(BiometricAuth *auth)
{
    g_autofree GStrv enrolled_fingers = NULL;
    gboolean has_prints = FALSE;
    int i;

    enrolled_fingers = get_string_array_property(auth->biomd_fingerprint_proxy, "EnrolledFingers");

    if (enrolled_fingers) {
        has_prints = (g_strv_length(enrolled_fingers) > 0);

        if (auth->debug) {
            if (has_prints) {
                g_debug("User has enrolled fingerprints:");
                for (i = 0; enrolled_fingers[i]; i++) {
                    g_debug("  - %s", enrolled_fingers[i]);
                }
            } else {
                g_debug("User has no enrolled fingerprints");
            }
        }
    } else {
        g_debug("Failed to get enrolled fingers");
    }

    return has_prints;
}

static int
start_identification(BiometricAuth *auth)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) result = NULL;
    gboolean success = FALSE;
    int state;

    auth->auth_status = 0;

    result = g_dbus_proxy_call_sync(
        auth->biomd_fingerprint_proxy,
        "Identify",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_debug("Failed to start identification: %s", error->message);
        return PAM_AUTH_ERR;
    }

    g_variant_get(result, "(b)", &success);

    if (!success) {
        g_debug("Identify method reported failure");
        return PAM_AUTH_ERR;
    }

    state = get_int_property(auth->biomd_fingerprint_proxy, "State", -1);
    if (state != STATE_IDENTIFYING) {
        g_debug("Failed to transition to identifying state, current state: %d", state);
        return PAM_AUTH_ERR;
    }

    if (auth->debug)
        g_debug("Identify started successfully");

    return PAM_SUCCESS;
}

static int
wait_for_auth_result(BiometricAuth *auth, int timeout_seconds) {
    time_t start_time = time(NULL);
    int retval = PAM_AUTH_ERR;

    /* not my favorite but we can't return early it must block */
    while (auth->auth_status == 0 && (time(NULL) - start_time) < timeout_seconds) {
        process_events_briefly();

        usleep(100000);
    }

    if (auth->auth_status == 1) {
        if (auth->debug)
            g_debug("Authentication succeeded with finger: %s",
                    auth->finger_name ? auth->finger_name : "unknown");

        retval = PAM_SUCCESS;
    } else if (auth->auth_status == 0) {
        if (auth->debug)
            g_debug("Authentication timed out after %d seconds", timeout_seconds);

        retval = PAM_AUTH_ERR;
    } else {
        if (auth->debug)
            g_debug("Authentication failed");

        retval = PAM_AUTH_ERR;
    }

    return retval;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int retval;
    const char *username;
    BiometricAuth auth = {0};
    int timeout = 30;

    auth.debug = is_flag_set(argv, argc, "debug");

    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        g_debug("Could not get username: %s", pam_strerror(pamh, retval));
        return retval;
    }

    auth.pamh = pamh;
    auth.auth_status = 0;
    auth.finger_name = NULL;

    retval = init_biomd_proxy(&auth);
    if (retval != PAM_SUCCESS) {
        g_debug("Failed to initialize Biomd proxy");
        return retval;
    }

    if (!user_has_fingerprints(&auth)) {
        if (auth.debug)
            g_debug("User has no enrolled fingerprints, skipping fingerprint auth");

        cleanup_biomd(&auth);
        return PAM_AUTHINFO_UNAVAIL;
    }

    display_prompt(pamh, "Scan your finger to authenticate...");

    retval = start_identification(&auth);
    if (retval != PAM_SUCCESS) {
        g_debug("Failed to start identification");
        cleanup_biomd(&auth);
        return retval;
    }

    retval = wait_for_auth_result(&auth, timeout);

    cleanup_biomd(&auth);

    return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_biomd_modstruct = {
    "pam_biomd",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
