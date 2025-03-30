/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "biomd.h"

typedef struct {
    guint biomd_registration_id;
    guint fingerprint_registration_id;
} BiomService;

BiomService *service_state = NULL;

gboolean
biomd_init(GDBusConnection *connection, GError **error)
{
    service_state = g_new0(BiomService, 1);
    service_state->biomd_registration_id = 0;
    service_state->fingerprint_registration_id = 0;

    manager_init(connection);
    fingerprint_init(connection);

    service_state->biomd_registration_id = manager_register(connection, error);
    if (*error != NULL) {
        g_warning("Registering manager: %s\n", (*error)->message);
        g_free(service_state);
        service_state = NULL;
        return FALSE;
    }

    service_state->fingerprint_registration_id = fingerprint_register(connection, error);
    if (*error != NULL) {
        g_warning("Registering fingerprint: %s\n", (*error)->message);
        g_dbus_connection_unregister_object(connection, service_state->biomd_registration_id);
        g_free(service_state);
        service_state = NULL;
        return FALSE;
    }

    g_bus_own_name_on_connection(
        connection,
        "io.FuriOS.Biomd",
        G_BUS_NAME_OWNER_FLAGS_NONE,
        NULL,
        NULL,
        NULL,
        NULL);
    return TRUE;
}

void
biomd_cleanup(GDBusConnection *connection)
{
    if (service_state == NULL) {
        g_warning("Service state is NULL in biomd_cleanup\n");
        return;
    }

    if (service_state->biomd_registration_id > 0) {
        g_dbus_connection_unregister_object(connection, service_state->biomd_registration_id);
        service_state->biomd_registration_id = 0;
    }

    if (service_state->fingerprint_registration_id > 0) {
        g_dbus_connection_unregister_object(connection, service_state->fingerprint_registration_id);
        service_state->fingerprint_registration_id = 0;
    }

    manager_cleanup(connection);
    fingerprint_cleanup(connection);

    g_free(service_state);
    service_state = NULL;
}

int
main(void)
{
    GMainLoop *loop;
    GError *error = NULL;
    GDBusConnection *connection;

    loop = g_main_loop_new(NULL, FALSE);
    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error != NULL) {
        g_warning("Connecting to system bus: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    if (!biomd_init(connection, &error)) {
        g_warning("Initializing biomd service: %s\n", error->message);
        g_error_free(error);
        g_object_unref(connection);
        return 1;
    }

    g_main_loop_run(loop);

    biomd_cleanup(connection);
    g_object_unref(connection);
    g_main_loop_unref(loop);

    return 0;
}
