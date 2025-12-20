/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "manager.h"
#include "introspect.h"

typedef struct {
    GDBusNodeInfo *biomd_introspection_data;
} BiomManager;

BiomManager *manager_state = NULL;

static void
handle_biomd_method_call(GDBusConnection *connection,
                         const gchar *sender,
                         const gchar *object_path,
                         const gchar *interface_name,
                         const gchar *method_name,
                         GVariant *parameters,
                         GDBusMethodInvocation *invocation,
                         gpointer user_data)
{
    if (g_strcmp0(method_name, "GetSupportedModules") == 0) {
        const gchar *modules[] = {"Fingerprint", "Face", NULL};
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(^as)", modules));
    } else if (g_strcmp0(method_name, "Ping") == 0) {
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
    } else {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_UNKNOWN_METHOD,
                                              "Unknown method: %s", method_name);
    }
}

static GVariant *
handle_biomd_get_property(GDBusConnection *connection,
                          const gchar *sender,
                          const gchar *object_path,
                          const gchar *interface_name,
                          const gchar *property_name,
                          GError **error,
                          gpointer user_data)
{
    g_set_error(error,
                G_DBUS_ERROR,
                G_DBUS_ERROR_UNKNOWN_PROPERTY,
                "Unknown property: %s", property_name);
    return NULL;
}

static gboolean
handle_biomd_set_property(GDBusConnection *connection,
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

static const GDBusInterfaceVTable biomd_interface_vtable = {
    handle_biomd_method_call,
    handle_biomd_get_property,
    handle_biomd_set_property
};

void
manager_init(GDBusConnection *connection)
{
    GError *error = NULL;

    manager_state = g_new0(BiomManager, 1);

    manager_state->biomd_introspection_data = g_dbus_node_info_new_for_xml(biomd_introspection_xml, &error);
    if (error != NULL) {
        g_warning("Parsing Biomd introspection XML: %s\n", error->message);
        g_error_free(error);
    }
}

void
manager_cleanup(GDBusConnection *connection)
{
    if (manager_state == NULL) {
        g_warning("Manager state is NULL in manager_cleanup\n");
        return;
    }

    if (manager_state->biomd_introspection_data != NULL) {
        g_dbus_node_info_unref(manager_state->biomd_introspection_data);
        manager_state->biomd_introspection_data = NULL;
    }

    g_free(manager_state);
    manager_state = NULL;
}

guint
manager_register(GDBusConnection *connection, GError **error)
{
    if (manager_state == NULL) {
        g_warning("Manager state is NULL in manager_register\n");
        g_set_error(error,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_FAILED,
                    "Manager state not initialized");
        return 0;
    }

    if (manager_state->biomd_introspection_data == NULL) {
        g_warning("Biomd introspection data not initialized\n");
        g_set_error(error,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_FAILED,
                    "Biomd introspection data not initialized");
        return 0;
    }

    return g_dbus_connection_register_object(
        connection,
        "/io/FuriOS/Biomd",
        manager_state->biomd_introspection_data->interfaces[0],
        &biomd_interface_vtable,
        NULL,
        NULL,
        error);
}
