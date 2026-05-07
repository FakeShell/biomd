/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef MANAGER_H
#define MANAGER_H
#include "biomd.h"

/**
 * Initialize the manager service
 * @param connection The DBus connection
 */
void
manager_init(GDBusConnection *connection);

/**
 * Clean up the manager service resources
 * @param connection The DBus connection
 */
void
manager_cleanup(GDBusConnection *connection);

/**
 * Register the manager object on DBus
 * @param connection The DBus connection
 * @param error Return location for error
 * @return Registration ID or 0 if registration failed
 */
guint
manager_register(GDBusConnection *connection, GError **error);

#endif /* MANAGER_H */
