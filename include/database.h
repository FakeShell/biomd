/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef DATABASE_H
#define DATABASE_H

#include <glib.h>
#include <sqlite3.h>
#include <time.h>

#define DB_DIR "/var/lib/biomd"
#define DB_PATH "/var/lib/biomd/fingerprints.db"

static gchar *valid_finger_names[] = {
    "right-index-finger",
    "left-index-finger",
    "right-thumb",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
    "left-thumb",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    NULL
};

/**
 * Initialize the fingerprint database
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
database_init(void);

/**
 * Clean up database resources
 */
void
database_cleanup(void);

/**
 * Add a fingerprint to the database
 * @param finger_id The numeric fingerprint ID
 * @param finger_name Optional human-readable name (can be NULL)
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
database_add_fingerprint(guint32 finger_id, const gchar *finger_name);

/**
 * Remove a fingerprint from the database
 * @param finger_id The numeric fingerprint ID
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
database_remove_fingerprint(guint32 finger_id);

/**
 * Get the human-readable name for a fingerprint ID
 * @param finger_id The numeric fingerprint ID
 * @return The finger name (caller must free) or NULL if not found
 */
gchar*
database_get_finger_name(guint32 finger_id);

/**
 * Get the finger ID from a human-readable name
 * @param finger_name The human-readable finger name
 * @return The finger ID or 0 if not found
 */
guint32
database_get_finger_id(const gchar *finger_name);

/**
 * Get the enrollment timestamp for a fingerprint
 * @param finger_id The numeric fingerprint ID
 * @return The timestamp or 0 if not found
 */
time_t
database_get_finger_enrolled_time(guint32 finger_id);

/**
 * Get all enrolled fingerprints
 * @return GArray of gchar* finger names (caller must free array and strings)
 */
GArray*
database_get_all_fingerprints(void);

/**
 * Check if a finger name is valid from the predefined list
 * @param finger_name The finger name to check
 * @return TRUE if valid, FALSE otherwise
 */
gboolean
database_is_valid_finger_name(const gchar *finger_name);

/**
 * Get a suggested finger name that hasn't been used yet
 * @return A suggested finger name (caller must free) or NULL if all are used
 */
gchar*
database_get_suggested_finger_name(void);

/**
 * Set a human-readable name for a fingerprint
 * @param finger_id The numeric fingerprint ID
 * @param finger_name The human-readable name
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
database_set_finger_name(guint32 finger_id, const gchar *finger_name);

#endif /* DATABASE_H */
