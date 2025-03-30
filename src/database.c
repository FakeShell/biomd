/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <glib.h>
#include <sys/stat.h>
#include <sys/types.h>

static sqlite3 *db = NULL;

gboolean
database_init(void)
{
    struct stat st = {0};
    if (stat(DB_DIR, &st) == -1) {
        if (mkdir(DB_DIR, 0700) == -1) {
            g_warning("Failed to create database directory %s", DB_DIR);
            return FALSE;
        }
    }

    int rc = sqlite3_open(DB_PATH, &db);
    if (rc != SQLITE_OK) {
        g_warning("Cannot open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        db = NULL;
        return FALSE;
    }

    const char *sql =
        "CREATE TABLE IF NOT EXISTS fingerprints ("
        "finger_id INTEGER PRIMARY KEY,"
        "finger_name TEXT"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("SQL error: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        db = NULL;
        return FALSE;
    }

    return TRUE;
}

void
database_cleanup(void)
{
    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
    }
}

gboolean
database_add_fingerprint(guint32 finger_id, const gchar *finger_name)
{
    if (db == NULL) {
        g_warning("Database not initialized");
        return FALSE;
    }

    gchar *name_to_use;
    gboolean free_name = FALSE;

    if (finger_name != NULL) {
        name_to_use = (gchar*)finger_name;
    } else {
        name_to_use = g_strdup_printf("finger_%u", finger_id);
        free_name = TRUE;
    }

    const char *sql = "INSERT OR REPLACE INTO fingerprints (finger_id, finger_name) VALUES (?, ?);";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        if (free_name)
            g_free(name_to_use);

        return FALSE;
    }

    sqlite3_bind_int(stmt, 1, finger_id);
    sqlite3_bind_text(stmt, 2, name_to_use, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (free_name)
        g_free(name_to_use);

    return (rc == SQLITE_DONE);
}

gboolean
database_remove_fingerprint(guint32 finger_id)
{
    if (db == NULL) {
        g_warning("Database not initialized");
        return FALSE;
    }

    const char *sql = "DELETE FROM fingerprints WHERE finger_id = ?;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return FALSE;
    }

    sqlite3_bind_int(stmt, 1, finger_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE);
}

gchar*
database_get_finger_name(guint32 finger_id)
{
    if (db == NULL) {
        g_warning("Database not initialized");
        return NULL;
    }

    const char *sql = "SELECT finger_name FROM fingerprints WHERE finger_id = ?;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, finger_id);

    gchar *finger_name = NULL;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *name = (const char*)sqlite3_column_text(stmt, 0);
        if (name)
            finger_name = g_strdup(name);
        else
            finger_name = g_strdup_printf("finger_%u", finger_id);
    }

    sqlite3_finalize(stmt);
    return finger_name;
}

guint32
database_get_finger_id(const gchar *finger_name)
{
    if (db == NULL || finger_name == NULL) {
        g_warning("Database not initialized or NULL finger name");
        return 0;
    }

    const char *sql = "SELECT finger_id FROM fingerprints WHERE finger_name = ?;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, finger_name, -1, SQLITE_TRANSIENT);

    guint32 finger_id = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        finger_id = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return finger_id;
}

GArray*
database_get_all_fingerprints(void)
{
    GArray *fingerprints = g_array_new(TRUE, TRUE, sizeof(gchar*));

    if (db == NULL) {
        g_warning("Database not initialized");
        return fingerprints;
    }

    const char *sql = "SELECT finger_id, finger_name FROM fingerprints;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return fingerprints;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        guint32 finger_id = sqlite3_column_int(stmt, 0);
        const char *name = (const char*)sqlite3_column_text(stmt, 1);
        gchar *finger_name;

        if (name != NULL)
            finger_name = g_strdup(name);
        else
            finger_name = g_strdup_printf("finger_%u", finger_id);

        g_array_append_val(fingerprints, finger_name);
    }

    sqlite3_finalize(stmt);
    return fingerprints;
}

gboolean
database_is_valid_finger_name(const gchar *finger_name)
{
    if (finger_name == NULL)
        return FALSE;
    if (g_str_has_prefix(finger_name, "finger_"))
        return TRUE;

    for (int i = 0; valid_finger_names[i] != NULL; i++) {
        if (g_strcmp0(finger_name, valid_finger_names[i]) == 0)
            return TRUE;
    }

    return FALSE;
}

gchar*
database_get_suggested_finger_name(void)
{
    if (db == NULL) {
        g_warning("Database not initialized");
        return NULL;
    }

    const char *sql = "SELECT finger_name FROM fingerprints;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return NULL;
    }

    GHashTable *used_names = g_hash_table_new(g_str_hash, g_str_equal);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name = (const char*)sqlite3_column_text(stmt, 0);
        if (name != NULL && !g_str_has_prefix(name, "finger_"))
            g_hash_table_insert(used_names, (gpointer)name, (gpointer)1);
    }

    sqlite3_finalize(stmt);

    gchar *suggestion = NULL;
    for (int i = 0; valid_finger_names[i] != NULL; i++) {
        if (!g_hash_table_contains(used_names, valid_finger_names[i])) {
            suggestion = g_strdup(valid_finger_names[i]);
            break;
        }
    }

    g_hash_table_destroy(used_names);
    return suggestion;
}

gboolean
database_set_finger_name(guint32 finger_id, const gchar *finger_name)
{
    if (db == NULL) {
        g_warning("Database not initialized");
        return FALSE;
    }

    if (finger_name == NULL) {
        g_warning("NULL finger name provided");
        return FALSE;
    }

    gboolean exists = FALSE;
    const char *check_sql = "SELECT 1 FROM fingerprints WHERE finger_id = ?;";
    sqlite3_stmt *check_stmt;

    int rc = sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return FALSE;
    }

    sqlite3_bind_int(check_stmt, 1, finger_id);
    rc = sqlite3_step(check_stmt);
    exists = (rc == SQLITE_ROW);
    sqlite3_finalize(check_stmt);

    if (!exists)
        return database_add_fingerprint(finger_id, finger_name);

    const char *sql = "UPDATE fingerprints SET finger_name = ? WHERE finger_id = ?;";
    sqlite3_stmt *stmt;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return FALSE;
    }

    sqlite3_bind_text(stmt, 1, finger_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, finger_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE);
}
