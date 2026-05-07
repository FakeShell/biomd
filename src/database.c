/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <glib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define CURRENT_DB_VERSION 2

static sqlite3 *db = NULL;

static int
get_db_version(sqlite3 *db)
{
    int version = 0;
    sqlite3_stmt *stmt;
    const char *sql = "PRAGMA user_version;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare version query: %s", sqlite3_errmsg(db));
        return 0;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW)
        version = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return version;
}

static gboolean
set_db_version(sqlite3 *db, int version)
{
    char *sql = g_strdup_printf("PRAGMA user_version = %d;", version);
    char *err_msg = NULL;

    int rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to set database version: %s", err_msg);
        sqlite3_free(err_msg);
        g_free(sql);
        return FALSE;
    }

    g_free(sql);
    return TRUE;
}

static gboolean
table_exists(sqlite3 *db, const char *table_name)
{
    sqlite3_stmt *stmt;
    gboolean exists = FALSE;
    char *sql = g_strdup_printf("SELECT 1 FROM sqlite_master WHERE type='table' AND name='%s';", table_name);

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            exists = TRUE;
        sqlite3_finalize(stmt);
    }

    g_free(sql);
    return exists;
}

static gboolean
create_initial_schema(sqlite3 *db)
{
    const char *sql =
        "CREATE TABLE IF NOT EXISTS fingerprints ("
        "finger_id INTEGER PRIMARY KEY,"
        "finger_name TEXT"
        ");";

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("SQL error creating initial schema: %s", err_msg);
        sqlite3_free(err_msg);
        return FALSE;
    }

    return set_db_version(db, 1);
}

static gboolean
migrate_v1_to_v2(sqlite3 *db)
{
    char *err_msg = NULL;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to begin transaction: %s", err_msg);
        sqlite3_free(err_msg);
        return FALSE;
    }

    const char *create_sql =
        "CREATE TABLE fingerprints_new ("
        "finger_id INTEGER PRIMARY KEY,"
        "finger_name TEXT,"
        "enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(db, create_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to create new table: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return FALSE;
    }

    const char *copy_sql =
        "INSERT INTO fingerprints_new (finger_id, finger_name) "
        "SELECT finger_id, finger_name FROM fingerprints;";

    rc = sqlite3_exec(db, copy_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to copy data: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return FALSE;
    }

    rc = sqlite3_exec(db, "DROP TABLE fingerprints;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to drop old table: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return FALSE;
    }

    rc = sqlite3_exec(db, "ALTER TABLE fingerprints_new RENAME TO fingerprints;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to rename table: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return FALSE;
    }

    rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to commit transaction: %s", err_msg);
        sqlite3_free(err_msg);
        return FALSE;
    }

    return set_db_version(db, 2);
}

static gboolean
handle_existing_database(sqlite3 *db)
{
    g_debug("Detected existing database with no version");

    if (!table_exists(db, "fingerprints")) {
        g_debug("No fingerprints table, creating new schema");
        return create_initial_schema(db);
    }

    sqlite3_stmt *stmt;
    gboolean has_timestamp = FALSE;
    const char *sql = "PRAGMA table_info(fingerprints);";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to get table info: %s", sqlite3_errmsg(db));
        return FALSE;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *column_name = (const char*)sqlite3_column_text(stmt, 1);
        if (g_strcmp0(column_name, "enrolled_at") == 0) {
            has_timestamp = TRUE;
            break;
        }
    }

    sqlite3_finalize(stmt);

    if (has_timestamp) {
        g_debug("Database already has timestamp column, setting version to 2");
        return set_db_version(db, 2);
    } else {
        g_debug("Migrating existing database without version to version 2");
        return migrate_v1_to_v2(db);
    }
}

static gboolean
run_migrations(sqlite3 *db)
{
    int db_version = get_db_version(db);
    g_debug("Current database version: %d", db_version);

    if (db_version == 0 && table_exists(db, "fingerprints"))
        return handle_existing_database(db);

    if (db_version == 0) {
        if (!create_initial_schema(db))
            return FALSE;
        db_version = 1;
    }

    if (db_version < CURRENT_DB_VERSION) {
        if (db_version == 1) {
            g_debug("Migrating database from version 1 to 2");
            if (!migrate_v1_to_v2(db))
                return FALSE;
            db_version = 2;
        }
    }

    return (db_version == CURRENT_DB_VERSION);
}

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

    char *err_msg = NULL;
    rc = sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        g_warning("Failed to enable foreign keys: %s", err_msg);
        sqlite3_free(err_msg);
    }

    if (!run_migrations(db)) {
        g_warning("Failed to migrate database to latest version");
        sqlite3_close(db);
        db = NULL;
        return FALSE;
    }

    g_debug("Database initialized successfully (version %d)", get_db_version(db));
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

    const char *sql = "INSERT OR REPLACE INTO fingerprints (finger_id, finger_name) "
                      "VALUES (?, ?);";
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

time_t
database_get_finger_enrolled_time(guint32 finger_id)
{
    if (db == NULL) {
        g_warning("Database not initialized");
        return 0;
    }

    const char *sql = "SELECT strftime('%s', enrolled_at) FROM fingerprints WHERE finger_id = ?;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_int(stmt, 1, finger_id);

    time_t enrolled_time = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        enrolled_time = sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return enrolled_time;
}

GArray*
database_get_all_fingerprints(void)
{
    GArray *fingerprints = g_array_new(TRUE, TRUE, sizeof(gchar*));

    if (db == NULL) {
        g_warning("Database not initialized");
        return fingerprints;
    }

    const char *sql = "SELECT finger_id, finger_name FROM fingerprints ORDER BY datetime(enrolled_at);";
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
