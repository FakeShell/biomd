/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "fpd_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t
read_uint32(FILE *file)
{
    uint32_t value = 0;
    uint8_t buffer[4];
    if (fread(buffer, 1, 4, file) != 4)
        return 0;

    // Qt uses big endian by default for QDataStream
    value = ((uint32_t)buffer[0] << 24) |
            ((uint32_t)buffer[1] << 16) |
            ((uint32_t)buffer[2] << 8) |
            ((uint32_t)buffer[3]);
    return value;
}

static gchar*
read_qstring(FILE *file)
{
    uint32_t byte_length = read_uint32(file);
    if (byte_length == 0xFFFFFFFF)
        return g_strdup("");

    uint8_t *utf16_data = g_malloc(byte_length);
    if (!utf16_data) {
        g_warning("Memory allocation failed");
        return NULL;
    }

    size_t bytes_read = fread(utf16_data, 1, byte_length, file);
    if (bytes_read != byte_length) {
        g_warning("Failed to read string data: expected %u bytes, got %zu", byte_length, bytes_read);
        g_free(utf16_data);
        return NULL;
    }

    gchar *utf8_string = NULL;
    if (byte_length > 0) {
        GError *error = NULL;
        utf8_string = g_convert((const gchar*)utf16_data, byte_length,
                                "UTF-8", "UTF-16BE",
                                NULL, NULL, &error);
        if (error) {
            g_warning("Conversion error: %s", error->message);
            g_error_free(error);
            g_free(utf16_data);
            return g_strdup("");
        }
    } else {
        utf8_string = g_strdup("");
    }
    g_free(utf16_data);
    return utf8_string;
}

uint32_t
check_fingerprint_exists(uint32_t target_id)
{
    const gchar *filename = "/var/lib/droidian-fpd/32011/fingerprints.db";
    FILE *file = fopen(filename, "rb");
    if (!file)
        return 0;

    uint32_t item_count = read_uint32(file);
    g_debug("Number of fingerprints in legacy database: %u", item_count);
    uint32_t found_id = 0;
    for (uint32_t i = 0; i < item_count; i++) {
        uint32_t fingerprint_id = read_uint32(file);
        gchar *name = read_qstring(file);
        if (name) {
            if (fingerprint_id == target_id) {
                g_debug("Found legacy fingerprint ID: %u, name: %s", fingerprint_id, name);
                found_id = fingerprint_id;
                g_free(name);
                break;
            }
            g_free(name);
        } else {
            g_warning("Failed to read description for legacy fingerprint ID: %u", fingerprint_id);
        }
    }

    fclose(file);
    return found_id;
}

gchar*
get_legacy_fingerprint_name(uint32_t fingerprint_id)
{
    const gchar *filename = "/var/lib/droidian-fpd/32011/fingerprints.db";
    FILE *file = fopen(filename, "rb");
    if (!file)
        return NULL;

    uint32_t item_count = read_uint32(file);
    gchar *result = NULL;

    for (uint32_t i = 0; i < item_count; i++) {
        uint32_t current_id = read_uint32(file);
        gchar *name = read_qstring(file);

        if (current_id == fingerprint_id && name) {
            result = g_strdup(name);
            g_free(name);
            break;
        }

        if (name)
            g_free(name);
    }

    fclose(file);
    return result;
}
