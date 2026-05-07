/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef FPD_COMPAT_H
#define FPD_COMPAT_H

#include <glib.h>
#include <stdint.h>

/**
 * Checks if a fingerprint with the specified ID exists in the legacy database
 * @param target_id The fingerprint ID to check
 * @return The fingerprint ID if found, 0 otherwise
 */
uint32_t
check_fingerprint_exists(uint32_t target_id);

/**
 * Gets the name of a fingerprint from the legacy database
 * @param fingerprint_id The fingerprint ID
 * @return A newly allocated string with the description (caller must free), or NULL if not found
 */
gchar*
get_legacy_fingerprint_name(uint32_t fingerprint_id);

#endif /* FPD_COMPAT_H */
