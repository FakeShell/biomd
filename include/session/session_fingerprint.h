/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef SESSION_FINGERPRINT_H
#define SESSION_FINGERPRINT_H

#include <gio/gio.h>

#include "biomd_enums.h"

typedef struct _SessionFingerprint SessionFingerprint;

typedef void (*SessionFingerprintSuccessCb)(gpointer user_data);
typedef void (*SessionFingerprintErrorCb)(gint error_code, gpointer user_data);

/**
 * Create a fingerprint session helper.
 * @param system_bus A system-bus connection
 * @param success_cb Called when an Identified signal is received
 * @param error_cb Called when ErrorInfoChanged signal is received
 * @param user_data Passed to callbacks
 * @return A new SessionFingerprint instance or NULL on failure
 */
SessionFingerprint *
session_fingerprint_new(GDBusConnection *system_bus,
                        SessionFingerprintSuccessCb success_cb,
                        SessionFingerprintErrorCb error_cb,
                        gpointer user_data);

/**
 * Free a fingerprint helper.
 * @param fp Fingerprint helper
 */
void
session_fingerprint_free(SessionFingerprint *fp);

/**
 * Check if fingerprint hardware is available.
 * @param fp Fingerprint helper
 * @return TRUE if available, FALSE otherwise
 */
gboolean
session_fingerprint_is_available(SessionFingerprint *fp);

/**
 * Check if any fingers are enrolled.
 * @param fp Fingerprint helper
 * @return TRUE if enrolled fingers exist, FALSE otherwise
 */
gboolean
session_fingerprint_has_enrolled(SessionFingerprint *fp);

/**
 * Start identification.
 * @param fp Fingerprint helper
 * @return TRUE if started successfully, FALSE otherwise
 */
gboolean
session_fingerprint_start(SessionFingerprint *fp);

/**
 * Stop identification.
 * @param fp Fingerprint helper
 */
void
session_fingerprint_stop(SessionFingerprint *fp);

#endif /* SESSION_FINGERPRINT_H */
