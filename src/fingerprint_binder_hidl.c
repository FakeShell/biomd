/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "fingerprint_binder_hidl.h"
#include <stdio.h>
#include <gbinder.h>
#include <stdlib.h>
#include <stdint.h>
#include <glib.h>
#include <sys/stat.h>
#include <unistd.h>

#define FP_IFACE_PREFIX                  "android.hardware.biometrics.fingerprint@"
#define FP_IFACE(x)                      FP_IFACE_PREFIX "2.1::" x
#define FP                               FP_IFACE("IBiometricsFingerprint")
#define FP_CLIENT_CALLBACK               FP_IFACE("IBiometricsFingerprintClientCallback")
#define FP_SERVICE                       FP "/default"

#define GK_IFACE_PREFIX                  "android.hardware.gatekeeper@"
#define GK_IFACE(x)                      GK_IFACE_PREFIX "1.0::" x
#define GK                               GK_IFACE("IGatekeeper")
#define GK_SERVICE                       GK "/default"

#define HWBINDER_DEVICE                  "/dev/hwbinder"

enum FingerprintFunctions {
    /* android.hardware.biometrics.fingerprint@2.1::IBiometricsFingerprint */
    FP_SET_NOTIFY = 1,
    FP_PRE_ENROLL = 2,
    FP_ENROLL = 3,
    FP_POST_ENROLL = 4,
    FP_GET_AUTHENTICATOR_ID = 5,
    FP_CANCEL = 6,
    FP_ENUMERATE = 7,
    FP_REMOVE = 8,
    FP_SET_ACTIVE_GROUP = 9,
    FP_AUTHENTICATE = 10,
};

enum FingerprintCallbacks {
    /* android.hardware.biometrics.fingerprint@2.1::IBiometricsFingerprintClientCallback */
    FP_CALLBACK_ENROLL_RESULT = 1,
    FP_CALLBACK_ACQUIRED = 2,
    FP_CALLBACK_AUTHENTICATED = 3,
    FP_CALLBACK_ERROR = 4,
    FP_CALLBACK_REMOVED = 5,
    FP_CALLBACK_ENUMERATE = 6,
};

enum GatekeeperFunctions {
    /* android.hardware.gatekeeper@1.0::IGatekeeper */
    GK_ENROLL = 1,
    GK_VERIFY = 2,
    GK_DELETE_USER = 3,
    GK_DELETE_ALL_USERS = 4,
};

typedef enum {
    FINGERPRINT_STATUS_UNKNOWN = 1,
    FINGERPRINT_STATUS_OK = 0,
    FINGERPRINT_STATUS_ENOENT = -2,
    FINGERPRINT_STATUS_EINTR = -4,
    FINGERPRINT_STATUS_EIO = -5,
    FINGERPRINT_STATUS_EAGAIN = -11,
    FINGERPRINT_STATUS_ENOMEM = -12,
    FINGERPRINT_STATUS_EACCES = -13,
    FINGERPRINT_STATUS_EFAULT = -14,
    FINGERPRINT_STATUS_EBUSY = -16,
    FINGERPRINT_STATUS_EINVAL = -22,
    FINGERPRINT_STATUS_ENOSPC = -28,
    FINGERPRINT_STATUS_ETIMEDOUT = -110,
} RequestStatus;

typedef struct gatekeeper_response {
    guint32 code GBINDER_ALIGNED(4);
    guint32 timeout GBINDER_ALIGNED(4);
    GBinderHidlVec data GBINDER_ALIGNED(8);
} GatekeeperResponse;

struct _BiomFingerprintHidl {
    GBinderClient* fingerprint_client;
    GBinderRemoteObject* fingerprint_remote;
    GBinderLocalObject* fingerprint_callback;
    GBinderClient* gatekeeper_client;
    GBinderRemoteObject* gatekeeper_remote;
    GBinderServiceManager* sm;

    guint64 device_id;
    gboolean available;

    FingerprintHidlCallbacks callbacks;
    gpointer user_data;
};

static const gchar*
fingerprint_hidl_error_to_string(FingerprintError error)
{
    switch (error) {
        case FINGERPRINT_ERROR_NO_ERROR: return "No error";
        case FINGERPRINT_ERROR_HW_UNAVAILABLE: return "Hardware unavailable";
        case FINGERPRINT_ERROR_UNABLE_TO_PROCESS: return "Unable to process";
        case FINGERPRINT_ERROR_TIMEOUT: return "Timeout";
        case FINGERPRINT_ERROR_NO_SPACE: return "No space";
        case FINGERPRINT_ERROR_CANCELED: return "Canceled";
        case FINGERPRINT_ERROR_UNABLE_TO_REMOVE: return "Unable to remove";
        case FINGERPRINT_ERROR_LOCKOUT: return "Lockout";
        case FINGERPRINT_ERROR_VENDOR: return "Vendor specific error";
        default: return "Unknown error";
    }
}

static const gchar*
fingerprint_hidl_acquired_to_string(FingerprintAcquiredInfo info)
{
    switch (info) {
        case FINGERPRINT_ACQUIRED_GOOD: return "Good";
        case FINGERPRINT_ACQUIRED_PARTIAL: return "Partial";
        case FINGERPRINT_ACQUIRED_INSUFFICIENT: return "Insufficient";
        case FINGERPRINT_ACQUIRED_IMAGER_DIRTY: return "Imager dirty";
        case FINGERPRINT_ACQUIRED_TOO_SLOW: return "Too slow";
        case FINGERPRINT_ACQUIRED_TOO_FAST: return "Too fast";
        case FINGERPRINT_ACQUIRED_VENDOR: return "Vendor specific";
        default: return "Unknown";
    }
}

static const gchar*
fingerprint_hidl_status_to_string(RequestStatus status)
{
    switch (status) {
        case FINGERPRINT_STATUS_OK: return "OK";
        case FINGERPRINT_STATUS_UNKNOWN: return "Unknown";
        case FINGERPRINT_STATUS_ENOENT: return "No such file or directory";
        case FINGERPRINT_STATUS_EINTR: return "Interrupted";
        case FINGERPRINT_STATUS_EIO: return "I/O error";
        case FINGERPRINT_STATUS_EAGAIN: return "Try again";
        case FINGERPRINT_STATUS_ENOMEM: return "Out of memory";
        case FINGERPRINT_STATUS_EACCES: return "Permission denied";
        case FINGERPRINT_STATUS_EFAULT: return "Bad address";
        case FINGERPRINT_STATUS_EBUSY: return "Device or resource busy";
        case FINGERPRINT_STATUS_EINVAL: return "Invalid argument";
        case FINGERPRINT_STATUS_ENOSPC: return "No space left on device";
        case FINGERPRINT_STATUS_ETIMEDOUT: return "Connection timed out";
        default: return "Unknown status";
    }
}

static guint64
fingerprint_hidl_set_notify(BiomFingerprintHidl* self)
{
    const gint fp_code = FP_SET_NOTIFY;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    guint64 device_id = 0;

    if (!self || !self->fingerprint_client || !self->fingerprint_callback) {
        g_warning("Invalid parameters in fingerprint_hidl_set_notify");
        return 0;
    }

    /* setNotify(IBiometricsFingerprintClientCallback clientCallback) generates (uint64_t deviceId); */
    req = gbinder_client_new_request(self->fingerprint_client);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_local_object(&writer, self->fingerprint_callback);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_uint64(&reader, &device_id);

    g_debug("Fingerprint HIDL set notify status %d, device_id: %lu", status, device_id);

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);

    return device_id;
}

guint64
fingerprint_hidl_pre_enroll(BiomFingerprintHidl* self)
{
    const gint fp_code = FP_PRE_ENROLL;
    GBinderLocalRequest* req;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    guint64 auth = 0;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_pre_enroll");
        return 0;
    }

    /* preEnroll() generates (uint64_t authChallenge); */
    req = gbinder_client_new_request(self->fingerprint_client);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_uint64(&reader, &auth);

    g_debug("Fingerprint HIDL pre enroll status %d, auth: %lu", status, auth);

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);

    return auth;
}

void
fingerprint_hidl_enroll(BiomFingerprintHidl* self, void* hat, guint32 gid, guint32 timeout)
{
    const gint fp_code = FP_ENROLL;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_enroll");
        return;
    }

    /* enroll(uint8_t[69] hat, uint32_t gid, uint32_t timeoutSec) generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);
    gbinder_local_request_init_writer(req, &writer);

    if (!hat) {
        g_warning("NULL hardware authentication token");
        gbinder_local_request_unref(req);
        return;
    }

    gbinder_writer_append_buffer_object(&writer, hat, 69); // hw_auth_token_t is exactly 69 bytes long
    gbinder_writer_append_int32(&writer, gid);
    gbinder_writer_append_int32(&writer, timeout);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL enroll status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

void
fingerprint_hidl_post_enroll(BiomFingerprintHidl* self)
{
    const gint fp_code = FP_POST_ENROLL;
    GBinderLocalRequest* req;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_post_enroll");
        return;
    }

    /* postEnroll() generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL post enroll status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

int
fingerprint_hidl_get_authenticator_id(BiomFingerprintHidl* self)
{
    const gint fp_code = FP_GET_AUTHENTICATOR_ID;
    GBinderLocalRequest* req;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 auth_id = 0;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_get_authenticator_id");
        return 0;
    }

    /* getAuthenticatorId() generates (uint64_t AuthenticatorId); */
    req = gbinder_client_new_request2(self->fingerprint_client, fp_code);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &auth_id);

    g_debug("Fingerprint HIDL get authenticator id status %d, auth_id: %d", status, auth_id);

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);

    return auth_id;
}

void
fingerprint_hidl_cancel(BiomFingerprintHidl* self)
{
    const gint fp_code = FP_CANCEL;
    GBinderLocalRequest* req;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_cancel");
        return;
    }

    /* cancel() generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL cancel status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

void
fingerprint_hidl_enumerate(BiomFingerprintHidl* self)
{
    const gint fp_code = FP_ENUMERATE;
    GBinderLocalRequest* req;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_enumerate");
        return;
    }

    /* enumerate() generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL enumerate status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

void
fingerprint_hidl_remove(BiomFingerprintHidl* self, guint32 gid, guint32 fid)
{
    const gint fp_code = FP_REMOVE;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_remove");
        return;
    }

    /* remove(uint32_t gid, uint32_t fid) generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, gid);
    gbinder_writer_append_int32(&writer, fid);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL remove status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

void
fingerprint_hidl_set_active_group(BiomFingerprintHidl* self, guint gid, const char *path)
{
    const gint fp_code = FP_SET_ACTIVE_GROUP;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_set_active_group");
        return;
    }

    /* setActiveGroup(uint32_t gid, string storePath) generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, gid);
    gbinder_writer_append_hidl_string(&writer, path);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL set active group status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

void
fingerprint_hidl_authenticate(BiomFingerprintHidl* self, guint64 operation_id, guint32 gid)
{
    const gint fp_code = FP_AUTHENTICATE;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    gint32 status;
    gint32 errno_code;

    if (!self || !self->fingerprint_client) {
        g_warning("Invalid parameters in fingerprint_hidl_authenticate");
        return;
    }

    /* authenticate(uint64_t operationId, uint32_t gid) generates (RequestStatus debugErrno); */
    req = gbinder_client_new_request(self->fingerprint_client);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int64(&writer, operation_id);
    gbinder_writer_append_int32(&writer, gid);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client, fp_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);
    gbinder_reader_read_int32(&reader, &errno_code);

    g_debug("Fingerprint HIDL authenticate status %d, errno: %d (%s)",
            status, errno_code, fingerprint_hidl_status_to_string((RequestStatus)errno_code));

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
}

static int
fingerprint_hidl_callback_handle_enroll_result(BiomFingerprintHidl* self, GBinderReader* reader)
{
    guint32 finger_id, group_id, remaining;
    guint64 device_id;

    /* onEnrollResult(uint64_t deviceId, uint32_t fingerId, uint32_t groupId, uint32_t remaining); */
    if (gbinder_reader_read_uint64(reader, &device_id) &&
        gbinder_reader_read_uint32(reader, &finger_id) &&
        gbinder_reader_read_uint32(reader, &group_id) &&
        gbinder_reader_read_uint32(reader, &remaining)) {

        g_debug("onEnrollResult device_id: %lu, finger_id: %u, group_id: %u, remaining: %u",
                device_id, finger_id, group_id, remaining);

        if (self->callbacks.enroll_result)
            self->callbacks.enroll_result(self->user_data, finger_id, group_id, remaining);

        return GBINDER_STATUS_OK;
    } else {
        g_warning("Failed to parse IBiometricsFingerprintClientCallback::onEnrollResult payload");
        return GBINDER_STATUS_FAILED;
    }
}

static int
fingerprint_hidl_callback_handle_acquired(BiomFingerprintHidl* self, GBinderReader* reader)
{
    guint32 acquired_info, vendor_code;
    guint64 device_id;

    /* onAcquired(uint64_t deviceId, FingerprintAcquiredInfo acquiredInfo, int32_t vendorCode); */
    if (gbinder_reader_read_uint64(reader, &device_id) &&
        gbinder_reader_read_uint32(reader, &acquired_info) &&
        gbinder_reader_read_uint32(reader, &vendor_code)) {

        g_debug("onAcquired device_id: %lu, acquired_info: %u (%s), vendor_code: %u",
                device_id, acquired_info,
                fingerprint_hidl_acquired_to_string((FingerprintAcquiredInfo)acquired_info),
                vendor_code);

        if (self->callbacks.acquired)
            self->callbacks.acquired(self->user_data, (FingerprintAcquiredInfo)acquired_info, vendor_code);

        return GBINDER_STATUS_OK;
    } else {
        g_warning("Failed to parse IBiometricsFingerprintClientCallback::onAcquired payload");
        return GBINDER_STATUS_FAILED;
    }
}

static int
fingerprint_hidl_callback_handle_authenticated(BiomFingerprintHidl* self, GBinderReader* reader)
{
    guint32 finger_id, group_id;
    guint64 device_id;

    /* onAuthenticated(uint64_t deviceId, uint32_t fingerId, uint32_t groupId, vec<uint8_t> token); */
    if (gbinder_reader_read_uint64(reader, &device_id) &&
        gbinder_reader_read_uint32(reader, &finger_id) &&
        gbinder_reader_read_uint32(reader, &group_id)) {

        g_debug("onAuthenticated device_id: %lu, finger_id: %u, group_id: %u",
                device_id, finger_id, group_id);

        if (self->callbacks.authenticated)
            self->callbacks.authenticated(self->user_data, finger_id, group_id);

        return GBINDER_STATUS_OK;
    } else {
        g_warning("Failed to parse IBiometricsFingerprintClientCallback::onAuthenticated payload");
        return GBINDER_STATUS_FAILED;
    }
}

static int
fingerprint_hidl_callback_handle_error(BiomFingerprintHidl* self, GBinderReader* reader)
{
    guint32 error, vendor_code;
    guint64 device_id;

    /* onError(uint64_t deviceId, FingerprintError error, int32_t vendorCode); */
    if (gbinder_reader_read_uint64(reader, &device_id) &&
        gbinder_reader_read_uint32(reader, &error) &&
        gbinder_reader_read_uint32(reader, &vendor_code)) {

        g_debug("onError device_id: %lu, error: %u (%s), vendor_code: %u",
                device_id, error,
                fingerprint_hidl_error_to_string((FingerprintError)error),
                vendor_code);

        if (self->callbacks.error)
            self->callbacks.error(self->user_data, (FingerprintError)error, vendor_code);

        return GBINDER_STATUS_OK;
    } else {
        g_warning("Failed to parse IBiometricsFingerprintClientCallback::onError payload");
        return GBINDER_STATUS_FAILED;
    }
}

static int
fingerprint_hidl_callback_handle_removed(BiomFingerprintHidl* self, GBinderReader* reader)
{
    guint32 finger_id, group_id, remaining;
    guint64 device_id;

    /* onRemoved(uint64_t deviceId, uint32_t fingerId, uint32_t groupId, uint32_t remaining); */
    if (gbinder_reader_read_uint64(reader, &device_id) &&
        gbinder_reader_read_uint32(reader, &finger_id) &&
        gbinder_reader_read_uint32(reader, &group_id) &&
        gbinder_reader_read_uint32(reader, &remaining)) {

        g_debug("onRemoved device_id: %lu, finger_id: %u, group_id: %u, remaining: %u",
                device_id, finger_id, group_id, remaining);

        if (self->callbacks.removed)
            self->callbacks.removed(self->user_data, finger_id, group_id, remaining);

        return GBINDER_STATUS_OK;
    } else {
        g_warning("Failed to parse IBiometricsFingerprintClientCallback::onRemoved payload");
        return GBINDER_STATUS_FAILED;
    }
}

static int
fingerprint_hidl_callback_handle_enumerate(BiomFingerprintHidl* self, GBinderReader* reader)
{
    guint32 finger_id, group_id, remaining;
    guint64 device_id;

    /* onEnumerate(uint64_t deviceId, uint32_t fingerId, uint32_t groupId, uint32_t remaining); */
    if (gbinder_reader_read_uint64(reader, &device_id) &&
        gbinder_reader_read_uint32(reader, &finger_id) &&
        gbinder_reader_read_uint32(reader, &group_id) &&
        gbinder_reader_read_uint32(reader, &remaining)) {

        g_debug("onEnumerate device_id: %lu, finger_id: %u, group_id: %u, remaining: %u",
                device_id, finger_id, group_id, remaining);

        if (self->callbacks.enumerate)
            self->callbacks.enumerate(self->user_data, finger_id, group_id, remaining);

        return GBINDER_STATUS_OK;
    } else {
        g_warning("Failed to parse IBiometricsFingerprintClientCallback::onEnumerate payload");
        return GBINDER_STATUS_FAILED;
    }
}

static GBinderLocalReply*
fingerprint_hidl_client_callback(GBinderLocalObject* obj, GBinderRemoteRequest* req,
                                 guint code, guint flags, int* status, void* user_data)
{
    BiomFingerprintHidl* self = (BiomFingerprintHidl*) user_data;
    const char* iface = gbinder_remote_request_interface(req);

    if (!g_strcmp0(iface, FP_CLIENT_CALLBACK)) {
        GBinderReader reader;
        gbinder_remote_request_init_reader(req, &reader);

        switch (code) {
        case FP_CALLBACK_ENROLL_RESULT:
            g_debug("%s %u enrollResult", iface, code);
            *status = fingerprint_hidl_callback_handle_enroll_result(self, &reader);
            break;
        case FP_CALLBACK_ACQUIRED:
            g_debug("%s %u acquired", iface, code);
            *status = fingerprint_hidl_callback_handle_acquired(self, &reader);
            break;
        case FP_CALLBACK_AUTHENTICATED:
            g_debug("%s %u authenticated", iface, code);
            *status = fingerprint_hidl_callback_handle_authenticated(self, &reader);
            break;
        case FP_CALLBACK_ERROR:
            g_debug("%s %u error", iface, code);
            *status = fingerprint_hidl_callback_handle_error(self, &reader);
            break;
        case FP_CALLBACK_REMOVED:
            g_debug("%s %u removed", iface, code);
            *status = fingerprint_hidl_callback_handle_removed(self, &reader);
            break;
        case FP_CALLBACK_ENUMERATE:
            g_debug("%s %u enumerate", iface, code);
            *status = fingerprint_hidl_callback_handle_enumerate(self, &reader);
            break;
        default:
            g_warning("IBiometricsFingerprintClientCallback %u unknown callback", code);
            *status = GBINDER_STATUS_FAILED;
            break;
        }
    } else {
        g_warning("FP client callback event unhandled: %s %u", iface, code);
        *status = GBINDER_STATUS_FAILED;
    }

    return (*status == GBINDER_STATUS_OK) ? gbinder_local_reply_append_int32
        (gbinder_local_object_new_reply(obj), 0) : NULL;
}

static gboolean
fingerprint_hidl_gatekeeper_save_blob_to_file(const char* filename, const void* data, guint32 size, guint32 mode)
{
    FILE* fp;
    gboolean success = FALSE;

    char* full_path = g_strdup_printf("/var/lib/biomd/%s", filename);
    char* tmp_filename = g_strdup_printf("%s.tmp", full_path);

    struct stat st = {0};
    if (stat("/var/lib/biomd", &st) == -1) {
        if (mkdir("/var/lib/biomd", 0700) == -1) {
            g_warning("Failed to create directory /var/lib/biomd");
            g_free(full_path);
            g_free(tmp_filename);
            return FALSE;
        }
    }

    fp = fopen(tmp_filename, "wb");
    if (fp) {
        if (fwrite(data, 1, size, fp) == size) {
            fclose(fp);
            if (chmod(tmp_filename, mode) == 0 && rename(tmp_filename, full_path) == 0)
                success = TRUE;
        } else {
            fclose(fp);
        }
    }

    if (!success)
        unlink(tmp_filename);

    g_free(full_path);
    g_free(tmp_filename);
    return success;
}

static gboolean
fingerprint_hidl_gatekeeper_load_handle_file(guint32 uid, void** handle, guint32* handle_size)
{
    FILE* fp;
    gboolean success = FALSE;

    char* filename = g_strdup_printf("handle-%u.blob", uid);
    char* full_path = g_strdup_printf("/var/lib/biomd/%s", filename);

    *handle = NULL;
    *handle_size = 0;

    fp = fopen(full_path, "rb");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        *handle_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (*handle_size > 0) {
            *handle = g_malloc(*handle_size);
            if (*handle) {
                if (fread(*handle, 1, *handle_size, fp) == *handle_size) {
                    success = TRUE;
                } else {
                    g_free(*handle);
                    *handle = NULL;
                    *handle_size = 0;
                }
            }
        }
        fclose(fp);
    } else {
        g_debug("Failed to open handle file: %s", full_path);
    }

    g_free(filename);
    g_free(full_path);
    return success;
}

char*
fingerprint_hidl_gatekeeper_enroll(BiomFingerprintHidl* self, guint32 uid, const char* password)
{
    const gint gk_code = GK_ENROLL;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    const GatekeeperResponse* gatekeeper_response;
    gint32 status;
    void* crypto_blob = NULL;
    guint32 crypto_blob_size = 0;
    gboolean success = FALSE;
    char* filename = NULL;

    if (!self || !self->gatekeeper_client) {
        g_warning("Invalid parameters in fingerprint_hidl_gk_enroll");
        return NULL;
    }

    /* enroll(uint32_t uid,
     *        vec<uint8_t> currentPasswordHandle,
     *        vec<uint8_t> currentPassword,
     *        vec<uint8_t> desiredPassword)
     *     generates (GatekeeperResponse response); */
    req = gbinder_client_new_request(self->gatekeeper_client);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, uid);
    gbinder_writer_append_hidl_vec(&writer, NULL, 0, 0);
    gbinder_writer_append_hidl_vec(&writer, NULL, 0, 0);
    gbinder_writer_append_hidl_vec(&writer, password, strlen(password), 1);

    reply = gbinder_client_transact_sync_reply(self->gatekeeper_client, gk_code, req, &status);

    if (reply && status == 0) {
        gbinder_remote_reply_init_reader(reply, &reader);
        gbinder_reader_read_int32(&reader, &status);
        g_debug("Gatekeeper enroll status %d", status);

        gatekeeper_response = gbinder_reader_read_hidl_struct(&reader, GatekeeperResponse);
        if (gatekeeper_response) {
            g_debug("Gatekeeper enroll timeout: %d, gatekeeper status code: %d", gatekeeper_response->timeout, gatekeeper_response->code);

            if (gatekeeper_response->data.count > 0 && gatekeeper_response->data.data.ptr) {
                crypto_blob = g_memdup2(gatekeeper_response->data.data.ptr, gatekeeper_response->data.count);
                crypto_blob_size = gatekeeper_response->data.count;

                filename = g_strdup_printf("handle-%u.blob", uid);

                if (crypto_blob && filename) {
                    if (fingerprint_hidl_gatekeeper_save_blob_to_file(filename, crypto_blob, crypto_blob_size, 0600))
                        success = TRUE;
                    else
                        g_warning("Could not save password handle");
                }
                g_free(filename);
            } else {
                g_warning("Empty or invalid gatekeeper response data");
            }
        } else {
            g_warning("Could not read gatekeeper response");
        }
    } else {
        g_warning("Gatekeeper transaction failed");
    }

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);

    if (!success) {
        g_warning("Gatekeeper enroll failed");
        g_free(crypto_blob);
        return NULL;
    }

    return crypto_blob;
}

static gboolean
fingerprint_hidl_gatekeeper_verify(BiomFingerprintHidl* self, guint32 uid, guint64 challenge,
                                   void* handle, guint32 handle_size, const char* password, void* auth_token)
{
    const gint gk_code = GK_VERIFY;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    const GatekeeperResponse* gatekeeper_response;
    gint32 status;
    gboolean success = FALSE;

    /* verify(uint32_t uid, uint64_t challenge,
     *        vec<uint8_t> enrolledPasswordHandle,
     *        vec<uint8_t> providedPassword)
     *     generates (GatekeeperResponse response); */
    req = gbinder_client_new_request(self->gatekeeper_client);
    if (!req) {
        g_warning("Failed to allocate gatekeeper binder request");
        return FALSE;
    }

    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, uid);
    gbinder_writer_append_int64(&writer, challenge);
    gbinder_writer_append_hidl_vec(&writer, handle, handle_size, 1);
    gbinder_writer_append_hidl_vec(&writer, password, strlen(password), 1);

    reply = gbinder_client_transact_sync_reply(self->gatekeeper_client, gk_code, req, &status);

    if (!reply || status != 0) {
        g_warning("Gatekeeper verify transaction failed");
        goto cleanup;
    }

    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);

    g_debug("Gatekeeper verify status %d", status);

    if (status != 0) {
        g_warning("Gatekeeper transaction returned non-zero status");
        goto cleanup;
    }

    gatekeeper_response = gbinder_reader_read_hidl_struct(&reader, GatekeeperResponse);
    if (!gatekeeper_response) {
        g_warning("Could not read gatekeeper response");
        goto cleanup;
    }

    g_debug("Gatekeeper verify timeout: %d, gatekeeper status code: %d", gatekeeper_response->timeout, gatekeeper_response->code);

    // hw_auth_token_t must be 69 bytes long
    if (auth_token && gatekeeper_response->data.count == 69) {
        memcpy(auth_token, gatekeeper_response->data.data.ptr, 69);
        success = TRUE;
    } else if (gatekeeper_response->data.count != 69) {
        g_warning("Gatekeeper verify returned something which doesn't look like an hw_auth_token_t");
    }

cleanup:
    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);
    return success;
}

char*
fingerprint_hidl_gatekeeper_delete_user(BiomFingerprintHidl* self, guint32 uid)
{
    const gint gk_code = GK_DELETE_USER;
    GBinderLocalRequest* req;
    GBinderWriter writer;
    GBinderReader reader;
    GBinderRemoteReply* reply;
    const GatekeeperResponse* gatekeeper_response;
    gint32 status;
    char* crypto_blob;

    /* deleteUser(uint32_t uid)
     *     generates (GatekeeperResponse response); */
    req = gbinder_client_new_request(self->gatekeeper_client);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, uid);

    reply = gbinder_client_transact_sync_reply(self->gatekeeper_client, gk_code, req, &status);
    gbinder_remote_reply_init_reader(reply, &reader);
    gbinder_reader_read_int32(&reader, &status);

    g_debug("Gatekeeper delete user status %d", status);

    gatekeeper_response = gbinder_reader_read_hidl_struct(&reader, GatekeeperResponse);
    g_debug("Gatekeeper delete user timeout: %d, gatekeeper status code: %d", gatekeeper_response->timeout, gatekeeper_response->code);

    crypto_blob = g_malloc(gatekeeper_response->data.count + 1);
    if (crypto_blob) {
        memcpy(crypto_blob, gatekeeper_response->data.data.ptr, gatekeeper_response->data.count);
        crypto_blob[gatekeeper_response->data.count] = '\0';
    }

    g_debug("Gatekeeper delete user data: %s", crypto_blob);

    gbinder_local_request_unref(req);
    gbinder_remote_reply_unref(reply);

    return crypto_blob;
}

BiomFingerprintHidl*
fingerprint_hidl_init(const FingerprintHidlCallbacks* callbacks, gpointer user_data)
{
    GBinderServiceManager* sm;
    GBinderRemoteObject* fingerprint_remote;
    GBinderRemoteObject* gatekeeper_remote;
    BiomFingerprintHidl* self;

    g_debug("Initializing fingerprint HIDL interface");

    sm = gbinder_servicemanager_new(HWBINDER_DEVICE);
    if (!sm) {
        g_warning("Failed to create gbinder service manager");
        return NULL;
    }

    fingerprint_remote = gbinder_servicemanager_get_service_sync(sm, FP_SERVICE, NULL);
    if (!fingerprint_remote) {
        g_warning("Failed to get fingerprint remote service");
        gbinder_servicemanager_unref(sm);
        return NULL;
    }

    gatekeeper_remote = gbinder_servicemanager_get_service_sync(sm, GK_SERVICE, NULL);
    if (!gatekeeper_remote) {
        g_warning("Failed to get gatekeeper remote service");
        gbinder_remote_object_unref(fingerprint_remote);
        gbinder_servicemanager_unref(sm);
        return NULL;
    }

    self = g_new0(BiomFingerprintHidl, 1);
    self->sm = sm;
    self->fingerprint_remote = fingerprint_remote;
    self->gatekeeper_remote = gatekeeper_remote;
    self->available = FALSE;

    if (callbacks)
        self->callbacks = *callbacks;

    self->user_data = user_data;

    self->fingerprint_client = gbinder_client_new(self->fingerprint_remote, FP);
    if (!self->fingerprint_client) {
        g_warning("Failed to create fingerprint client");
        fingerprint_hidl_cleanup(self);
        return NULL;
    }

    self->gatekeeper_client = gbinder_client_new(self->gatekeeper_remote, GK);
    if (!self->gatekeeper_client) {
        g_warning("Failed to create gatekeeper client");
        fingerprint_hidl_cleanup(self);
        return NULL;
    }

    self->fingerprint_callback = gbinder_servicemanager_new_local_object(
        sm,
        FP_CLIENT_CALLBACK,
        fingerprint_hidl_client_callback,
        self);

    self->available = TRUE;

    self->device_id = fingerprint_hidl_set_notify(self);
    g_debug("Fingerprint HIDL initialization complete, device ID: %lu", self->device_id);

    return self;
}

void
fingerprint_hidl_cleanup(BiomFingerprintHidl* self)
{
    if (!self)
        return;

    g_debug("Cleaning up fingerprint HIDL interface");

    if (self->fingerprint_client) {
        gbinder_client_unref(self->fingerprint_client);
        self->fingerprint_client = NULL;
    }

    if (self->gatekeeper_client) {
        gbinder_client_unref(self->gatekeeper_client);
        self->gatekeeper_client = NULL;
    }

    if (self->fingerprint_callback) {
        gbinder_local_object_unref(self->fingerprint_callback);
        self->fingerprint_callback = NULL;
    }

    if (self->fingerprint_remote) {
        gbinder_remote_object_unref(self->fingerprint_remote);
        self->fingerprint_remote = NULL;
    }

    if (self->gatekeeper_remote) {
        gbinder_remote_object_unref(self->gatekeeper_remote);
        self->gatekeeper_remote = NULL;
    }

    if (self->sm) {
        gbinder_servicemanager_unref(self->sm);
        self->sm = NULL;
    }

    g_free(self);
}

gboolean
fingerprint_hidl_is_available(BiomFingerprintHidl* self)
{
    return self && self->available;
}

gboolean
fingerprint_hidl_setup(BiomFingerprintHidl* self)
{
    if (!self || !self->available) {
        g_warning("Fingerprint HIDL interface not available for setup");
        return FALSE;
    }

    g_debug("Setting up fingerprint HIDL configuration");

    fingerprint_hidl_set_active_group(self, 0 /* gid */, "/data/vendor_de/0/fpdata" /* storePath */);
    fingerprint_hidl_enumerate(self);

    return TRUE;
}

gboolean
fingerprint_hidl_perform_enrollment(BiomFingerprintHidl* self, const gchar* password, guint32 timeout_sec)
{
    guint64 auth;
    void* handle = NULL;
    guint32 handle_size = 0;
    void* auth_token = NULL;
    gboolean verify_success = FALSE;

    if (!self || !self->available) {
        g_warning("Fingerprint HIDL interface not available for enrollment");
        return FALSE;
    }

    g_debug("Starting HIDL fingerprint enrollment sequence");

    auth = fingerprint_hidl_pre_enroll(self);
    if (auth == 0) {
        g_warning("Failed to get pre-enroll challenge");
        return FALSE;
    }

    /* 69 bytes for hw_auth_token_t */
    auth_token = g_malloc(69);
    if (!auth_token) {
        g_warning("Failed to allocate memory for auth token");
        return FALSE;
    }

    if (!fingerprint_hidl_gatekeeper_load_handle_file(0 /* uid */, &handle, &handle_size)) {
        g_debug("No existing handle found, enrolling password first");
        fingerprint_hidl_gatekeeper_delete_user(self, 0 /* uid */);
        fingerprint_hidl_gatekeeper_enroll(self, 0 /* uid */, password ? password : "default_password");

        if (!fingerprint_hidl_gatekeeper_load_handle_file(0 /* uid */, &handle, &handle_size)) {
            g_warning("Failed to load password handle after enrollment");
            g_free(auth_token);
            return FALSE;
        }
    }

    verify_success = fingerprint_hidl_gatekeeper_verify(
        self,
        0,
        auth,
        handle,
        handle_size,
        password ? password : "default_password",
        auth_token);

    g_free(handle);

    if (verify_success) {
        g_debug("Password verification successful, proceeding to enroll fingerprint");
        fingerprint_hidl_enroll(self, auth_token, 0 /* gid */, timeout_sec > 0 ? timeout_sec : 60);
    } else {
        g_warning("Password verification failed, cannot enroll fingerprint");
    }

    g_free(auth_token);

    return verify_success;
}

gboolean
fingerprint_hidl_perform_authentication(BiomFingerprintHidl* self)
{
    if (!self || !self->available) {
        g_warning("Fingerprint HIDL interface not available for authentication");
        return FALSE;
    }

    g_debug("Starting HIDL fingerprint authentication");
    fingerprint_hidl_authenticate(self, 0 /* operationId */, 0 /* gid */);
    return TRUE;
}

gboolean
fingerprint_hidl_cancel_operation(BiomFingerprintHidl* self)
{
    if (!self || !self->available) {
        g_warning("Fingerprint HIDL interface not available for cancellation");
        return FALSE;
    }

    g_debug("Cancelling current HIDL fingerprint operation");
    fingerprint_hidl_cancel(self);
    return TRUE;
}

gboolean
fingerprint_hidl_remove_fingerprint(BiomFingerprintHidl* self, guint32 finger_id)
{
    if (!self || !self->available) {
        g_warning("Fingerprint HIDL interface not available for removal");
        return FALSE;
    }

    g_debug("Removing HIDL fingerprint with ID %u", finger_id);
    fingerprint_hidl_remove(self, 0 /* gid */, finger_id);
    return TRUE;
}
