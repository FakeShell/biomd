/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 */

#include "face.h"
#include "introspect.h"
#include "face_backend.h"
#include "face_fart_backend.h"

static GDBusNodeInfo *face_introspection_data = NULL;
static GDBusNodeInfo *face_agent_introspection_data = NULL;

typedef enum {
    FACE_AGENT_ROLE_NONE = 0,
    FACE_AGENT_ROLE_ENROLLMENT = 1,
    FACE_AGENT_ROLE_RECOGNITION = 2
} FaceAgentRole;

typedef enum {
    FACE_AGENT_MODE_NONE = 0,
    FACE_AGENT_MODE_ENROLL = 1,
    FACE_AGENT_MODE_RECOGNIZE = 2
} FaceAgentMode;

typedef struct _FaceAgent {
    gchar *path;
    gchar *owner;
    FaceAgentRole role;
    gboolean has_access;
    gboolean busy;
    guint32 last_enroll_state;
    guint32 last_recog_state;
    gint32 enrollment_progress;
    FaceAgentMode mode;
    guint reg_id;
    grefcount ref_count;
} FaceAgent;

typedef struct {
    BiometricState current_state;
    gboolean face_enrolled;
    FaceImplementationType implementation_type;
    FaceAgent *enrollment_agent;
    FaceAgent *recognition_agent;
    FaceAgent *active_agent;
    GHashTable *agents_by_path;
    guint next_agent_id;
    GDBusConnection *connection;
    guint name_owner_changed_sub;
    FaceBackend *backend;
    GMutex lock;
} BiomFace;

static BiomFace *face_state = NULL;

static void
emit_agent_signal_enrollment_state(FaceAgent *agent, guint32 state);
static void
emit_agent_signal_enrollment_progress(FaceAgent *agent, gint32 progress);
static void
emit_agent_signal_recognition_state(FaceAgent *agent, guint32 state);

static FaceAgent *
face_agent_ref(FaceAgent *agent)
{
    if (!agent)
        return NULL;
    g_ref_count_inc(&agent->ref_count);
    return agent;
}

static void
face_agent_free(FaceAgent *agent)
{
    if (!agent)
        return;
    g_free(agent->path);
    g_free(agent->owner);
    g_free(agent);
}

static void
face_agent_unref(FaceAgent *agent)
{
    if (!agent)
        return;
    if (g_ref_count_dec(&agent->ref_count))
        face_agent_free(agent);
}

static void
face_agent_reset_enrollment_state_locked(FaceAgent *agent)
{
    if (!agent)
        return;

    agent->last_enroll_state = (guint32)ENROLLMENT_IDLE;
    agent->enrollment_progress = 0;

    emit_agent_signal_enrollment_progress(agent, 0);
    emit_agent_signal_enrollment_state(agent, agent->last_enroll_state);
}

static void
face_agent_reset_recognition_state_locked(FaceAgent *agent)
{
    if (!agent)
        return;

    agent->last_recog_state = (guint32)RECOGNITION_IDLE;
    emit_agent_signal_recognition_state(agent, agent->last_recog_state);
}

static void
face_agent_reset_all_state_locked(FaceAgent *agent)
{
    if (!agent)
        return;

    agent->mode = FACE_AGENT_MODE_NONE;
    agent->busy = FALSE;

    face_agent_reset_enrollment_state_locked(agent);
    face_agent_reset_recognition_state_locked(agent);
}

static FaceAgent *
face_agent_new(const gchar *path, const gchar *owner)
{
    FaceAgent *agent = g_new0(FaceAgent, 1);
    g_ref_count_init(&agent->ref_count);

    agent->path = g_strdup(path);
    agent->owner = g_strdup(owner);
    agent->role = FACE_AGENT_ROLE_NONE;
    agent->has_access = FALSE;
    agent->busy = FALSE;
    agent->last_enroll_state = (guint32)ENROLLMENT_IDLE;
    agent->last_recog_state = (guint32)RECOGNITION_IDLE;
    agent->enrollment_progress = 0;
    agent->mode = FACE_AGENT_MODE_NONE;
    agent->reg_id = 0;
    return agent;
}

static void
set_active_agent_locked(FaceAgent *agent)
{
    if (!face_state)
        return;

    if (face_state->active_agent == agent)
        return;

    if (face_state->active_agent)
        face_agent_unref(face_state->active_agent);

    face_state->active_agent = agent ? face_agent_ref(agent) : NULL;
}

static void
set_enrollment_agent_locked(FaceAgent *agent)
{
    if (!face_state)
        return;

    if (face_state->enrollment_agent == agent)
        return;

    if (face_state->enrollment_agent)
        face_agent_unref(face_state->enrollment_agent);

    face_state->enrollment_agent = agent ? face_agent_ref(agent) : NULL;
}

static void
set_recognition_agent_locked(FaceAgent *agent)
{
    if (!face_state)
        return;

    if (face_state->recognition_agent == agent)
        return;

    if (face_state->recognition_agent)
        face_agent_unref(face_state->recognition_agent);

    face_state->recognition_agent = agent ? face_agent_ref(agent) : NULL;
}

static void
emit_manager_signal_state_changed(BiometricState state)
{
    if (!face_state || !face_state->connection)
        return;

    g_dbus_connection_emit_signal(
        face_state->connection,
        NULL,
        "/io/FuriOS/Biomd/Face",
        "io.FuriOS.Biomd.Face",
        "StateChanged",
        g_variant_new("(i)", (gint32)state),
        NULL);
}

static void
emit_manager_signal_face_enrolled_changed(gboolean enrolled)
{
    if (!face_state || !face_state->connection)
        return;

    g_dbus_connection_emit_signal(
        face_state->connection,
        NULL,
        "/io/FuriOS/Biomd/Face",
        "io.FuriOS.Biomd.Face",
        "FaceEnrolledChanged",
        g_variant_new("(b)", enrolled),
        NULL);
}

static void
emit_agent_signal_access_changed(FaceAgent *agent, gboolean has_access)
{
    if (!face_state || !face_state->connection || !agent || !agent->path)
        return;

    g_dbus_connection_emit_signal(
        face_state->connection,
        NULL,
        agent->path,
        "io.FuriOS.Biomd.Face.Agent",
        "AccessChanged",
        g_variant_new("(b)", has_access),
        NULL);
}

static void
emit_agent_signal_enrollment_state(FaceAgent *agent, guint32 state)
{
    if (!face_state || !face_state->connection || !agent || !agent->path)
        return;

    g_dbus_connection_emit_signal(
        face_state->connection,
        NULL,
        agent->path,
        "io.FuriOS.Biomd.Face.Agent",
        "EnrollmentStateChanged",
        g_variant_new("(u)", state),
        NULL);
}

static void
emit_agent_signal_enrollment_progress(FaceAgent *agent, gint32 progress)
{
    if (!face_state || !face_state->connection || !agent || !agent->path)
        return;

    g_dbus_connection_emit_signal(
        face_state->connection,
        NULL,
        agent->path,
        "io.FuriOS.Biomd.Face.Agent",
        "EnrollmentProgressChanged",
        g_variant_new("(i)", progress),
        NULL);
}

static void
emit_agent_signal_recognition_state(FaceAgent *agent, guint32 state)
{
    if (!face_state || !face_state->connection || !agent || !agent->path)
        return;

    g_dbus_connection_emit_signal(
        face_state->connection,
        NULL,
        agent->path,
        "io.FuriOS.Biomd.Face.Agent",
        "RecognitionStateChanged",
        g_variant_new("(u)", state),
        NULL);
}

static FaceAgent *
lookup_agent_by_path(const gchar *path)
{
    if (!face_state || !face_state->agents_by_path || !path)
        return NULL;

    return (FaceAgent *)g_hash_table_lookup(face_state->agents_by_path, path);
}

static gboolean
sender_matches_agent_owner(const gchar *sender, FaceAgent *agent)
{
    return (sender && agent && agent->owner && g_strcmp0(sender, agent->owner) == 0);
}

static gchar *
make_next_agent_path(void)
{
    if (!face_state)
        return g_strdup("/io/FuriOS/Biomd/Face/Agent0");

    return g_strdup_printf("/io/FuriOS/Biomd/Face/Agent%u", face_state->next_agent_id++);
}

static void
recompute_access_and_notify_locked(void)
{
    FaceAgent *enroll = face_state ? face_state->enrollment_agent : NULL;
    FaceAgent *recog  = face_state ? face_state->recognition_agent : NULL;

    gboolean enroll_should = (enroll != NULL);
    gboolean recog_should  = (enroll == NULL && recog != NULL);

    if (enroll) {
        if (enroll->has_access != enroll_should) {
            enroll->has_access = enroll_should;
            emit_agent_signal_access_changed(enroll, enroll_should);
        }
    }

    if (recog) {
        if (recog->has_access != recog_should) {
            /* if recognition is losing access, treat it like Cancel happened */
            if (!recog_should) {
                gboolean was_active = (face_state->active_agent == recog);

                recog->mode = FACE_AGENT_MODE_NONE;
                recog->busy = FALSE;
                face_agent_reset_recognition_state_locked(recog);

                if (was_active) {
                    if (face_state->backend)
                        face_backend_cancel_operation(face_state->backend);

                    face_state->current_state = STATE_IDLE;
                    emit_manager_signal_state_changed(face_state->current_state);
                    set_active_agent_locked(NULL);
                }
            }

            recog->has_access = recog_should;
            emit_agent_signal_access_changed(recog, recog_should);
        }
    }
}

static void
backend_update_face_enrolled_locked(void)
{
    if (!face_state || !face_state->backend)
        return;

    gboolean new_enrolled = face_backend_is_enrolled(face_state->backend);
    if (face_state->face_enrolled != new_enrolled) {
        face_state->face_enrolled = new_enrolled;
        g_debug("FaceEnrolled changed -> %d", new_enrolled ? 1 : 0);
        emit_manager_signal_face_enrolled_changed(new_enrolled);
    }
}

static void
on_backend_enrollment_state(gpointer user_data, guint32 state)
{
    (void) user_data;

    if (!face_state)
        return;

    g_mutex_lock(&face_state->lock);

    FaceAgent *agent = face_state->active_agent;
    if (agent && agent->role == FACE_AGENT_ROLE_ENROLLMENT) {
        agent->last_enroll_state = state;
        emit_agent_signal_enrollment_state(agent, state);
    } else if (face_state->enrollment_agent) {
        face_state->enrollment_agent->last_enroll_state = state;
        emit_agent_signal_enrollment_state(face_state->enrollment_agent, state);
    }

    backend_update_face_enrolled_locked();

    g_mutex_unlock(&face_state->lock);
}

static void
on_backend_enrollment_progress(gpointer user_data, gint32 progress)
{
    (void) user_data;

    if (!face_state)
        return;

    if (progress < 0)
        progress = 0;
    if (progress > 100)
        progress = 100;

    g_mutex_lock(&face_state->lock);

    FaceAgent *agent = face_state->active_agent;
    if (agent && agent->role == FACE_AGENT_ROLE_ENROLLMENT) {
        if (agent->enrollment_progress != progress) {
            agent->enrollment_progress = progress;
            emit_agent_signal_enrollment_progress(agent, progress);
        }
    } else if (face_state->enrollment_agent) {
        if (face_state->enrollment_agent->enrollment_progress != progress) {
            face_state->enrollment_agent->enrollment_progress = progress;
            emit_agent_signal_enrollment_progress(face_state->enrollment_agent, progress);
        }
    }

    g_mutex_unlock(&face_state->lock);
}

static void
on_backend_recognition_state(gpointer user_data, guint32 state)
{
    (void) user_data;

    if (!face_state)
        return;

    g_mutex_lock(&face_state->lock);

    FaceAgent *agent = face_state->active_agent;
    if (agent && agent->role == FACE_AGENT_ROLE_RECOGNITION) {
        agent->last_recog_state = state;
        emit_agent_signal_recognition_state(agent, state);
    } else if (face_state->recognition_agent) {
        face_state->recognition_agent->last_recog_state = state;
        emit_agent_signal_recognition_state(face_state->recognition_agent, state);
    }

    backend_update_face_enrolled_locked();

    g_mutex_unlock(&face_state->lock);
}

typedef struct {
    FaceAgent *agent;
    gint fd;
    gint width;
    gint height;
    gint channels;
    guint32 format;
} SubmitFrameJob;

static void
submit_frame_job_free(SubmitFrameJob *job)
{
    if (!job)
        return;

    if (job->fd >= 0)
        close(job->fd);

    if (job->agent)
        face_agent_unref(job->agent);

    g_free(job);
}

static void
submit_frame_worker(GTask *task,
                    gpointer source_object,
                    gpointer task_data,
                    GCancellable *cancellable)
{
    (void) source_object;
    (void) cancellable;

    SubmitFrameJob *job = (SubmitFrameJob*)task_data;
    gboolean ok = FALSE;

    if (!face_state || !job || !job->agent) {
        g_task_return_boolean(task, FALSE);
        return;
    }

    g_mutex_lock(&face_state->lock);
    FaceBackend *backend = face_state->backend;
    g_mutex_unlock(&face_state->lock);

    if (!backend) {
        g_task_return_boolean(task, FALSE);
        return;
    }

    ok = face_backend_submit_frame(backend,
                                  job->fd,
                                  job->width,
                                  job->height,
                                  job->channels,
                                  job->format);

    g_task_return_boolean(task, ok);
}

static void
submit_frame_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    (void) source_object;

    FaceAgent *agent = (FaceAgent*)user_data;
    (void) g_task_propagate_boolean(G_TASK(res), NULL);

    if (!face_state || !agent)
        return;

    g_mutex_lock(&face_state->lock);
    agent->busy = FALSE;
    g_mutex_unlock(&face_state->lock);

    face_agent_unref(agent);
}

static gint
resolve_unix_fd_from_invocation(GDBusMethodInvocation *invocation, gint handle, GError **error)
{
    if (!invocation) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Invocation is NULL");
        return -1;
    }

    if (handle < 0) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Invalid fd handle");
        return -1;
    }

    GDBusMessage *msg = g_dbus_method_invocation_get_message(invocation);
    if (!msg) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "No DBus message on invocation");
        return -1;
    }

    GUnixFDList *fd_list = g_dbus_message_get_unix_fd_list(msg);
    if (!fd_list) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "No unix fd list attached");
        return -1;
    }

    /* caller must close it. */
    gint fd = g_unix_fd_list_get(fd_list, handle, error);
    if (fd < 0)
        return -1;

    return fd;
}

static void
handle_face_agent_method_call(GDBusConnection *connection,
                              const gchar *sender,
                              const gchar *object_path,
                              const gchar *interface_name,
                              const gchar *method_name,
                              GVariant *parameters,
                              GDBusMethodInvocation *invocation,
                              gpointer user_data)
{
    (void) connection;
    (void) object_path;
    (void) interface_name;

    FaceAgent *agent = (FaceAgent*)user_data;

    if (!face_state || !agent) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_FAILED,
                                              "Face agent not initialized");
        return;
    }

    if (!sender_matches_agent_owner(sender, agent)) {
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
        return;
    }

    /* must have access */
    g_mutex_lock(&face_state->lock);
    gboolean has_access = agent->has_access;
    g_mutex_unlock(&face_state->lock);

    if (!has_access) {
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
        return;
    }

    if (g_strcmp0(method_name, "StartEnrollment") == 0) {
        gboolean ok = FALSE;

        g_mutex_lock(&face_state->lock);

        if (agent->role != FACE_AGENT_ROLE_ENROLLMENT) {
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        backend_update_face_enrolled_locked();
        if (face_state->face_enrolled) {
            g_debug("StartEnrollment rejected: face already enrolled");
            face_agent_reset_enrollment_state_locked(agent);
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        if (face_state->current_state != STATE_IDLE ||
            (face_state->active_agent && face_state->active_agent != agent)) {
            g_debug("StartEnrollment rejected: current_state=%d active_agent=%s",
                    (int)face_state->current_state,
                    (face_state->active_agent && face_state->active_agent->path) ? face_state->active_agent->path : "(none)");
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        agent->mode = FACE_AGENT_MODE_ENROLL;
        agent->busy = FALSE;
        face_agent_reset_enrollment_state_locked(agent);
        set_active_agent_locked(agent);

        face_state->current_state = STATE_ENROLLING;
        emit_manager_signal_state_changed(face_state->current_state);

        if (face_state->backend)
            ok = face_backend_start_enrollment(face_state->backend);

        g_mutex_unlock(&face_state->lock);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ok));
        return;
    }

    if (g_strcmp0(method_name, "StartRecognition") == 0) {
        gboolean ok = FALSE;

        g_mutex_lock(&face_state->lock);

        if (agent->role != FACE_AGENT_ROLE_RECOGNITION) {
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        backend_update_face_enrolled_locked();
        if (!face_state->face_enrolled) {
            g_debug("StartRecognition rejected: no face enrolled");
            agent->last_recog_state = (guint32)RECOGNITION_NOT_ENROLLED;
            emit_agent_signal_recognition_state(agent, agent->last_recog_state);
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        if (face_state->current_state != STATE_IDLE ||
            (face_state->active_agent && face_state->active_agent != agent)) {
            g_debug("StartRecognition rejected: current_state=%d active_agent=%s",
                    (int)face_state->current_state,
                    (face_state->active_agent && face_state->active_agent->path) ? face_state->active_agent->path : "(none)");
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        agent->mode = FACE_AGENT_MODE_RECOGNIZE;
        agent->busy = FALSE;
        face_agent_reset_recognition_state_locked(agent);
        set_active_agent_locked(agent);

        face_state->current_state = STATE_IDENTIFYING;
        emit_manager_signal_state_changed(face_state->current_state);

        if (face_state->backend)
            ok = face_backend_start_recognition(face_state->backend);

        g_mutex_unlock(&face_state->lock);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ok));
        return;
    }

    if (g_strcmp0(method_name, "Cancel") == 0) {
        gboolean ok = FALSE;

        g_mutex_lock(&face_state->lock);

        if (face_state->active_agent && face_state->active_agent != agent) {
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        face_agent_reset_all_state_locked(agent);

        face_state->current_state = STATE_IDLE;
        emit_manager_signal_state_changed(face_state->current_state);

        if (face_state->backend)
            ok = face_backend_cancel_operation(face_state->backend);

        set_active_agent_locked(NULL);

        g_mutex_unlock(&face_state->lock);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ok));
        return;
    }

    if (g_strcmp0(method_name, "RemoveFaceData") == 0) {
        gboolean ok = FALSE;

        g_mutex_lock(&face_state->lock);

        if (face_state->active_agent && face_state->active_agent != agent) {
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        backend_update_face_enrolled_locked();
        if (!face_state->face_enrolled) {
            g_debug("RemoveFaceData: no face enrolled");
            g_mutex_unlock(&face_state->lock);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        if (face_state->backend)
            ok = face_backend_remove_face_data(face_state->backend);

        backend_update_face_enrolled_locked();

        face_agent_reset_enrollment_state_locked(agent);
        face_agent_reset_recognition_state_locked(agent);

        g_mutex_unlock(&face_state->lock);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ok));
        return;
    }

    if (g_strcmp0(method_name, "SubmitFrame") == 0) {
        gint32 handle = -1;
        gint32 width = 0, height = 0, channels = 0;
        guint32 format = 0;

        g_variant_get(parameters, "(hiiiu)", &handle, &width, &height, &channels, &format);

        if (format != (guint32)FACE_FRAME_FORMAT_BGR &&
            format != (guint32)FACE_FRAME_FORMAT_RGB &&
            format != (guint32)FACE_FRAME_FORMAT_GRAY) {
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        if (handle < 0 || width <= 0 || height <= 0 || channels <= 0) {
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        /* resolve the real fd from the invocation's unix fd list */
        GError *fd_err = NULL;
        gint realfd = resolve_unix_fd_from_invocation(invocation, handle, &fd_err);
        if (realfd < 0) {
            g_debug("SubmitFrame: failed to resolve fd handle=%d: %s",
                    handle, fd_err ? fd_err->message : "unknown");
            g_clear_error(&fd_err);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        g_mutex_lock(&face_state->lock);

        if (agent->mode == FACE_AGENT_MODE_NONE) {
            g_mutex_unlock(&face_state->lock);
            close(realfd);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        if (agent->mode == FACE_AGENT_MODE_ENROLL) {
            backend_update_face_enrolled_locked();
            if (face_state->face_enrolled) {
                g_debug("SubmitFrame rejected: enroll mode but face already enrolled");
                face_agent_reset_enrollment_state_locked(agent);
                g_mutex_unlock(&face_state->lock);
                close(realfd);
                g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
                return;
            }
        }

        if (agent->mode == FACE_AGENT_MODE_RECOGNIZE) {
            backend_update_face_enrolled_locked();
            if (!face_state->face_enrolled) {
                g_debug("SubmitFrame rejected: recognize mode but not enrolled");
                agent->last_recog_state = (guint32)RECOGNITION_NOT_ENROLLED;
                emit_agent_signal_recognition_state(agent, agent->last_recog_state);
                g_mutex_unlock(&face_state->lock);
                close(realfd);
                g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
                return;
            }
        }

        if (!face_state->active_agent || face_state->active_agent != agent) {
            g_mutex_unlock(&face_state->lock);
            close(realfd);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        /* reject if busy */
        if (agent->busy) {
            g_mutex_unlock(&face_state->lock);
            close(realfd);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", FALSE));
            return;
        }

        agent->busy = TRUE;

        g_mutex_unlock(&face_state->lock);

        SubmitFrameJob *job = g_new0(SubmitFrameJob, 1);
        job->agent = face_agent_ref(agent);
        job->fd = realfd;
        job->width = width;
        job->height = height;
        job->channels = channels;
        job->format = format;

        FaceAgent *done_agent = face_agent_ref(agent);

        GTask *task = g_task_new(NULL, NULL, submit_frame_done, done_agent);
        g_task_set_task_data(task, job, (GDestroyNotify)submit_frame_job_free);
        g_task_run_in_thread(task, submit_frame_worker);
        g_object_unref(task);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        return;
    }

    g_dbus_method_invocation_return_error(invocation,
                                          G_DBUS_ERROR,
                                          G_DBUS_ERROR_UNKNOWN_METHOD,
                                          "Unknown agent method: %s", method_name);
}

static GVariant *
handle_face_agent_get_property(GDBusConnection *connection,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *property_name,
                               GError **error,
                               gpointer user_data)
{
    (void) connection;
    (void) sender;
    (void) object_path;
    (void) interface_name;

    FaceAgent *agent = (FaceAgent *)user_data;

    if (!face_state || !agent) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Agent not initialized");
        return NULL;
    }

    g_mutex_lock(&face_state->lock);

    if (g_strcmp0(property_name, "Busy") == 0) {
        gboolean v = agent->busy;
        g_mutex_unlock(&face_state->lock);
        return g_variant_new_boolean(v);
    } else if (g_strcmp0(property_name, "HasAccess") == 0) {
        gboolean v = agent->has_access;
        g_mutex_unlock(&face_state->lock);
        return g_variant_new_boolean(v);
    } else if (g_strcmp0(property_name, "LastEnrollmentState") == 0) {
        guint32 v = agent->last_enroll_state;
        g_mutex_unlock(&face_state->lock);
        return g_variant_new_uint32(v);
    } else if (g_strcmp0(property_name, "LastRecognitionState") == 0) {
        guint32 v = agent->last_recog_state;
        g_mutex_unlock(&face_state->lock);
        return g_variant_new_uint32(v);
    } else if (g_strcmp0(property_name, "EnrollmentProgress") == 0) {
        gint32 v = agent->enrollment_progress;
        g_mutex_unlock(&face_state->lock);
        return g_variant_new_int32(v);
    } else if (g_strcmp0(property_name, "Mode") == 0) {
        gint32 v = (gint32)agent->mode;
        g_mutex_unlock(&face_state->lock);
        return g_variant_new_int32(v);
    }

    g_mutex_unlock(&face_state->lock);

    g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
                "Unknown property: %s", property_name);
    return NULL;
}

static gboolean
handle_face_agent_set_property(GDBusConnection *connection,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *property_name,
                               GVariant *value,
                               GError **error,
                               gpointer user_data)
{
    (void) connection;
    (void) sender;
    (void) object_path;
    (void) interface_name;
    (void) value;
    (void) user_data;

    g_set_error(error,
                G_DBUS_ERROR,
                G_DBUS_ERROR_PROPERTY_READ_ONLY,
                "Property %s is not writable", property_name);
    return FALSE;
}

static const GDBusInterfaceVTable face_agent_interface_vtable = {
    handle_face_agent_method_call,
    handle_face_agent_get_property,
    handle_face_agent_set_property
};

static GVariant *
handle_face_get_property(GDBusConnection *connection,
                         const gchar *sender,
                         const gchar *object_path,
                         const gchar *interface_name,
                         const gchar *property_name,
                         GError **error,
                         gpointer user_data)
{
    (void) connection;
    (void) sender;
    (void) object_path;
    (void) interface_name;

    BiomFace *self = (BiomFace *)user_data;

    if (!self) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Face state not initialized");
        return NULL;
    }

    g_mutex_lock(&self->lock);

    if (g_strcmp0(property_name, "State") == 0) {
        gint32 v = (gint32)self->current_state;
        g_mutex_unlock(&self->lock);
        return g_variant_new_int32(v);
    } else if (g_strcmp0(property_name, "FaceEnrolled") == 0) {
        gboolean v = self->face_enrolled;
        g_mutex_unlock(&self->lock);
        return g_variant_new_boolean(v);
    } else if (g_strcmp0(property_name, "ImplementationType") == 0) {
        gint32 v = (gint32)self->implementation_type;
        g_mutex_unlock(&self->lock);
        return g_variant_new_int32(v);
    }

    g_mutex_unlock(&self->lock);

    g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
                "Unknown property: %s", property_name);
    return NULL;
}

static gboolean
handle_face_set_property(GDBusConnection *connection,
                         const gchar *sender,
                         const gchar *object_path,
                         const gchar *interface_name,
                         const gchar *property_name,
                         GVariant *value,
                         GError **error,
                         gpointer user_data)
{
    (void) connection;
    (void) sender;
    (void) object_path;
    (void) interface_name;
    (void) value;
    (void) user_data;

    g_set_error(error,
                G_DBUS_ERROR,
                G_DBUS_ERROR_PROPERTY_READ_ONLY,
                "Property %s is not writable", property_name);
    return FALSE;
}

static gboolean
register_agent_as_role_locked(const gchar *sender,
                              const gchar *agent_path,
                              FaceAgentRole role,
                              GError **error)
{
    if (!face_state) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Face state not initialized");
        return FALSE;
    }

    if (!sender || !*sender) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Sender missing");
        return FALSE;
    }

    if (!agent_path || !*agent_path || !g_variant_is_object_path(agent_path)) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Invalid agent path");
        return FALSE;
    }

    FaceAgent *agent = lookup_agent_by_path(agent_path);
    if (!agent) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Unknown agent path");
        return FALSE;
    }

    if (!sender_matches_agent_owner(sender, agent)) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED, "Not agent owner");
        return FALSE;
    }

    /* if it's already the requested role, this is a no-op success */
    if (agent->role == role) {
        recompute_access_and_notify_locked();
        return TRUE;
    }

    if (agent->role == FACE_AGENT_ROLE_ENROLLMENT) {
        if (face_state->enrollment_agent == agent) {
            /* clear enrollment registration */
            agent->has_access = FALSE;
            emit_agent_signal_access_changed(agent, FALSE);

            if (face_state->active_agent == agent) {
                face_state->current_state = STATE_IDLE;
                emit_manager_signal_state_changed(face_state->current_state);
                set_active_agent_locked(NULL);
            }

            set_enrollment_agent_locked(NULL);
        }

        agent->role = FACE_AGENT_ROLE_NONE;
        agent->mode = FACE_AGENT_MODE_NONE;
        agent->busy = FALSE;
        face_agent_reset_enrollment_state_locked(agent);
    } else if (agent->role == FACE_AGENT_ROLE_RECOGNITION) {
        if (face_state->recognition_agent == agent) {
            /* clear recognition registration */
            agent->has_access = FALSE;
            emit_agent_signal_access_changed(agent, FALSE);

            if (face_state->active_agent == agent) {
                face_state->current_state = STATE_IDLE;
                emit_manager_signal_state_changed(face_state->current_state);
                set_active_agent_locked(NULL);
            }

            set_recognition_agent_locked(NULL);
        }

        agent->role = FACE_AGENT_ROLE_NONE;
        agent->mode = FACE_AGENT_MODE_NONE;
        agent->busy = FALSE;
        face_agent_reset_recognition_state_locked(agent);
    }

    if (role == FACE_AGENT_ROLE_ENROLLMENT) {
        if (face_state->enrollment_agent && face_state->enrollment_agent != agent) {
            g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                        "Enrollment agent already registered");
            return FALSE;
        }
        set_enrollment_agent_locked(agent);
        agent->role = FACE_AGENT_ROLE_ENROLLMENT;
    } else if (role == FACE_AGENT_ROLE_RECOGNITION) {
        if (face_state->recognition_agent && face_state->recognition_agent != agent) {
            g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                        "Recognition agent already registered");
            return FALSE;
        }
        set_recognition_agent_locked(agent);
        agent->role = FACE_AGENT_ROLE_RECOGNITION;
    } else {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Invalid role");
        return FALSE;
    }

    recompute_access_and_notify_locked();
    return TRUE;
}

static void
unregister_role_locked(FaceAgentRole role)
{
    if (!face_state)
        return;

    if (role == FACE_AGENT_ROLE_ENROLLMENT) {
        FaceAgent *a = face_state->enrollment_agent;
        if (a) {
            /* fully reset agent role so it can register again */
            a->role = FACE_AGENT_ROLE_NONE;
            a->mode = FACE_AGENT_MODE_NONE;
            a->busy = FALSE;
            face_agent_reset_enrollment_state_locked(a);

            a->has_access = FALSE;
            emit_agent_signal_access_changed(a, FALSE);

            if (face_state->active_agent == a) {
                face_state->current_state = STATE_IDLE;
                emit_manager_signal_state_changed(face_state->current_state);
                set_active_agent_locked(NULL);
            }
        }
        set_enrollment_agent_locked(NULL);
    } else if (role == FACE_AGENT_ROLE_RECOGNITION) {
        FaceAgent *a = face_state->recognition_agent;
        if (a) {
            /* fully reset agent role so it can register again */
            a->role = FACE_AGENT_ROLE_NONE;
            a->mode = FACE_AGENT_MODE_NONE;
            a->busy = FALSE;
            face_agent_reset_recognition_state_locked(a);

            a->has_access = FALSE;
            emit_agent_signal_access_changed(a, FALSE);

            if (face_state->active_agent == a) {
                face_state->current_state = STATE_IDLE;
                emit_manager_signal_state_changed(face_state->current_state);
                set_active_agent_locked(NULL);
            }
        }
        set_recognition_agent_locked(NULL);
    }

    recompute_access_and_notify_locked();
}

static gboolean
destroy_agent_by_path_locked(const gchar *sender,
                             const gchar *agent_path,
                             GError **error)
{
    if (!face_state || !face_state->connection) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Face state not initialized");
        return FALSE;
    }

    if (!agent_path || !*agent_path || !g_variant_is_object_path(agent_path)) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Invalid agent path");
        return FALSE;
    }

    FaceAgent *agent = lookup_agent_by_path(agent_path);
    if (!agent) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "Unknown agent path");
        return FALSE;
    }

    if (!sender_matches_agent_owner(sender, agent)) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED, "Not agent owner");
        return FALSE;
    }

    if (face_state->enrollment_agent == agent)
        unregister_role_locked(FACE_AGENT_ROLE_ENROLLMENT);
    if (face_state->recognition_agent == agent)
        unregister_role_locked(FACE_AGENT_ROLE_RECOGNITION);

    if (face_state->active_agent == agent) {
        face_state->current_state = STATE_IDLE;
        emit_manager_signal_state_changed(face_state->current_state);
        set_active_agent_locked(NULL);
    }

    face_agent_reset_all_state_locked(agent);

    if (agent->reg_id != 0) {
        g_dbus_connection_unregister_object(face_state->connection, agent->reg_id);
        agent->reg_id = 0;
    }

    g_hash_table_remove(face_state->agents_by_path, agent->path);

    recompute_access_and_notify_locked();
    return TRUE;
}

static void
handle_face_method_call(GDBusConnection *connection,
                        const gchar *sender,
                        const gchar *object_path,
                        const gchar *interface_name,
                        const gchar *method_name,
                        GVariant *parameters,
                        GDBusMethodInvocation *invocation,
                        gpointer user_data)
{
    (void) connection;
    (void) object_path;
    (void) interface_name;

    BiomFace *self = (BiomFace *)user_data;

    if (!self || !face_state) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_FAILED,
                                              "Face state not initialized");
        return;
    }

    if (g_strcmp0(method_name, "CreateAgent") == 0) {
        gchar *new_path = make_next_agent_path();

        g_mutex_lock(&face_state->lock);

        if (!face_agent_introspection_data) {
            g_mutex_unlock(&face_state->lock);
            g_warning("Face Agent introspection not initialized");
            g_free(new_path);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", "/"));
            return;
        }

        FaceAgent *agent = face_agent_new(new_path, sender);
        GError *local_error = NULL;

        agent->reg_id = g_dbus_connection_register_object(
            self->connection,
            agent->path,
            face_agent_introspection_data->interfaces[0],
            &face_agent_interface_vtable,
            face_agent_ref(agent),
            (GDestroyNotify)face_agent_unref,
            &local_error);

        if (agent->reg_id == 0) {
            g_mutex_unlock(&face_state->lock);
            g_warning("Failed to register agent object: %s",
                      local_error ? local_error->message : "unknown");
            g_clear_error(&local_error);
            face_agent_unref(agent);
            g_free(new_path);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", "/"));
            return;
        }

        g_hash_table_insert(self->agents_by_path, g_strdup(agent->path), face_agent_ref(agent));
        recompute_access_and_notify_locked();

        g_mutex_unlock(&face_state->lock);

        face_agent_unref(agent);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", new_path));
        g_free(new_path);
        return;
    }

    if (g_strcmp0(method_name, "DestroyAgent") == 0) {
        const gchar *agent_path = NULL;
        g_variant_get(parameters, "(&o)", &agent_path);

        GError *local_error = NULL;

        g_mutex_lock(&face_state->lock);
        gboolean ok = destroy_agent_by_path_locked(sender, agent_path, &local_error);
        g_mutex_unlock(&face_state->lock);

        if (!ok) {
            g_dbus_method_invocation_return_gerror(invocation, local_error);
            g_clear_error(&local_error);
            return;
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        return;
    }

    if (g_strcmp0(method_name, "RegisterEnrollmentAgent") == 0) {
        const gchar *agent_path = NULL;
        g_variant_get(parameters, "(&o)", &agent_path);

        GError *local_error = NULL;

        g_mutex_lock(&face_state->lock);
        gboolean ok = register_agent_as_role_locked(sender, agent_path, FACE_AGENT_ROLE_ENROLLMENT, &local_error);
        g_mutex_unlock(&face_state->lock);

        if (!ok) {
            g_dbus_method_invocation_return_gerror(invocation, local_error);
            g_clear_error(&local_error);
            return;
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        return;
    }

    if (g_strcmp0(method_name, "UnregisterEnrollmentAgent") == 0) {
        g_mutex_lock(&face_state->lock);
        unregister_role_locked(FACE_AGENT_ROLE_ENROLLMENT);
        g_mutex_unlock(&face_state->lock);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        return;
    }

    if (g_strcmp0(method_name, "RegisterRecognitionAgent") == 0) {
        const gchar *agent_path = NULL;
        g_variant_get(parameters, "(&o)", &agent_path);

        GError *local_error = NULL;

        g_mutex_lock(&face_state->lock);
        gboolean ok = register_agent_as_role_locked(sender, agent_path, FACE_AGENT_ROLE_RECOGNITION, &local_error);
        g_mutex_unlock(&face_state->lock);

        if (!ok) {
            g_dbus_method_invocation_return_gerror(invocation, local_error);
            g_clear_error(&local_error);
            return;
        }

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        return;
    }

    if (g_strcmp0(method_name, "UnregisterRecognitionAgent") == 0) {
        g_mutex_lock(&face_state->lock);
        unregister_role_locked(FACE_AGENT_ROLE_RECOGNITION);
        g_mutex_unlock(&face_state->lock);

        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        return;
    }

    g_dbus_method_invocation_return_error(invocation,
                                          G_DBUS_ERROR,
                                          G_DBUS_ERROR_UNKNOWN_METHOD,
                                          "Unknown method: %s", method_name);
}

static const GDBusInterfaceVTable face_interface_vtable = {
    handle_face_method_call,
    handle_face_get_property,
    handle_face_set_property
};

static void
on_name_owner_changed(GDBusConnection *conn,
                      const gchar *sender_name,
                      const gchar *object_path,
                      const gchar *interface_name,
                      const gchar *signal_name,
                      GVariant *parameters,
                      gpointer user_data)
{
    (void) conn;
    (void) sender_name;
    (void) object_path;
    (void) interface_name;
    (void) signal_name;
    (void) user_data;

    const gchar *name = NULL;
    const gchar *old_owner = NULL;
    const gchar *new_owner = NULL;

    g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);

    /* unique name disappeared when new_owner == "" */
    if (!name || name[0] != ':' || (new_owner && *new_owner))
        return;

    if (!face_state)
        return;

    g_mutex_lock(&face_state->lock);

    if (face_state->enrollment_agent &&
        face_state->enrollment_agent->owner &&
        g_strcmp0(face_state->enrollment_agent->owner, name) == 0) {
        g_debug("Enrollment agent vanished (%s), unregistering", name);
        unregister_role_locked(FACE_AGENT_ROLE_ENROLLMENT);
    }

    if (face_state->recognition_agent &&
        face_state->recognition_agent->owner &&
        g_strcmp0(face_state->recognition_agent->owner, name) == 0) {
        g_debug("Recognition agent vanished (%s), unregistering", name);
        unregister_role_locked(FACE_AGENT_ROLE_RECOGNITION);
    }

    if (face_state->active_agent &&
        face_state->active_agent->owner &&
        g_strcmp0(face_state->active_agent->owner, name) == 0) {
        face_state->current_state = STATE_IDLE;
        emit_manager_signal_state_changed(face_state->current_state);

        face_agent_reset_all_state_locked(face_state->active_agent);
        set_active_agent_locked(NULL);
    }

    if (face_state->agents_by_path) {
        GHashTableIter iter;
        gpointer k, v;

        g_hash_table_iter_init(&iter, face_state->agents_by_path);
        while (g_hash_table_iter_next(&iter, &k, &v)) {
            FaceAgent *agent = (FaceAgent*)v;
            if (agent && agent->owner && g_strcmp0(agent->owner, name) == 0) {
                if (face_state->connection && agent->reg_id) {
                    g_dbus_connection_unregister_object(face_state->connection, agent->reg_id);
                    agent->reg_id = 0;
                }
                g_hash_table_iter_remove(&iter);
            }
        }
    }

    recompute_access_and_notify_locked();

    g_mutex_unlock(&face_state->lock);
}

guint
face_register(GDBusConnection *connection, GError **error)
{
    if (!connection) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Connection is NULL");
        return 0;
    }

    if (!face_introspection_data || !face_agent_introspection_data) {
        g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Face introspection not initialized");
        return 0;
    }

    return g_dbus_connection_register_object(
        connection,
        "/io/FuriOS/Biomd/Face",
        face_introspection_data->interfaces[0],
        &face_interface_vtable,
        face_state,
        NULL,
        error);
}

BiometricState
face_get_state(void)
{
    if (!face_state)
        return STATE_IDLE;

    g_mutex_lock(&face_state->lock);
    BiometricState s = face_state->current_state;
    g_mutex_unlock(&face_state->lock);
    return s;
}

gboolean
face_get_enrolled(void)
{
    if (!face_state)
        return FALSE;

    g_mutex_lock(&face_state->lock);
    gboolean e = face_state->face_enrolled;
    g_mutex_unlock(&face_state->lock);
    return e;
}

FaceImplementationType
face_get_implementation_type(void)
{
    if (!face_state)
        return TYPE_UNKNOWN;

    g_mutex_lock(&face_state->lock);
    FaceImplementationType t = face_state->implementation_type;
    g_mutex_unlock(&face_state->lock);
    return t;
}

void
face_init(GDBusConnection *connection)
{
    GError *error = NULL;

    face_state = g_new0(BiomFace, 1);
    face_state->current_state = STATE_IDLE;
    face_state->face_enrolled = FALSE;
    face_state->implementation_type = TYPE_UNKNOWN;

    face_state->enrollment_agent = NULL;
    face_state->recognition_agent = NULL;
    face_state->active_agent = NULL;

    face_state->agents_by_path = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)face_agent_unref);
    face_state->next_agent_id = 1;

    face_state->connection = connection;
    face_state->name_owner_changed_sub = 0;
    face_state->backend = NULL;

    g_mutex_init(&face_state->lock);

    face_introspection_data = g_dbus_node_info_new_for_xml(face_introspection_xml, &error);
    if (error) {
        g_warning("Parsing Face introspection XML: %s", error->message);
        g_clear_error(&error);
    }

    face_agent_introspection_data = g_dbus_node_info_new_for_xml(face_agent_introspection_xml, &error);
    if (error) {
        g_warning("Parsing Face Agent introspection XML: %s", error->message);
        g_clear_error(&error);
    }

    FaceBackendCallbacks cb = {
        .enrollment_state = on_backend_enrollment_state,
        .enrollment_progress = on_backend_enrollment_progress,
        .recognition_state = on_backend_recognition_state,
        .error = NULL,
        .user_data = face_state
    };

    face_state->backend = face_fart_backend_new(cb);
    if (!face_state->backend) {
        g_warning("Failed to create face backend");
        face_state->implementation_type = TYPE_UNKNOWN;
        face_state->face_enrolled = FALSE;
    } else {
        face_state->implementation_type = TYPE_SOFTWARE;

        if (face_backend_is_available(face_state->backend))
            face_backend_setup_default(face_state->backend);

        face_state->face_enrolled = face_backend_is_enrolled(face_state->backend);
        g_debug("Initial FaceEnrolled=%d", face_state->face_enrolled ? 1 : 0);
    }

    /* watch disappearing agents */
    if (connection)
        face_state->name_owner_changed_sub =
            g_dbus_connection_signal_subscribe(
                connection,
                "org.freedesktop.DBus",
                "org.freedesktop.DBus",
                "NameOwnerChanged",
                "/org/freedesktop/DBus",
                NULL,
                G_DBUS_SIGNAL_FLAGS_NONE,
                on_name_owner_changed,
                NULL,
                NULL);

    emit_manager_signal_state_changed(face_state->current_state);
    emit_manager_signal_face_enrolled_changed(face_state->face_enrolled);
}

void
face_cleanup(GDBusConnection *connection)
{
    (void) connection;

    if (face_state) {
        if (face_state->connection && face_state->name_owner_changed_sub) {
            g_dbus_connection_signal_unsubscribe(face_state->connection,
                                                 face_state->name_owner_changed_sub);
            face_state->name_owner_changed_sub = 0;
        }

        if (face_state->agents_by_path) {
            GHashTableIter iter;
            gpointer k, v;

            g_hash_table_iter_init(&iter, face_state->agents_by_path);
            while (g_hash_table_iter_next(&iter, &k, &v)) {
                FaceAgent *agent = (FaceAgent *)v;
                if (agent && face_state->connection && agent->reg_id) {
                    g_dbus_connection_unregister_object(face_state->connection, agent->reg_id);
                    agent->reg_id = 0;
                }
            }

            g_hash_table_unref(face_state->agents_by_path);
            face_state->agents_by_path = NULL;
        }

        if (face_state->backend) {
            face_backend_free(face_state->backend);
            face_state->backend = NULL;
        }

        if (face_state->active_agent)
            face_agent_unref(face_state->active_agent);
        if (face_state->enrollment_agent)
            face_agent_unref(face_state->enrollment_agent);
        if (face_state->recognition_agent)
            face_agent_unref(face_state->recognition_agent);

        face_state->active_agent = NULL;
        face_state->enrollment_agent = NULL;
        face_state->recognition_agent = NULL;

        g_mutex_clear(&face_state->lock);

        g_free(face_state);
        face_state = NULL;
    }

    if (face_introspection_data) {
        g_dbus_node_info_unref(face_introspection_data);
        face_introspection_data = NULL;
    }

    if (face_agent_introspection_data) {
        g_dbus_node_info_unref(face_agent_introspection_data);
        face_agent_introspection_data = NULL;
    }
}
