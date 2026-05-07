/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#include "face_tensorflow_fart.h"

#include <unistd.h>
#include <fcntl.h>

#include <glib/gstdio.h>

#include <openssl/rand.h>

#include <fart/fart.h>

#define BIOMD_FACE_DATA_DIR  "/var/lib/biomd"
#define BIOMD_FACE_DATA_FILE "face.dat"
#define BIOMD_FACE_KEY_FILE  "face.key"

#define FACE_ENC_MAGIC "BMFACE1"
#define FACE_ENC_MAGIC_LEN 7
#define FACE_KEY_SIZE 32
#define FACE_NONCE_SIZE 12
#define FACE_TAG_SIZE 16

typedef struct {
    gint fd;
    gint width;
    gint height;
    gint channels;
    guint32 format;
    FaceTfFartMode mode;
} FrameJob;

struct _BiomFaceTensorflowFart {
    gchar *detection_model;
    gchar *recognition_model;
    gchar *anti_spoof_model;
    gchar *data_dir;
    gchar *data_path;
    gchar *key_path;

    gboolean available;

    FaceTfFartMode mode;

    FaceAnalysisRecognition *fart_handle;

    GThread *worker;
    GAsyncQueue *queue;
    gboolean running;

    GMutex state_lock;
    guint32 last_state;
    gboolean enrolled_cached;
    guint32 enroll_progress_cached;
};

static void
secure_memzero(void *ptr, gsize len)
{
    if (!ptr || len == 0)
        return;

    volatile guint8 *p = (volatile guint8 *)ptr;
    while (len--)
        *p++ = 0;
}

static const char *
mode_to_string(FaceTfFartMode mode)
{
    switch (mode) {
        case TF_FART_MODE_NONE: return "NONE";
        case TF_FART_MODE_ENROLL: return "ENROLL";
        case TF_FART_MODE_RECOGNIZE: return "RECOGNIZE";
        default: return "UNKNOWN";
    }
}

static const char *
format_to_string(guint32 fmt)
{
    switch (fmt) {
        case (guint32)FACE_FRAME_FORMAT_BGR:  return "BGR";
        case (guint32)FACE_FRAME_FORMAT_RGB:  return "RGB";
        case (guint32)FACE_FRAME_FORMAT_GRAY: return "GRAY";
        default: return "UNKNOWN_FMT";
    }
}

static gint64
now_monotonic_ns(void)
{
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return ((gint64)ts.tv_sec * 1000000000LL) + (gint64)ts.tv_nsec;
#endif
    return (gint64)g_get_monotonic_time() * 1000LL;
}

static gboolean
fd_get_size(gint fd, gsize *out_size)
{
    if (!out_size)
        return FALSE;

    struct stat st;
    if (fstat(fd, &st) != 0)
        return FALSE;

    if (st.st_size < 0)
        return FALSE;

    *out_size = (gsize)st.st_size;
    return TRUE;
}

static gboolean
read_exact_into_buffer(gint fd, guint8 *dst, gsize bytes)
{
    gsize off = 0;
    while (off < bytes) {
        ssize_t r = read(fd, dst + off, bytes - off);
        if (r == 0) {
            g_debug("read_exact_into_buffer: EOF at off=%zu / %zu", off, bytes);
            return FALSE;
        }
        if (r < 0) {
            if (errno == EINTR)
                continue;
            g_debug("read_exact_into_buffer: read() failed at off=%zu / %zu: %s",
                    off, bytes, g_strerror(errno));
            return FALSE;
        }
        off += (gsize)r;
    }
    return TRUE;
}

static gboolean
write_all(int fd, const guint8 *buf, gsize len)
{
    gsize off = 0;

    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return FALSE;
        }
        if (w == 0)
            return FALSE;

        off += (gsize)w;
    }

    return TRUE;
}

static gboolean
ensure_data_dir_exists(const gchar *dir_path)
{
    if (!dir_path || !*dir_path)
        return FALSE;

    if (g_file_test(dir_path, G_FILE_TEST_IS_DIR)) {
        if (chmod(dir_path, 0700) != 0)
            g_warning("Failed to chmod data dir '%s': %s", dir_path, g_strerror(errno));
        return TRUE;
    }

    if (g_mkdir_with_parents(dir_path, 0700) != 0) {
        g_warning("Failed to create face data dir '%s': %s", dir_path, g_strerror(errno));
        return FALSE;
    }

    if (chmod(dir_path, 0700) != 0)
        g_warning("Failed to chmod data dir '%s': %s", dir_path, g_strerror(errno));

    return TRUE;
}

static gboolean
file_is_root_only(const gchar *path, gboolean must_exist)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        if (!must_exist && errno == ENOENT)
            return TRUE;

        g_warning("stat('%s') failed: %s", path, g_strerror(errno));
        return FALSE;
    }

    if (st.st_uid != 0) {
        g_warning("Refusing to use '%s': owner uid is %u, expected root", path, (unsigned)st.st_uid);
        return FALSE;
    }

    if ((st.st_mode & 077) != 0) {
        g_warning("Refusing to use '%s': group/other permissions are too open: %o",
                  path, (unsigned)(st.st_mode & 0777));
        return FALSE;
    }

    return TRUE;
}

static gboolean
load_or_create_key(const gchar *key_path, guint8 key[FACE_KEY_SIZE])
{
    gchar *contents = NULL;
    gsize len = 0;

    if (g_file_test(key_path, G_FILE_TEST_EXISTS)) {
        if (!file_is_root_only(key_path, TRUE))
            return FALSE;

        if (!g_file_get_contents(key_path, &contents, &len, NULL)) {
            g_warning("Failed to read face key '%s'", key_path);
            return FALSE;
        }

        if (len != FACE_KEY_SIZE) {
            g_warning("Invalid face key size in '%s': %zu", key_path, len);
            secure_memzero(contents, len);
            g_free(contents);
            return FALSE;
        }

        memcpy(key, contents, FACE_KEY_SIZE);
        secure_memzero(contents, len);
        g_free(contents);
        return TRUE;
    }

    if (RAND_bytes(key, FACE_KEY_SIZE) != 1) {
        g_warning("RAND_bytes failed while generating face key");
        return FALSE;
    }

    int fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        g_warning("Failed to create face key '%s': %s", key_path, g_strerror(errno));
        secure_memzero(key, FACE_KEY_SIZE);
        return FALSE;
    }

    gboolean ok = write_all(fd, key, FACE_KEY_SIZE);

    if (fsync(fd) != 0)
        g_warning("fsync failed for face key '%s': %s", key_path, g_strerror(errno));

    if (close(fd) != 0)
        g_warning("close failed for face key '%s': %s", key_path, g_strerror(errno));

    if (!ok) {
        g_warning("Failed to write face key '%s'", key_path);
        g_remove(key_path);
        secure_memzero(key, FACE_KEY_SIZE);
        return FALSE;
    }

    if (chmod(key_path, 0600) != 0) {
        g_warning("Failed to chmod face key '%s': %s", key_path, g_strerror(errno));
        g_remove(key_path);
        secure_memzero(key, FACE_KEY_SIZE);
        return FALSE;
    }

    if (!file_is_root_only(key_path, TRUE)) {
        g_remove(key_path);
        secure_memzero(key, FACE_KEY_SIZE);
        return FALSE;
    }

    return TRUE;
}

static gboolean
encrypt_json_to_file(const gchar *path, const guint8 key[FACE_KEY_SIZE], const gchar *json)
{
    if (!path || !key || !json)
        return FALSE;

    guint8 nonce[FACE_NONCE_SIZE];
    guint8 tag[FACE_TAG_SIZE];

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        g_warning("RAND_bytes failed while generating face data nonce");
        return FALSE;
    }

    gsize plaintext_len = strlen(json);
    int out_len1 = 0;
    int out_len2 = 0;

    guint8 *ciphertext = g_malloc0(plaintext_len + EVP_MAX_BLOCK_LENGTH);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        g_free(ciphertext);
        return FALSE;
    }

    gboolean ok = FALSE;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, FACE_NONCE_SIZE, NULL) != 1)
        goto out;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;

    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len1, (const guint8 *)json, (int)plaintext_len) != 1)
        goto out;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len1, &out_len2) != 1)
        goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, FACE_TAG_SIZE, tag) != 1)
        goto out;

    gsize ciphertext_len = (gsize)(out_len1 + out_len2);
    gsize total_len = FACE_ENC_MAGIC_LEN + FACE_NONCE_SIZE + FACE_TAG_SIZE + ciphertext_len;
    guint8 *file_buf = g_malloc0(total_len);

    gsize off = 0;
    memcpy(file_buf + off, FACE_ENC_MAGIC, FACE_ENC_MAGIC_LEN);
    off += FACE_ENC_MAGIC_LEN;
    memcpy(file_buf + off, nonce, FACE_NONCE_SIZE);
    off += FACE_NONCE_SIZE;
    memcpy(file_buf + off, tag, FACE_TAG_SIZE);
    off += FACE_TAG_SIZE;
    memcpy(file_buf + off, ciphertext, ciphertext_len);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        g_warning("Failed to open encrypted face data '%s': %s", path, g_strerror(errno));
        g_free(file_buf);
        goto out;
    }

    ok = write_all(fd, file_buf, total_len);

    if (fsync(fd) != 0)
        g_warning("fsync failed for encrypted face data '%s': %s", path, g_strerror(errno));

    if (close(fd) != 0)
        g_warning("close failed for encrypted face data '%s': %s", path, g_strerror(errno));

    if (chmod(path, 0600) != 0) {
        g_warning("Failed to chmod encrypted face data '%s': %s", path, g_strerror(errno));
        ok = FALSE;
    }

    if (!file_is_root_only(path, TRUE))
        ok = FALSE;

    secure_memzero(file_buf, total_len);
    g_free(file_buf);

out:
    EVP_CIPHER_CTX_free(ctx);
    secure_memzero(ciphertext, plaintext_len + EVP_MAX_BLOCK_LENGTH);
    g_free(ciphertext);
    secure_memzero(nonce, sizeof(nonce));
    secure_memzero(tag, sizeof(tag));

    return ok;
}

static gchar *
decrypt_json_from_file(const gchar *path, const guint8 key[FACE_KEY_SIZE])
{
    if (!path || !key)
        return NULL;

    if (!g_file_test(path, G_FILE_TEST_EXISTS))
        return g_strdup("");

    if (!file_is_root_only(path, TRUE))
        return NULL;

    gchar *contents = NULL;
    gsize len = 0;

    if (!g_file_get_contents(path, &contents, &len, NULL)) {
        g_warning("Failed to read encrypted face data '%s'", path);
        return NULL;
    }

    if (len < FACE_ENC_MAGIC_LEN + FACE_NONCE_SIZE + FACE_TAG_SIZE) {
        g_warning("Encrypted face data '%s' is too small", path);
        secure_memzero(contents, len);
        g_free(contents);
        return NULL;
    }

    guint8 *p = (guint8 *)contents;

    if (memcmp(p, FACE_ENC_MAGIC, FACE_ENC_MAGIC_LEN) != 0) {
        g_warning("Encrypted face data '%s' has invalid magic", path);
        secure_memzero(contents, len);
        g_free(contents);
        return NULL;
    }

    gsize off = FACE_ENC_MAGIC_LEN;
    guint8 *nonce = p + off;
    off += FACE_NONCE_SIZE;
    guint8 *tag = p + off;
    off += FACE_TAG_SIZE;

    guint8 *ciphertext = p + off;
    gsize ciphertext_len = len - off;

    guint8 *plaintext = g_malloc0(ciphertext_len + 1);
    int out_len1 = 0;
    int out_len2 = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_memzero(contents, len);
        g_free(contents);
        g_free(plaintext);
        return NULL;
    }

    gchar *json = NULL;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, FACE_NONCE_SIZE, NULL) != 1)
        goto out;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;

    if (EVP_DecryptUpdate(ctx, plaintext, &out_len1, ciphertext, (int)ciphertext_len) != 1)
        goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, FACE_TAG_SIZE, tag) != 1)
        goto out;

    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len1, &out_len2) != 1) {
        g_warning("Failed to authenticate/decrypt encrypted face data '%s'", path);
        goto out;
    }

    plaintext[out_len1 + out_len2] = '\0';
    json = g_strdup((const gchar *)plaintext);

out:
    EVP_CIPHER_CTX_free(ctx);
    secure_memzero(contents, len);
    secure_memzero(plaintext, ciphertext_len + 1);
    g_free(contents);
    g_free(plaintext);

    return json;
}

static gboolean
persist_enrollment_json(BiomFaceTensorflowFart *self)
{
    if (!self || !self->fart_handle || !self->data_path || !self->key_path)
        return FALSE;

    guint8 key[FACE_KEY_SIZE];

    if (!load_or_create_key(self->key_path, key))
        return FALSE;

    char *json = fart_export_enrollment_json(self->fart_handle);
    if (!json) {
        g_warning("Failed to export enrollment JSON from libfart");
        secure_memzero(key, sizeof(key));
        return FALSE;
    }

    gboolean ok = FALSE;

    if (json[0] == '\0')
        g_warning("Refusing to save empty enrollment JSON");
    else
        ok = encrypt_json_to_file(self->data_path, key, json);

    secure_memzero(json, strlen(json));
    fart_free_string(json);
    secure_memzero(key, sizeof(key));

    if (!ok)
        g_warning("Failed to persist encrypted face data");

    return ok;
}

typedef struct {
    BiomFaceTensorflowFart *self;
    guint32 state;
    gboolean enrolled;
    guint32 enroll_progress;
} PublishCtx;

static gboolean
publish_state_idle(gpointer user_data)
{
    PublishCtx *ctx = (PublishCtx *)user_data;
    BiomFaceTensorflowFart *self = ctx->self;

    g_mutex_lock(&self->state_lock);
    self->last_state = ctx->state;
    self->enrolled_cached = ctx->enrolled;
    self->enroll_progress_cached = ctx->enroll_progress;
    g_mutex_unlock(&self->state_lock);

    g_debug("publish_state_idle: last_state=%u enrolled_cached=%d enroll_progress=%u",
            ctx->state, ctx->enrolled, ctx->enroll_progress);

    g_free(ctx);
    return G_SOURCE_REMOVE;
}

static void
publish_state_async(BiomFaceTensorflowFart *self, guint32 state, guint32 enroll_progress)
{
    PublishCtx *ctx = g_new0(PublishCtx, 1);
    ctx->self = self;
    ctx->state = state;
    ctx->enrolled = (self->fart_handle != NULL) ? (fart_is_enrolled(self->fart_handle) ? TRUE : FALSE) : FALSE;

    if (enroll_progress > 100)
        enroll_progress = 100;

    ctx->enroll_progress = enroll_progress;

    g_debug("publish_state_async: scheduling state=%u enrolled_now=%d progress=%u",
            state, ctx->enrolled, ctx->enroll_progress);

    g_idle_add(publish_state_idle, ctx);
}

static void
frame_job_free(FrameJob *job)
{
    if (!job)
        return;
    if (job->fd >= 0)
        close(job->fd);
    g_free(job);
}

static gpointer
worker_thread_main(gpointer user_data)
{
    BiomFaceTensorflowFart *self = (BiomFaceTensorflowFart *)user_data;

    g_debug("face worker thread started");

    while (TRUE) {
        FrameJob *job = (FrameJob *)g_async_queue_pop(self->queue);
        if (!job)
            continue;

        if (job->fd == -1 && job->width == 0 && job->height == 0 && job->channels == 0) {
            g_debug("face worker thread got poison pill, exiting");
            frame_job_free(job);
            break;
        }

        if (!self->running || !self->available || !self->fart_handle) {
            g_debug("face worker thread dropping frame (running=%d available=%d handle=%p)",
                    self->running, self->available, self->fart_handle);
            frame_job_free(job);
            continue;
        }

        if (job->fd < 0 || job->width <= 0 || job->height <= 0 || job->channels <= 0) {
            g_debug("face worker thread invalid job params fd=%d w=%d h=%d c=%d",
                    job->fd, job->width, job->height, job->channels);
            publish_state_async(self, (guint32)RECOGNITION_FAIL, self->enroll_progress_cached);
            frame_job_free(job);
            continue;
        }

        if (job->format != (guint32)FACE_FRAME_FORMAT_BGR) {
            g_debug("face worker thread rejecting non-BGR format=%u (%s)",
                    job->format, format_to_string(job->format));
            publish_state_async(self, (guint32)RECOGNITION_FAIL, self->enroll_progress_cached);
            frame_job_free(job);
            continue;
        }

        const gsize expected = (gsize)job->width * (gsize)job->height * (gsize)job->channels;

        gsize fd_size = 0;
        if (fd_get_size(job->fd, &fd_size)) {
            if (fd_size < expected) {
                g_debug("face worker thread fd_size too small: fd_size=%zu expected=%zu (w=%d h=%d c=%d)",
                        fd_size, expected, job->width, job->height, job->channels);
                publish_state_async(self, (guint32)RECOGNITION_FAIL, self->enroll_progress_cached);
                frame_job_free(job);
                continue;
            }
            if (fd_size != expected)
                g_debug("face worker thread fd_size differs from expected: fd_size=%zu expected=%zu (extra=%zd)",
                        fd_size, expected, (ssize_t)fd_size - (ssize_t)expected);
        } else {
            g_debug("face worker thread fstat(fd=%d) failed: %s", job->fd, g_strerror(errno));
        }

        guint8 *buf = (guint8 *)g_malloc(expected);
        if (!buf) {
            g_debug("face worker thread g_malloc(%zu) failed", expected);
            publish_state_async(self, (guint32)RECOGNITION_FAIL, self->enroll_progress_cached);
            frame_job_free(job);
            continue;
        }

        if (lseek(job->fd, 0, SEEK_SET) < 0) {
            g_debug("face worker thread lseek(fd=%d) failed: %s", job->fd, g_strerror(errno));
            g_free(buf);
            publish_state_async(self, (guint32)RECOGNITION_FAIL, self->enroll_progress_cached);
            frame_job_free(job);
            continue;
        }

        gint64 t_read0 = now_monotonic_ns();
        if (!read_exact_into_buffer(job->fd, buf, expected)) {
            gint64 t_read1 = now_monotonic_ns();
            g_debug("face worker thread read_exact failed (%zu bytes) after %.2f ms",
                    expected, (double)(t_read1 - t_read0) / 1000000.0);
            g_free(buf);
            publish_state_async(self, (guint32)RECOGNITION_FAIL, self->enroll_progress_cached);
            frame_job_free(job);
            continue;
        }
        gint64 t_read1 = now_monotonic_ns();

        guint32 s0 = 0;
        if (expected >= 16)
            s0 = (guint32)buf[0] | ((guint32)buf[1] << 8) | ((guint32)buf[2] << 16) | ((guint32)buf[3] << 24);

        g_debug("face worker thread worker: got frame mode=%s w=%d h=%d c=%d fmt=%s expected=%zu read_ms=%.2f first_u32=0x%08x",
                mode_to_string(job->mode),
                job->width, job->height, job->channels,
                format_to_string(job->format),
                expected,
                (double)(t_read1 - t_read0) / 1000000.0,
                s0);

        guint32 state = (guint32)RECOGNITION_FAIL;
        guint32 progress_to_publish = self->enroll_progress_cached;

        gint64 t_inf0 = now_monotonic_ns();

        if (job->mode == TF_FART_MODE_ENROLL) {
            int prog = 0;
            EnrollmentState s = fart_enroll(self->fart_handle,
                                            buf,
                                            job->width, job->height, job->channels,
                                            &prog);

            if (prog < 0)
                prog = 0;
            if (prog > 100)
                prog = 100;

            state = (guint32)s;
            progress_to_publish = (guint32)prog;

            if (s == ENROLLMENT_COMPLETE) {
                if (!persist_enrollment_json(self)) {
                    state = (guint32)ENROLLMENT_SAVE_FAILED;
                    g_warning("Enrollment completed but encrypted save failed");
                } else {
                    g_debug("Enrollment completed and encrypted face data saved to '%s'", self->data_path);
                }
            }

            g_debug("face worker thread fart_enroll %u (progress=%d enrolled_now=%d)",
                    state, prog, fart_is_enrolled(self->fart_handle) ? 1 : 0);
        } else if (job->mode == TF_FART_MODE_RECOGNIZE) {
            if (!fart_is_enrolled(self->fart_handle)) {
                state = (guint32)RECOGNITION_NOT_ENROLLED;
                g_debug("face worker thread recognize requested but not enrolled -> %u", state);
            } else {
                RecognitionState s = fart_recognize(self->fart_handle,
                                                    buf,
                                                    job->width,
                                                    job->height,
                                                    job->channels);
                state = (guint32)s;
                g_debug("face worker thread fart_recognize %u", (guint32)s);
            }
        } else {
            g_debug("face worker thread mode NONE, returning FAIL");
            state = (guint32)RECOGNITION_FAIL;
        }

        gint64 t_inf1 = now_monotonic_ns();

        g_debug("face worker thread inference_ms=%.2f state=%u progress=%u",
                (double)(t_inf1 - t_inf0) / 1000000.0, state, progress_to_publish);

        secure_memzero(buf, expected);
        g_free(buf);

        publish_state_async(self, state, progress_to_publish);
        frame_job_free(job);
    }

    g_debug("face worker thread stopped");
    return NULL;
}

static void
drain_queue(BiomFaceTensorflowFart *self)
{
    if (!self || !self->queue)
        return;

    int drained = 0;
    while (TRUE) {
        FrameJob *job = (FrameJob *)g_async_queue_try_pop(self->queue);
        if (!job)
            break;
        drained++;
        frame_job_free(job);
    }

    if (drained > 0)
        g_debug("drain_queue: drained %d pending frame(s)", drained);
}

BiomFaceTensorflowFart *
face_tensorflow_fart_init(const gchar *detection_model,
                          const gchar *recognition_model,
                          const gchar *anti_spoof_model)
{
    BiomFaceTensorflowFart *self;

    if (!detection_model || !recognition_model) {
        g_warning("Invalid tensorflow model paths");
        return NULL;
    }

    self = g_new0(BiomFaceTensorflowFart, 1);
    self->detection_model = g_strdup(detection_model);
    self->recognition_model = g_strdup(recognition_model);
    self->anti_spoof_model = g_strdup(anti_spoof_model);
    self->data_dir = g_strdup(BIOMD_FACE_DATA_DIR);
    self->data_path = g_build_filename(BIOMD_FACE_DATA_DIR, BIOMD_FACE_DATA_FILE, NULL);
    self->key_path = g_build_filename(BIOMD_FACE_DATA_DIR, BIOMD_FACE_KEY_FILE, NULL);

    self->queue = g_async_queue_new();
    self->running = TRUE;
    self->mode = TF_FART_MODE_NONE;

    g_mutex_init(&self->state_lock);
    self->last_state = (guint32)RECOGNITION_FAIL;
    self->enrolled_cached = FALSE;
    self->enroll_progress_cached = 0;

    if (!ensure_data_dir_exists(self->data_dir)) {
        g_warning("Failed to ensure data dir exists: %s", self->data_dir);
        self->available = FALSE;
        face_tensorflow_fart_cleanup(self);
        return NULL;
    }

    guint8 key[FACE_KEY_SIZE];
    if (!load_or_create_key(self->key_path, key)) {
        g_warning("Failed to load/create encrypted face data key");
        self->available = FALSE;
        face_tensorflow_fart_cleanup(self);
        return NULL;
    }

    gchar *enrollment_json = decrypt_json_from_file(self->data_path, key);
    secure_memzero(key, sizeof(key));

    if (!enrollment_json) {
        g_warning("Failed to decrypt/load encrypted face data");
        self->available = FALSE;
        face_tensorflow_fart_cleanup(self);
        return NULL;
    }

    self->fart_handle = fart_create(self->detection_model,
                                    self->recognition_model,
                                    self->anti_spoof_model,
                                    NULL,
                                    enrollment_json);

    secure_memzero(enrollment_json, strlen(enrollment_json));
    g_free(enrollment_json);

    if (!self->fart_handle) {
        g_warning("Failed to create libfart handle in JSON/in-memory mode");
        self->available = FALSE;
        face_tensorflow_fart_cleanup(self);
        return NULL;
    }

    self->available = TRUE;
    self->enrolled_cached = fart_is_enrolled(self->fart_handle) ? TRUE : FALSE;

    self->worker = g_thread_new("face-tf-fart-worker", worker_thread_main, self);
    if (!self->worker) {
        g_warning("Failed to start worker thread");
        face_tensorflow_fart_cleanup(self);
        return NULL;
    }

    g_debug("Initialized TensorFlow FART with detection='%s' recognition='%s' anti_spoof='%s' data_path='%s'",
            self->detection_model,
            self->recognition_model,
            self->anti_spoof_model ? self->anti_spoof_model : "(disabled)",
            self->data_path);

    return self;
}

void
face_tensorflow_fart_cleanup(BiomFaceTensorflowFart *self)
{
    if (!self)
        return;

    g_debug("Cleaning up TensorFlow FART");

    self->running = FALSE;

    if (self->queue) {
        FrameJob *poison = g_new0(FrameJob, 1);
        poison->fd = -1;
        poison->width = 0;
        poison->height = 0;
        poison->channels = 0;
        poison->format = (guint32)FACE_FRAME_FORMAT_BGR;
        poison->mode = TF_FART_MODE_NONE;
        g_async_queue_push(self->queue, poison);
    }

    if (self->worker) {
        g_thread_join(self->worker);
        self->worker = NULL;
    }

    drain_queue(self);

    if (self->queue) {
        g_async_queue_unref(self->queue);
        self->queue = NULL;
    }

    if (self->fart_handle) {
        fart_destroy(self->fart_handle);
        self->fart_handle = NULL;
    }

    g_free(self->detection_model);
    g_free(self->recognition_model);
    g_free(self->anti_spoof_model);
    g_free(self->data_dir);
    g_free(self->data_path);
    g_free(self->key_path);

    g_mutex_clear(&self->state_lock);

    g_free(self);
}

gboolean
face_tensorflow_fart_is_available(BiomFaceTensorflowFart *self)
{
    return self && self->available && self->fart_handle != NULL;
}

gboolean
face_tensorflow_fart_setup(BiomFaceTensorflowFart *self)
{
    if (!self || !self->available || !self->fart_handle) {
        g_warning("TensorFlow FART not available for setup");
        return FALSE;
    }

    g_debug("TensorFlow FART setup complete");
    return TRUE;
}

gboolean
face_tensorflow_fart_start_enroll(BiomFaceTensorflowFart *self)
{
    if (!self || !self->available || !self->fart_handle) {
        g_warning("TensorFlow FART not available for enrollment");
        return FALSE;
    }

    self->mode = TF_FART_MODE_ENROLL;

    g_mutex_lock(&self->state_lock);
    self->last_state = (guint32)ENROLLMENT_IN_PROGRESS;
    self->enroll_progress_cached = 0;
    g_mutex_unlock(&self->state_lock);

    g_debug("TensorFlow FART enrollment started");
    return TRUE;
}

gboolean
face_tensorflow_fart_start_recognize(BiomFaceTensorflowFart *self)
{
    if (!self || !self->available || !self->fart_handle) {
        g_warning("TensorFlow FART not available for recognition");
        return FALSE;
    }

    self->mode = TF_FART_MODE_RECOGNIZE;

    g_mutex_lock(&self->state_lock);
    self->last_state = (guint32)RECOGNITION_FAIL;
    g_mutex_unlock(&self->state_lock);

    g_debug("TensorFlow FART recognition started");
    return TRUE;
}

gboolean
face_tensorflow_fart_cancel(BiomFaceTensorflowFart *self)
{
    if (!self)
        return FALSE;

    self->mode = TF_FART_MODE_NONE;
    drain_queue(self);

    g_mutex_lock(&self->state_lock);
    self->last_state = (guint32)RECOGNITION_FAIL;
    g_mutex_unlock(&self->state_lock);

    g_debug("TensorFlow FART operation cancelled");
    return TRUE;
}

gboolean
face_tensorflow_fart_submit_frame(BiomFaceTensorflowFart *self,
                                  gint fd,
                                  gint width,
                                  gint height,
                                  gint channels,
                                  guint32 format,
                                  guint32 *out_state)
{
    if (!self || !out_state) {
        g_warning("Invalid parameters in face_tensorflow_fart_submit_frame");
        return FALSE;
    }

    if (!self->available || !self->fart_handle) {
        g_warning("TensorFlow FART not available in submit_frame");
        return FALSE;
    }

    if (fd < 0 || width <= 0 || height <= 0 || channels <= 0) {
        g_warning("Invalid frame parameters in face_tensorflow_fart_submit_frame: fd=%d w=%d h=%d c=%d",
                  fd, width, height, channels);
        return FALSE;
    }

    g_mutex_lock(&self->state_lock);
    *out_state = self->last_state;
    g_mutex_unlock(&self->state_lock);

    FrameJob *job = g_new0(FrameJob, 1);

    job->fd = dup(fd);
    if (job->fd < 0) {
        g_free(job);
        g_warning("dup(fd) failed in submit_frame: %s", g_strerror(errno));
        return FALSE;
    }

    job->width = width;
    job->height = height;
    job->channels = channels;
    job->format = format;
    job->mode = self->mode;

    int qlen = g_async_queue_length(self->queue);
    g_debug("submit_frame: mode=%s fd=%d->%d w=%d h=%d c=%d fmt=%s qlen_before=%d last_state=%u",
            mode_to_string(job->mode),
            fd, job->fd,
            width, height, channels,
            format_to_string(format),
            qlen,
            *out_state);

    g_async_queue_push(self->queue, job);
    return TRUE;
}

gboolean
face_tensorflow_fart_is_enrolled(BiomFaceTensorflowFart *self)
{
    if (!self || !self->available)
        return FALSE;

    g_mutex_lock(&self->state_lock);
    gboolean enrolled = self->enrolled_cached;
    g_mutex_unlock(&self->state_lock);

    return enrolled;
}

guint32
face_tensorflow_fart_get_mode(BiomFaceTensorflowFart *self)
{
    if (!self)
        return TF_FART_MODE_NONE;
    return (guint32)self->mode;
}

guint32
face_tensorflow_fart_get_enrollment_progress(BiomFaceTensorflowFart *self)
{
    if (!self || !self->available)
        return 0;

    g_mutex_lock(&self->state_lock);
    guint32 p = self->enroll_progress_cached;
    g_mutex_unlock(&self->state_lock);

    if (p > 100)
        p = 100;
    return p;
}

gboolean
face_tensorflow_fart_remove_face_data(BiomFaceTensorflowFart *self)
{
    if (!self)
        return FALSE;

    self->mode = TF_FART_MODE_NONE;
    drain_queue(self);

    gboolean removed_ok = TRUE;

    if (self->data_path && g_file_test(self->data_path, G_FILE_TEST_EXISTS)) {
        if (g_remove(self->data_path) != 0) {
            g_warning("Failed to remove encrypted face data file '%s': %s",
                      self->data_path, g_strerror(errno));
            removed_ok = FALSE;
        } else {
            g_debug("Removed encrypted face data file '%s'", self->data_path);
        }
    }

    if (self->fart_handle) {
        fart_destroy(self->fart_handle);
        self->fart_handle = NULL;
    }

    self->fart_handle = fart_create(self->detection_model,
                                    self->recognition_model,
                                    self->anti_spoof_model,
                                    NULL,
                                    "");

    if (!self->fart_handle) {
        g_warning("Failed to recreate libfart handle after removing encrypted face data");
        self->available = FALSE;
        return FALSE;
    }

    self->available = TRUE;

    g_mutex_lock(&self->state_lock);
    self->enrolled_cached = fart_is_enrolled(self->fart_handle) ? TRUE : FALSE;
    self->enroll_progress_cached = 0;
    self->last_state = (guint32)RECOGNITION_FAIL;
    g_mutex_unlock(&self->state_lock);

    publish_state_async(self, (guint32)RECOGNITION_FAIL, 0);

    return removed_ok;
}
