#include "utils.h"
#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#ifndef _WIN32
#include <pthread.h>
#include <sys/time.h>
#endif

static FILE *g_logfile = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_init(const char *logfile_path) {
    if (logfile_path && strlen(logfile_path) > 0) {
        g_logfile = fopen(logfile_path, "a");
    }
}

void log_close(void) {
    if (g_logfile) {
        fclose(g_logfile);
        g_logfile = NULL;
    }
}

#define LOG_RING_CAP 2000
static log_entry_t g_ring[LOG_RING_CAP];
static uint64_t g_ring_last_id = 0;   /* id of newest entry (0 = empty) */

int log_level_rank(const char *level) {
    if (!level) return 1;
    if (strcasecmp(level, "ERROR") == 0 || strcasecmp(level, "FATAL") == 0) return 3;
    if (strcasecmp(level, "WARN") == 0 || strcasecmp(level, "WARNING") == 0) return 2;
    if (strcasecmp(level, "DEBUG") == 0) return 0;
    return 1;
}

static int ci_contains(const char *hay, const char *needle) {
    if (!needle || !*needle) return 1;
    size_t nl = strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return 1;
    }
    return 0;
}

static log_entry_t *ring_slot(uint64_t id) { return &g_ring[id % LOG_RING_CAP]; }

int log_get_entries(log_entry_t *out, int max, uint64_t since_id, int min_rank, const char *search) {
    if (!out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_log_mutex);
    uint64_t first = (g_ring_last_id > LOG_RING_CAP) ? g_ring_last_id - LOG_RING_CAP + 1 : 1;
    if (since_id + 1 > first) first = since_id + 1;
    /* walk newest -> oldest, collect, then reverse */
    for (uint64_t id = g_ring_last_id; id >= first && id > 0 && n < max; id--) {
        const log_entry_t *e = ring_slot(id);
        if (e->id != id) continue;   /* slot cleared / overwritten */
        if (log_level_rank(e->level) < min_rank) continue;
        if (!ci_contains(e->msg, search)) continue;
        out[n++] = *e;
    }
    pthread_mutex_unlock(&g_log_mutex);
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        log_entry_t t = out[i]; out[i] = out[j]; out[j] = t;
    }
    return n;
}

void log_clear_entries(void) {
    pthread_mutex_lock(&g_log_mutex);
    /* ids stay monotonic so polling clients using since_id keep working */
    memset(g_ring, 0, sizeof(g_ring));
    pthread_mutex_unlock(&g_log_mutex);
}

int log_take_unpersisted(log_entry_t *out, int max) {
    if (!out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_log_mutex);
    uint64_t first = (g_ring_last_id > LOG_RING_CAP) ? g_ring_last_id - LOG_RING_CAP + 1 : 1;
    for (uint64_t id = first; id <= g_ring_last_id && id > 0 && n < max; id++) {
        log_entry_t *e = ring_slot(id);
        if (e->id != id || e->persisted) continue;
        out[n++] = *e;
        e->persisted = 1;
    }
    pthread_mutex_unlock(&g_log_mutex);
    return n;
}

void log_msg(const char *level, const char *fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    time_t now = time(NULL);
    struct tm tm_buf;
#ifdef _WIN32
    struct tm *tmp = localtime(&now);
    if (tmp) tm_buf = *tmp;
    else memset(&tm_buf, 0, sizeof(tm_buf));
#else
    localtime_r(&now, &tm_buf);
#endif

    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    pthread_mutex_lock(&g_log_mutex);

    fprintf(stdout, "[%s] [%s] %s\n", time_str, level, msg);
    fflush(stdout);

    if (g_logfile) {
        fprintf(g_logfile, "[%s] [%s] %s\n", time_str, level, msg);
        fflush(g_logfile);
    }

    /* Record in ring buffer */
    g_ring_last_id++;
    log_entry_t *e = ring_slot(g_ring_last_id);
    memset(e, 0, sizeof(*e));
    e->id = g_ring_last_id;
    e->ts = (int64_t)now;
    strncpy(e->level, level ? level : "INFO", sizeof(e->level) - 1);
    strncpy(e->msg, msg, sizeof(e->msg) - 1);
    e->persisted = (log_level_rank(e->level) >= 2) ? 0 : 1;

    pthread_mutex_unlock(&g_log_mutex);
}

void url_decode(const char *src, char *dst, size_t dst_len) {
    size_t i = 0, j = 0;
    while (src[i] && j + 1 < dst_len) {
        if (src[i] == '%' && src[i + 1] && src[i + 2]) {
            char hex[3] = { src[i + 1], src[i + 2], 0 };
            char *endptr;
            long val = strtol(hex, &endptr, 16);
            if (endptr == hex + 2) {
                dst[j++] = (char)val;
                i += 3;
                continue;
            }
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
            continue;
        }
        dst[j++] = src[i++];
    }
    dst[j] = '\0';
}

int sanitize_path(const char *root, const char *url_path, char *safe_fullpath, size_t max_len) {
    char decoded[1024];
    url_decode(url_path, decoded, sizeof(decoded));

    /* Strip query string if any */
    char *q = strchr(decoded, '?');
    if (q) *q = '\0';

    /* Check for directory traversal tricks */
    if (strstr(decoded, "..") != NULL) {
        return -1; /* Forbidden */
    }

    /* Remove leading slashes */
    const char *p = decoded;
    while (*p == '/' || *p == '\\') p++;

    /* Prevent hidden file access (starting with dot) */
    if (*p == '.' || strstr(p, "/.") || strstr(p, "\\.")) {
        return -1;
    }

    /* Build fullpath */
    size_t root_len = strlen(root);
    while (root_len > 0 && (root[root_len - 1] == '/' || root[root_len - 1] == '\\')) {
        root_len--;
    }

    if (strlen(p) == 0) {
        snprintf(safe_fullpath, max_len, "%.*s", (int)root_len, root);
    } else {
        snprintf(safe_fullpath, max_len, "%.*s/%s", (int)root_len, root, p);
    }

    return 0;
}

const char *get_mime_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";

    if (strcasecmp(dot, ".xml") == 0) return "application/xml; charset=utf-8";
    if (strcasecmp(dot, ".json") == 0) return "application/json; charset=utf-8";
    if (strcasecmp(dot, ".exe") == 0) return "application/vnd.microsoft.portable-executable";
    if (strcasecmp(dot, ".msi") == 0) return "application/x-msi";
    if (strcasecmp(dot, ".zip") == 0) return "application/zip";
    if (strcasecmp(dot, ".7z") == 0) return "application/x-7z-compressed";
    if (strcasecmp(dot, ".rar") == 0) return "application/vnd.rar";
    if (strcasecmp(dot, ".tar") == 0) return "application/x-tar";
    if (strcasecmp(dot, ".gz") == 0 || strcasecmp(dot, ".tgz") == 0) return "application/gzip";
    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0) return "text/html; charset=utf-8";
    if (strcasecmp(dot, ".css") == 0) return "text/css; charset=utf-8";
    if (strcasecmp(dot, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcasecmp(dot, ".svg") == 0) return "image/svg+xml";
    if (strcasecmp(dot, ".png") == 0) return "image/png";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(dot, ".gif") == 0) return "image/gif";
    if (strcasecmp(dot, ".ico") == 0) return "image/x-icon";
    if (strcasecmp(dot, ".txt") == 0 || strcasecmp(dot, ".log") == 0) return "text/plain; charset=utf-8";

    return "application/octet-stream";
}

void format_bytes(uint64_t bytes, char *out, size_t out_len) {
    const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    int u = 0;
    double count = (double)bytes;
    while (count >= 1024.0 && u < 4) {
        count /= 1024.0;
        u++;
    }
    if (u == 0) {
        snprintf(out, out_len, "%llu %s", (unsigned long long)bytes, units[u]);
    } else {
        snprintf(out, out_len, "%.2f %s", count, units[u]);
    }
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_decode(const char *src, char *dst, size_t max_len) {
    int val = 0, valb = -8;
    size_t out_len = 0;

    for (size_t i = 0; src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isspace(c) || c == '=') continue;

        const char *p = strchr(b64_table, c);
        if (!p) return -1;

        val = (val << 6) + (int)(p - b64_table);
        valb += 6;

        if (valb >= 0) {
            if (out_len + 1 >= max_len) return -1;
            dst[out_len++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    dst[out_len] = '\0';
    return (int)out_len;
}

char *read_entire_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz < 0) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, sz, f);
    buf[read_bytes] = '\0';
    fclose(f);

    if (out_size) *out_size = read_bytes;
    return buf;
}

uint64_t get_current_time_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}
