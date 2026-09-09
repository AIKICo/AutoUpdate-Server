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

void log_msg(const char *level, const char *fmt, ...) {
    pthread_mutex_lock(&g_log_mutex);

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

    va_list args1, args2;
    va_start(args1, fmt);
    va_copy(args2, args1);

    fprintf(stdout, "[%s] [%s] ", time_str, level);
    vfprintf(stdout, fmt, args1);
    fprintf(stdout, "\n");
    fflush(stdout);

    if (g_logfile) {
        fprintf(g_logfile, "[%s] [%s] ", time_str, level);
        vfprintf(g_logfile, fmt, args2);
        fprintf(g_logfile, "\n");
        fflush(g_logfile);
    }

    va_end(args1);
    va_end(args2);

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
