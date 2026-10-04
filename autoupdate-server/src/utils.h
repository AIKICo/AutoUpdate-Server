#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

void log_msg(const char *level, const char *fmt, ...);
void log_init(const char *logfile_path);
void log_close(void);

/* In-memory ring buffer of recent log entries (feeds the "System Logs" UI page) */
typedef struct {
    uint64_t id;          /* monotonically increasing, starts at 1 */
    int64_t  ts;          /* unix time */
    char     level[8];    /* DEBUG / INFO / WARN / ERROR */
    char     msg[512];
    int      persisted;   /* 1 once mirrored to the database (or not needed) */
} log_entry_t;

int  log_level_rank(const char *level);   /* DEBUG=0 INFO=1 WARN=2 ERROR=3 */
/* Fills `out` (oldest -> newest) with up to `max` newest entries having id > since_id,
 * rank >= min_rank and containing `search` (case-insensitive, may be NULL). Returns count. */
int  log_get_entries(log_entry_t *out, int max, uint64_t since_id, int min_rank, const char *search);
void log_clear_entries(void);
/* Returns not-yet-persisted WARN/ERROR entries and marks them as persisted. */
int  log_take_unpersisted(log_entry_t *out, int max);

void url_decode(const char *src, char *dst, size_t dst_len);
int sanitize_path(const char *root, const char *url_path, char *safe_fullpath, size_t max_len);
const char *get_mime_type(const char *path);
void format_bytes(uint64_t bytes, char *out, size_t out_len);
int base64_decode(const char *src, char *dst, size_t max_len);
char *read_entire_file(const char *path, size_t *out_size);
uint64_t get_current_time_ms(void);

#endif /* UTILS_H */
