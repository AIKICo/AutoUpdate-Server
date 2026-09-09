#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

void log_msg(const char *level, const char *fmt, ...);
void log_init(const char *logfile_path);
void log_close(void);

void url_decode(const char *src, char *dst, size_t dst_len);
int sanitize_path(const char *root, const char *url_path, char *safe_fullpath, size_t max_len);
const char *get_mime_type(const char *path);
void format_bytes(uint64_t bytes, char *out, size_t out_len);
int base64_decode(const char *src, char *dst, size_t max_len);
char *read_entire_file(const char *path, size_t *out_size);
uint64_t get_current_time_ms(void);

#endif /* UTILS_H */
