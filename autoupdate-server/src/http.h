#ifndef HTTP_H
#define HTTP_H

#include "compat.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_DELETE
} http_method_t;

typedef struct {
    http_method_t method;
    char method_str[16];
    char path[1024];
    char query[1024];
    char range_header[128];
    char auth_header[256];
    char host_header[256];
    char cookie_header[512];
    char content_type[128];
    size_t content_length;
    const char *body;
    size_t body_len;
} http_request_t;

int http_parse_request(const char *raw_req, size_t raw_len, http_request_t *req);
int http_get_cookie(const http_request_t *req, const char *cookie_name, char *out_val, size_t out_len);
int http_send_response(socket_t sock, int code, const char *status_text, const char *content_type, const char *extra_headers, const void *body, size_t body_len);
int http_send_json(socket_t sock, int code, const char *json_body);
int http_send_error(socket_t sock, int code, const char *message);
int http_send_file(socket_t sock, const char *filepath, const char *range_header, int is_head, uint64_t *out_bytes_sent);

#endif /* HTTP_H */
