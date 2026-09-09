#ifndef ADMIN_H
#define ADMIN_H

#include "http.h"
#include "compat.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint64_t start_time;
    uint64_t total_requests;
    uint64_t total_bytes_sent;
    int      active_connections;
    char     admin_user[64];
    char     admin_pass[64];
    char     updates_dir[1024];
    char     webroot_dir[1024];
    int      port;
} server_ctx_t;

int admin_is_authorized(const http_request_t *req, const server_ctx_t *ctx);
int admin_handle_request(socket_t sock, const http_request_t *req, server_ctx_t *ctx);
const char *admin_get_embedded_html(void);

#endif /* ADMIN_H */
