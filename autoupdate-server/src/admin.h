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

typedef struct {
    char     exe_name[256];
    uint64_t file_size;
    char     architecture[64];
    char     subsystem[64];
    char     runtime[64];
    char     file_version[64];
    char     product_version[64];
    char     file_description[128];
    char     company_name[128];
    char     detection_method[128];
    char     summary[512];
} pe_details_t;

int admin_is_authorized(const http_request_t *req, const server_ctx_t *ctx);
int admin_handle_request(socket_t sock, const http_request_t *req, server_ctx_t *ctx);
int inspect_pe_executable(const char *filepath, pe_details_t *details);
const char *admin_get_embedded_html(void);

#endif /* ADMIN_H */
