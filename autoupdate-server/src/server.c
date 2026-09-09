#include "server.h"
#include "http.h"
#include "utils.h"
#include "admin.h"
#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pthread.h>
#endif
#include <signal.h>
#include <time.h>
#include <errno.h>

static socket_t g_listen_fd = -1;
static volatile int g_running = 1;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    socket_t client_fd;
    struct sockaddr_in client_addr;
    server_ctx_t *ctx;
} client_thread_arg_t;

static server_ctx_t *g_active_ctx = NULL;

int server_init(server_ctx_t *ctx, int port, const char *updates_dir, const char *webroot_dir, const char *user, const char *pass) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->port = port > 0 ? port : DEFAULT_PORT;
    ctx->start_time = (uint64_t)time(NULL);

    strncpy(ctx->updates_dir, updates_dir ? updates_dir : "./updates", sizeof(ctx->updates_dir) - 1);
    strncpy(ctx->webroot_dir, webroot_dir ? webroot_dir : "./webroot", sizeof(ctx->webroot_dir) - 1);
    strncpy(ctx->admin_user, user ? user : "admin", sizeof(ctx->admin_user) - 1);
    strncpy(ctx->admin_pass, pass ? pass : "admin123", sizeof(ctx->admin_pass) - 1);

    return 0;
}

static void *client_worker(void *arg) {
    client_thread_arg_t *carg = (client_thread_arg_t *)arg;
    socket_t sock = carg->client_fd;
    server_ctx_t *ctx = carg->ctx;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(carg->client_addr.sin_addr), client_ip, sizeof(client_ip));
    free(carg);

    pthread_mutex_lock(&g_stats_mutex);
    ctx->active_connections++;
    ctx->total_requests++;
    pthread_mutex_unlock(&g_stats_mutex);

    /* Allocate buffer for reading request (up to 64MB for update uploads) */
    size_t buf_capacity = 65536;
    size_t buf_len = 0;
    char *buf = malloc(buf_capacity);
    if (!buf) {
        CLOSE_SOCK(sock);
        pthread_mutex_lock(&g_stats_mutex);
        ctx->active_connections--;
        pthread_mutex_unlock(&g_stats_mutex);
        return NULL;
    }

    /* Set socket timeout to prevent hanging connections (120s for large zip uploads) */
#ifdef _WIN32
    DWORD timeout_ms = 120000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = 120;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif

    int headers_parsed = 0;
    size_t header_len = 0;
    size_t expected_content_length = 0;
    http_request_t req;
    memset(&req, 0, sizeof(req));

    while (g_running) {
        if (!headers_parsed) {
            const char *end_header = strstr(buf, "\r\n\r\n");
            size_t delim_len = 4;
            if (!end_header) {
                end_header = strstr(buf, "\n\n");
                delim_len = 2;
            }

            if (end_header) {
                header_len = (size_t)(end_header - buf) + delim_len;
                if (http_parse_request(buf, buf_len, &req) == 0) {
                    headers_parsed = 1;
                    expected_content_length = req.content_length;

                    /* Fast pre-allocation for large payload */
                    if (expected_content_length > 0) {
                        size_t total_needed = header_len + expected_content_length + 4096;
                        if (total_needed > buf_capacity && total_needed <= 536870912) {
                            char *fast_buf = realloc(buf, total_needed);
                            if (fast_buf) {
                                buf = fast_buf;
                                buf_capacity = total_needed;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }

        if (headers_parsed) {
            size_t current_body_len = (buf_len >= header_len) ? (buf_len - header_len) : 0;
            if (current_body_len >= expected_content_length) {
                break;
            }
        }

        if (buf_len + 4096 >= buf_capacity) {
            if (buf_capacity >= 536870912) { /* 512 MB max upload */
                break;
            }
            buf_capacity *= 2;
            char *new_buf = realloc(buf, buf_capacity);
            if (!new_buf) break;
            buf = new_buf;
        }

        ssize_t n = SOCK_READ(sock, buf + buf_len, buf_capacity - buf_len - 1);
        if (n <= 0) break;
        buf_len += n;
        buf[buf_len] = '\0';
    }

    if (headers_parsed) {
        http_parse_request(buf, buf_len, &req);

        uint64_t bytes_sent = 0;

        /* CORS Preflight Handling */
        if (req.method == HTTP_METHOD_OPTIONS) {
            http_send_response(sock, 204, "No Content", "text/plain", NULL, NULL, 0);
        }
        /* Admin & API routes */
        else if (strncmp(req.path, "/admin", 6) == 0 || strncmp(req.path, "/api/", 5) == 0) {
            admin_handle_request(sock, &req, ctx);
        }
        /* Root path handling */
        else if (strcmp(req.path, "/") == 0) {
            char safe_idx[1024];
            if (sanitize_path(ctx->updates_dir, "/index.html", safe_idx, sizeof(safe_idx)) == 0 && access(safe_idx, 0) == 0) {
                http_send_file(sock, safe_idx, req.range_header, req.method == HTTP_METHOD_HEAD, &bytes_sent);
            } else {
                /* Redirect to admin panel */
                const char *redirect_headers = "Location: /admin/\r\n";
                http_send_response(sock, 302, "Found", "text/html", redirect_headers, "Redirecting to /admin/...\n", 26);
            }
        }
        /* Updates repository static file serving */
        else {
            char safe_filepath[1024];
            if (sanitize_path(ctx->updates_dir, req.path, safe_filepath, sizeof(safe_filepath)) < 0) {
                http_send_error(sock, 403, "Access Forbidden");
                log_msg("WARN", "[%s] Blocked path traversal attempt: %s", client_ip, req.path);
            } else {
                int res = http_send_file(sock, safe_filepath, req.range_header, req.method == HTTP_METHOD_HEAD, &bytes_sent);
                if (res == 0) {
                    if (strlen(req.range_header) > 0) {
                        log_msg("INFO", "[%s] [206 Partial] %s (%s) -> %llu bytes", client_ip, req.path, req.range_header, (unsigned long long)bytes_sent);
                    } else {
                        log_msg("INFO", "[%s] [200 OK] %s -> %llu bytes", client_ip, req.path, (unsigned long long)bytes_sent);
                    }
                }
            }
        }

        pthread_mutex_lock(&g_stats_mutex);
        ctx->total_bytes_sent += bytes_sent;
        pthread_mutex_unlock(&g_stats_mutex);
    }

    free(buf);
    CLOSE_SOCK(sock);

    pthread_mutex_lock(&g_stats_mutex);
    ctx->active_connections--;
    pthread_mutex_unlock(&g_stats_mutex);

    return NULL;
}

int server_start(server_ctx_t *ctx) {
    g_active_ctx = ctx;
    platform_init_network();

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALID_SOCK(g_listen_fd)) {
        log_msg("ERROR", "socket() failed: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons((uint16_t)ctx->port);

    if (bind(g_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_msg("ERROR", "bind() failed on port %d: %s", ctx->port, strerror(errno));
        CLOSE_SOCK(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }

    if (listen(g_listen_fd, 256) < 0) {
        log_msg("ERROR", "listen() failed: %s", strerror(errno));
        CLOSE_SOCK(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }

    log_msg("INFO", "==========================================================");
    log_msg("INFO", "AutoUpdate-Server started successfully!");
    log_msg("INFO", "Port: %d", ctx->port);
    log_msg("INFO", "Updates Directory: %s", ctx->updates_dir);
    log_msg("INFO", "Web Dashboard: http://localhost:%d/admin/", ctx->port);
    log_msg("INFO", "Range Requests / Resume support: ENABLED");
    log_msg("INFO", "Multi-Application Folders: ENABLED");
    log_msg("INFO", "==========================================================");

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        socket_t client_sock = accept(g_listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (!IS_VALID_SOCK(client_sock)) {
            if (errno == EINTR) continue;
            if (!g_running) break;
            log_msg("WARN", "accept() error");
            continue;
        }

        client_thread_arg_t *carg = malloc(sizeof(*carg));
        if (!carg) {
            CLOSE_SOCK(client_sock);
            continue;
        }
        carg->client_fd = client_sock;
        carg->client_addr = client_addr;
        carg->ctx = ctx;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&tid, &attr, client_worker, carg) != 0) {
            log_msg("ERROR", "pthread_create() failed");
            CLOSE_SOCK(client_sock);
            free(carg);
        }
        pthread_attr_destroy(&attr);
    }

    if (IS_VALID_SOCK(g_listen_fd)) {
        CLOSE_SOCK(g_listen_fd);
        g_listen_fd = -1;
    }
    platform_cleanup_network();
    return 0;
}

void server_stop(void) {
    g_running = 0;
    if (IS_VALID_SOCK(g_listen_fd)) {
        CLOSE_SOCK(g_listen_fd);
        g_listen_fd = -1;
    }
}

server_ctx_t *server_get_active_ctx(void) {
    return g_active_ctx;
}

int server_change_port(server_ctx_t *ctx, int new_port) {
    if (!ctx || new_port <= 0 || new_port > 65535) return -1;
    if (new_port == ctx->port) return 0;

    socket_t new_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALID_SOCK(new_listen_fd)) return -1;

    int opt = 1;
    setsockopt(new_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons((uint16_t)new_port);

    if (bind(new_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        CLOSE_SOCK(new_listen_fd);
        return -1;
    }

    if (listen(new_listen_fd, 256) < 0) {
        CLOSE_SOCK(new_listen_fd);
        return -1;
    }

    socket_t old_fd = g_listen_fd;
    g_listen_fd = new_listen_fd;
    ctx->port = new_port;
    if (IS_VALID_SOCK(old_fd)) {
        CLOSE_SOCK(old_fd);
    }

    log_msg("INFO", "Server port successfully changed to %d (Active listening)", new_port);
    return 0;
}

int server_set_storage_path(server_ctx_t *ctx, const char *new_path) {
    if (!ctx || !new_path || strlen(new_path) == 0) return -1;
    strncpy(ctx->updates_dir, new_path, sizeof(ctx->updates_dir) - 1);
    ctx->updates_dir[sizeof(ctx->updates_dir) - 1] = '\0';
    MKDIR(ctx->updates_dir);
    log_msg("INFO", "Storage directory successfully changed to: %s", ctx->updates_dir);
    return 0;
}
