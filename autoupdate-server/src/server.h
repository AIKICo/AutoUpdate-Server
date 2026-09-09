#ifndef SERVER_H
#define SERVER_H

#include "admin.h"

#define DEFAULT_PORT 8000

int server_init(server_ctx_t *ctx, int port, const char *updates_dir, const char *webroot_dir, const char *user, const char *pass);
int server_start(server_ctx_t *ctx);
void server_stop(void);
server_ctx_t *server_get_active_ctx(void);
int server_change_port(server_ctx_t *ctx, int new_port);
int server_set_storage_path(server_ctx_t *ctx, const char *new_path);

#endif /* SERVER_H */
