#ifndef SERVER_H
#define SERVER_H

#include "admin.h"

int server_init(server_ctx_t *ctx, int port, const char *updates_dir, const char *webroot_dir, const char *user, const char *pass);
int server_start(server_ctx_t *ctx);
void server_stop(void);

#endif /* SERVER_H */
