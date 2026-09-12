#ifndef DB_H
#define DB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(_MSC_VER) && !defined(USE_AMALGAMATION)
#include <winsqlite/winsqlite3.h>
#pragma comment(lib, "winsqlite3.lib")
#elif __has_include("sqlite3.h")
#include "sqlite3.h"
#elif __has_include(<sqlite3.h>)
#include <sqlite3.h>
#else
#include <winsqlite/winsqlite3.h>
#endif

int db_init(const char *db_path);
void db_close(void);

/* User Management */
int db_user_auth(const char *username, const char *password, char *out_role, size_t role_len);
int db_user_create(const char *username, const char *password, const char *role);
int db_user_delete(const char *username);
int db_user_change_password(const char *username, const char *new_password);
int db_user_list_json(char *out_buf, size_t max_len);
int db_user_count(void);

/* Session Management */
int db_session_create(const char *username, const char *role, char *out_token, size_t token_len);
int db_session_validate(const char *token, char *out_username, size_t user_len, char *out_role, size_t role_len);
int db_session_delete(const char *token);

/* Configuration Key-Value Store */
int db_config_get(const char *key, char *out_val, size_t max_len, const char *default_val);
int db_config_set(const char *key, const char *val);
int db_config_get_int(const char *key, int default_val);
int db_config_set_int(const char *key, int val);

#endif /* DB_H */
