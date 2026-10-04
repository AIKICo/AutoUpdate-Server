#ifndef DB_H
#define DB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Microsoft SQL Server backend (accessed through ODBC) */

#define DB_SETTINGS_FILE "dbconfig.ini"

typedef struct {
    char driver[128];      /* ODBC driver name, "" or "auto" = auto-detect (18 -> 17 -> 13 -> SQL Server) */
    char server[256];      /* host, host\instance or IP */
    int  port;             /* TCP port (0 = default / named instance) */
    char database[128];
    char user[128];
    char password[256];
    int  trusted;          /* 1 = Windows integrated authentication */
    int  encrypt;          /* 1 = Encrypt=yes */
    int  trust_cert;       /* 1 = TrustServerCertificate=yes */
    int  auto_create;      /* 1 = CREATE DATABASE if it does not exist */
} db_settings_t;

/* Connection settings (persisted in dbconfig.ini, because they are needed before the DB is reachable) */
void db_settings_defaults(db_settings_t *s);
int  db_settings_load(const char *ini_path, db_settings_t *s);
int  db_settings_save(const char *ini_path, const db_settings_t *s);

/* Lifecycle */
int  db_init(const char *ini_path);                 /* loads settings & connects; returns 0 on success, -1 if offline */
void db_close(void);
int  db_is_connected(void);
int  db_is_configured(void);
void db_get_settings(db_settings_t *out);
void db_get_last_error(char *out, size_t len);
/* Test a connection without touching the active one. Returns 0 on success; msg receives server version or the error. */
int  db_test_connection(const db_settings_t *s, char *msg, size_t msg_len);
/* Persist new settings and (re)connect with them. Returns 0 on success; err receives the failure reason. */
int  db_apply_settings(const char *ini_path, const db_settings_t *s, char *err, size_t err_len);

/* User Management */
int db_user_auth(const char *username, const char *password, char *out_role, size_t role_len);
int db_user_create(const char *username, const char *password, const char *role);
int db_user_delete(const char *username);
int db_user_change_password(const char *username, const char *new_password);
int db_user_list_json(char *out_buf, size_t max_len);
int db_user_count(void);

/* Session Management (falls back to memory when the database is offline) */
int db_session_create(const char *username, const char *role, char *out_token, size_t token_len);
int db_session_validate(const char *token, char *out_username, size_t user_len, char *out_role, size_t role_len);
int db_session_delete(const char *token);

/* Configuration Key-Value Store */
int db_config_get(const char *key, char *out_val, size_t max_len, const char *default_val);
int db_config_set(const char *key, const char *val);
int db_config_get_int(const char *key, int default_val);
int db_config_set_int(const char *key, int val);

/* Persistent application log (WARN/ERROR entries mirrored into the app_logs table) */
typedef struct {
    int64_t id;
    int64_t ts;
    char    level[16];
    char    msg[1024];
} db_log_row_t;

/* Reads newest-first rows. Returns the number of rows, or -1 if the database is offline. */
int db_logs_query(db_log_row_t *out, int max_rows, const char *min_level, const char *search);
int db_logs_clear(void);

#endif /* DB_H */
