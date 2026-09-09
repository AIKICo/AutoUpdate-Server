#include "db.h"
#include "sha256.h"
#include "compat.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *g_db = NULL;
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper to generate 16-character hex salt */
static void generate_salt(char *out_salt, size_t out_len) {
    if (out_len < 17) return;
    const char hex_chars[] = "0123456789abcdef";
    static unsigned int seed = 0;
    if (seed == 0) seed = (unsigned int)time(NULL);
    for (int i = 0; i < 16; i++) {
        seed = seed * 1103515245 + 12345;
        out_salt[i] = hex_chars[(seed >> 16) % 16];
    }
    out_salt[16] = '\0';
}

/* Helper to hash password with salt: SHA256(salt + ":" + password) */
static void hash_password(const char *salt, const char *password, char *out_hash) {
    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s", salt, password);

    SHA256_CTX ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)combined, strlen(combined));
    sha256_final(&ctx, digest);

    for (int i = 0; i < 32; i++) {
        sprintf(out_hash + (i * 2), "%02x", digest[i]);
    }
    out_hash[64] = '\0';
}

/* Helper to generate a random 32-character session token */
static void generate_token(char *out_token, size_t out_len) {
    if (out_len < 33) return;
    const char hex_chars[] = "0123456789abcdef";
    static unsigned int seed = 0;
    if (seed == 0) seed = (unsigned int)time(NULL) ^ 0x5a5a;
    for (int i = 0; i < 32; i++) {
        seed = seed * 1664525 + 1013904223;
        out_token[i] = hex_chars[(seed >> 16) % 16];
    }
    out_token[32] = '\0';
}

int db_init(const char *db_path) {
    pthread_mutex_lock(&g_db_mutex);
    if (g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    const char *path = (db_path && strlen(db_path) > 0) ? db_path : "autoupdate.db";
    int rc = sqlite3_open(path, &g_db);
    if (rc != SQLITE_OK) {
        log_msg("ERROR", "Failed to open SQLite database '%s': %s", path, sqlite3_errmsg(g_db));
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    /* Enable WAL mode for high concurrency */
    char *err_msg = NULL;
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    /* Create tables */
    const char *schema =
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password_hash TEXT NOT NULL,"
        "  salt TEXT NOT NULL,"
        "  role TEXT NOT NULL DEFAULT 'admin',"
        "  created_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS sessions ("
        "  token TEXT PRIMARY KEY,"
        "  username TEXT NOT NULL,"
        "  role TEXT NOT NULL,"
        "  expires_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS config ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ");";

    rc = sqlite3_exec(g_db, schema, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        log_msg("ERROR", "SQLite schema creation failed: %s", err_msg ? err_msg : "unknown");
        if (err_msg) sqlite3_free(err_msg);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    /* Seed default user 'admin' if users table is empty */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM users", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int count = sqlite3_column_int(stmt, 0);
            if (count == 0) {
                char salt[17];
                char hash[65];
                generate_salt(salt, sizeof(salt));
                hash_password(salt, "admin123", hash);

                sqlite3_stmt *ins = NULL;
                rc = sqlite3_prepare_v2(g_db, "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES ('admin', ?, ?, 'admin', ?)", -1, &ins, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(ins, 1, hash, -1, SQLITE_STATIC);
                    sqlite3_bind_text(ins, 2, salt, -1, SQLITE_STATIC);
                    sqlite3_bind_int64(ins, 3, (sqlite3_int64)time(NULL));
                    sqlite3_step(ins);
                    sqlite3_finalize(ins);
                    log_msg("INFO", "Default admin account created with username 'admin' and password 'admin123'");
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    /* Clean expired sessions */
    char clean_sql[128];
    snprintf(clean_sql, sizeof(clean_sql), "DELETE FROM sessions WHERE expires_at < %llu", (unsigned long long)time(NULL));
    sqlite3_exec(g_db, clean_sql, NULL, NULL, NULL);

    log_msg("INFO", "SQLite database initialized successfully at '%s'", path);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

void db_close(void) {
    pthread_mutex_lock(&g_db_mutex);
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
    pthread_mutex_unlock(&g_db_mutex);
}

int db_user_auth(const char *username, const char *password, char *out_role, size_t role_len) {
    if (!username || !password || !g_db) return 0;

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT password_hash, salt, role FROM users WHERE username = ?";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int authenticated = 0;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *db_hash = (const char *)sqlite3_column_text(stmt, 0);
        const char *salt = (const char *)sqlite3_column_text(stmt, 1);
        const char *role = (const char *)sqlite3_column_text(stmt, 2);

        char computed_hash[65];
        hash_password(salt, password, computed_hash);

        if (strcmp(db_hash, computed_hash) == 0) {
            authenticated = 1;
            if (out_role && role_len > 0) {
                strncpy(out_role, role ? role : "admin", role_len - 1);
                out_role[role_len - 1] = '\0';
            }
        }
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    return authenticated;
}

int db_user_create(const char *username, const char *password, const char *role) {
    if (!username || !password || strlen(username) == 0 || strlen(password) == 0 || !g_db) return -1;

    char salt[17];
    char hash[65];
    generate_salt(salt, sizeof(salt));
    hash_password(salt, password, hash);

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, (role && strlen(role) > 0) ? role : "admin", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_user_delete(const char *username) {
    if (!username || !g_db) return -1;

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM users WHERE username = ?";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Also remove any active sessions for deleted user */
    sqlite3_stmt *sstmt = NULL;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM sessions WHERE username = ?", -1, &sstmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(sstmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_step(sstmt);
        sqlite3_finalize(sstmt);
    }

    pthread_mutex_unlock(&g_db_mutex);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_user_change_password(const char *username, const char *new_password) {
    if (!username || !new_password || strlen(new_password) == 0 || !g_db) return -1;

    char salt[17];
    char hash[65];
    generate_salt(salt, sizeof(salt));
    hash_password(salt, new_password, hash);

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_user_list_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 16 || !g_db) return -1;

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id, username, role, created_at FROM users ORDER BY id ASC";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    size_t offset = 0;
    offset += snprintf(out_buf + offset, max_len - offset, "[\n");
    int first = 1;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *username = (const char *)sqlite3_column_text(stmt, 1);
        const char *role = (const char *)sqlite3_column_text(stmt, 2);
        uint64_t created_at = (uint64_t)sqlite3_column_int64(stmt, 3);

        char item[256];
        snprintf(item, sizeof(item), "%s  {\"id\": %d, \"username\": \"%s\", \"role\": \"%s\", \"created_at\": %llu}",
                 first ? "" : ",\n", id, username ? username : "", role ? role : "admin", (unsigned long long)created_at);

        size_t ilen = strlen(item);
        if (offset + ilen + 4 < max_len) {
            memcpy(out_buf + offset, item, ilen);
            offset += ilen;
            out_buf[offset] = '\0';
        }
        first = 0;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (offset + 3 < max_len) {
        offset += snprintf(out_buf + offset, max_len - offset, "\n]\n");
    }
    return 0;
}

int db_user_count(void) {
    if (!g_db) return 0;
    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    int count = 0;
    if (sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM users", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_mutex);
    return count;
}

int db_session_create(const char *username, const char *role, char *out_token, size_t token_len) {
    if (!username || !out_token || token_len < 33 || !g_db) return -1;

    generate_token(out_token, token_len);
    uint64_t expires = (uint64_t)time(NULL) + (7 * 24 * 3600); /* 7 days */

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, out_token, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, (role && strlen(role) > 0) ? role : "admin", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)expires);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_session_validate(const char *token, char *out_username, size_t user_len, char *out_role, size_t role_len) {
    if (!token || strlen(token) == 0 || !g_db) return 0;

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT username, role, expires_at FROM sessions WHERE token = ?";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    int valid = 0;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *user = (const char *)sqlite3_column_text(stmt, 0);
        const char *role = (const char *)sqlite3_column_text(stmt, 1);
        uint64_t expires = (uint64_t)sqlite3_column_int64(stmt, 2);

        if (expires > (uint64_t)time(NULL)) {
            valid = 1;
            if (out_username && user_len > 0) {
                strncpy(out_username, user ? user : "", user_len - 1);
                out_username[user_len - 1] = '\0';
            }
            if (out_role && role_len > 0) {
                strncpy(out_role, role ? role : "admin", role_len - 1);
                out_role[role_len - 1] = '\0';
            }
        }
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    return valid;
}

int db_session_delete(const char *token) {
    if (!token || !g_db) return -1;

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM sessions WHERE token = ?";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_config_get(const char *key, char *out_val, size_t max_len, const char *default_val) {
    if (!key || !out_val || max_len == 0) return -1;
    out_val[0] = '\0';

    if (!g_db) {
        if (default_val) strncpy(out_val, default_val, max_len - 1);
        return 0;
    }

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT value FROM config WHERE key = ?";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        if (default_val) strncpy(out_val, default_val, max_len - 1);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *v = (const char *)sqlite3_column_text(stmt, 0);
        if (v) {
            strncpy(out_val, v, max_len - 1);
            out_val[max_len - 1] = '\0';
        }
    } else if (default_val) {
        strncpy(out_val, default_val, max_len - 1);
        out_val[max_len - 1] = '\0';
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

int db_config_set(const char *key, const char *val) {
    if (!key || !val || !g_db) return -1;

    pthread_mutex_lock(&g_db_mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)";
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, val, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_config_get_int(const char *key, int default_val) {
    char buf[64];
    char def[64];
    snprintf(def, sizeof(def), "%d", default_val);
    db_config_get(key, buf, sizeof(buf), def);
    int res = atoi(buf);
    return res > 0 ? res : default_val;
}

int db_config_set_int(const char *key, int val) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", val);
    return db_config_set(key, buf);
}
