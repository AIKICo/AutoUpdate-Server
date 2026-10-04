/*
 * db.c - Microsoft SQL Server backend (ODBC)
 *
 * All access goes through a single ODBC connection protected by g_db_mutex.
 * Connection settings are kept in dbconfig.ini (they are required *before* the
 * database can be reached); everything else (users, sessions, config, logs) lives in MSSQL.
 *
 * If the database is unreachable the server keeps running: sessions fall back to
 * memory, logging keeps working and a background thread reconnects automatically,
 * so an operator can always log in and repair the connection from the web UI.
 */
#include "db.h"
#include "sha256.h"
#include "compat.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
#include <bcrypt.h>
#include <sql.h>
#include <sqlext.h>
#pragma comment(lib, "odbc32.lib")
#pragma comment(lib, "bcrypt.lib")
#else
#include <dlfcn.h>
/* Standalone ODBC Types & Constants (Cross-platform, no external unixodbc-dev headers needed) */
typedef void*           SQLHANDLE;
typedef SQLHANDLE       SQLHENV;
typedef SQLHANDLE       SQLHDBC;
typedef SQLHANDLE       SQLHSTMT;
typedef short           SQLSMALLINT;
typedef unsigned short  SQLUSMALLINT;
typedef int             SQLINTEGER;
typedef unsigned int    SQLUINTEGER;
typedef long long       SQLBIGINT;
typedef unsigned long long SQLUBIGINT;
typedef unsigned char   SQLCHAR;
typedef signed char     SQLSCHAR;
typedef double          SQLDOUBLE;
typedef float           SQLREAL;
typedef intptr_t        SQLLEN;
typedef uintptr_t       SQLULEN;
typedef SQLSMALLINT     SQLRETURN;
typedef void*           SQLPOINTER;

#define SQL_NULL_HANDLE      ((SQLHANDLE)0)
#define SQL_NULL_HENV        ((SQLHENV)0)
#define SQL_NULL_HDBC        ((SQLHDBC)0)
#define SQL_NULL_HSTMT       ((SQLHSTMT)0)

#define SQL_SUCCESS          0
#define SQL_SUCCESS_WITH_INFO 1
#define SQL_NO_DATA          100
#define SQL_ERROR            (-1)
#define SQL_INVALID_HANDLE   (-2)
#define SQL_NTS              (-3)
#define SQL_NULL_DATA        (-1)

#define SQL_HANDLE_ENV       1
#define SQL_HANDLE_DBC       2
#define SQL_HANDLE_STMT      3
#define SQL_HANDLE_DESC      4

#define SQL_ATTR_ODBC_VERSION 200
#define SQL_OV_ODBC3         3UL
#define SQL_ATTR_LOGIN_TIMEOUT 103
#define SQL_ATTR_QUERY_TIMEOUT 0

#define SQL_DRIVER_NOPROMPT  0

#define SQL_C_CHAR           1
#define SQL_C_LONG           4
#define SQL_C_SBIGINT        (-25)
#define SQL_C_WCHAR          (-8)

#define SQL_CHAR             1
#define SQL_VARCHAR          12
#define SQL_BIGINT           (-5)
#define SQL_WVARCHAR         (-9)

#define SQL_PARAM_INPUT      1

/* Dynamic function pointer types for libodbc.so */
typedef SQLRETURN (*pfn_SQLAllocHandle)(SQLSMALLINT, SQLHANDLE, SQLHANDLE*);
typedef SQLRETURN (*pfn_SQLSetEnvAttr)(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER);
typedef SQLRETURN (*pfn_SQLSetConnectAttr)(SQLHDBC, SQLINTEGER, SQLPOINTER, SQLINTEGER);
typedef SQLRETURN (*pfn_SQLSetStmtAttr)(SQLHSTMT, SQLINTEGER, SQLPOINTER, SQLINTEGER);
typedef SQLRETURN (*pfn_SQLDriverConnectA)(SQLHDBC, void*, SQLCHAR*, SQLSMALLINT, SQLCHAR*, SQLSMALLINT, SQLSMALLINT*, SQLUSMALLINT);
typedef SQLRETURN (*pfn_SQLDisconnect)(SQLHDBC);
typedef SQLRETURN (*pfn_SQLFreeHandle)(SQLSMALLINT, SQLHANDLE);
typedef SQLRETURN (*pfn_SQLPrepareA)(SQLHSTMT, SQLCHAR*, SQLINTEGER);
typedef SQLRETURN (*pfn_SQLBindParameter)(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLSMALLINT, SQLSMALLINT, SQLULEN, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN*);
typedef SQLRETURN (*pfn_SQLExecute)(SQLHSTMT);
typedef SQLRETURN (*pfn_SQLFetch)(SQLHSTMT);
typedef SQLRETURN (*pfn_SQLGetData)(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN*);
typedef SQLRETURN (*pfn_SQLGetDiagRecA)(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLCHAR*, SQLINTEGER*, SQLCHAR*, SQLSMALLINT, SQLSMALLINT*);

static void *g_odbc_lib = NULL;
static pfn_SQLAllocHandle      fn_SQLAllocHandle = NULL;
static pfn_SQLSetEnvAttr       fn_SQLSetEnvAttr = NULL;
static pfn_SQLSetConnectAttr   fn_SQLSetConnectAttr = NULL;
static pfn_SQLSetStmtAttr      fn_SQLSetStmtAttr = NULL;
static pfn_SQLDriverConnectA   fn_SQLDriverConnectA = NULL;
static pfn_SQLDisconnect       fn_SQLDisconnect = NULL;
static pfn_SQLFreeHandle       fn_SQLFreeHandle = NULL;
static pfn_SQLPrepareA         fn_SQLPrepareA = NULL;
static pfn_SQLBindParameter    fn_SQLBindParameter = NULL;
static pfn_SQLExecute          fn_SQLExecute = NULL;
static pfn_SQLFetch            fn_SQLFetch = NULL;
static pfn_SQLGetData          fn_SQLGetData = NULL;
static pfn_SQLGetDiagRecA      fn_SQLGetDiagRecA = NULL;

#define SQLAllocHandle      fn_SQLAllocHandle
#define SQLSetEnvAttr       fn_SQLSetEnvAttr
#define SQLSetConnectAttr   fn_SQLSetConnectAttr
#define SQLSetStmtAttr      fn_SQLSetStmtAttr
#define SQLDriverConnectA   fn_SQLDriverConnectA
#define SQLDisconnect       fn_SQLDisconnect
#define SQLFreeHandle       fn_SQLFreeHandle
#define SQLPrepareA         fn_SQLPrepareA
#define SQLBindParameter    fn_SQLBindParameter
#define SQLExecute          fn_SQLExecute
#define SQLFetch            fn_SQLFetch
#define SQLGetData          fn_SQLGetData
#define SQLGetDiagRecA      fn_SQLGetDiagRecA

static int odbc_load_dyn_lib(void) {
    if (g_odbc_lib) return 0;
    static const char *candidates[] = {
        "libodbc.so.2", "libodbc.so.1", "libodbc.so",
        "/usr/lib/x86_64-linux-gnu/libodbc.so.2", "/usr/lib/x86_64-linux-gnu/libodbc.so.1",
        "/usr/lib/libodbc.so.2", "/usr/lib64/libodbc.so.2", NULL
    };
    for (int i = 0; candidates[i]; i++) {
        g_odbc_lib = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (g_odbc_lib) break;
    }
    if (!g_odbc_lib) return -1;

    fn_SQLAllocHandle      = (pfn_SQLAllocHandle)dlsym(g_odbc_lib, "SQLAllocHandle");
    fn_SQLSetEnvAttr       = (pfn_SQLSetEnvAttr)dlsym(g_odbc_lib, "SQLSetEnvAttr");
    fn_SQLSetConnectAttr   = (pfn_SQLSetConnectAttr)dlsym(g_odbc_lib, "SQLSetConnectAttr");
    fn_SQLSetStmtAttr      = (pfn_SQLSetStmtAttr)dlsym(g_odbc_lib, "SQLSetStmtAttr");
    fn_SQLDriverConnectA   = (pfn_SQLDriverConnectA)dlsym(g_odbc_lib, "SQLDriverConnect");
    if (!fn_SQLDriverConnectA) fn_SQLDriverConnectA = (pfn_SQLDriverConnectA)dlsym(g_odbc_lib, "SQLDriverConnectA");
    fn_SQLDisconnect       = (pfn_SQLDisconnect)dlsym(g_odbc_lib, "SQLDisconnect");
    fn_SQLFreeHandle       = (pfn_SQLFreeHandle)dlsym(g_odbc_lib, "SQLFreeHandle");
    fn_SQLPrepareA         = (pfn_SQLPrepareA)dlsym(g_odbc_lib, "SQLPrepare");
    if (!fn_SQLPrepareA) fn_SQLPrepareA = (pfn_SQLPrepareA)dlsym(g_odbc_lib, "SQLPrepareA");
    fn_SQLBindParameter    = (pfn_SQLBindParameter)dlsym(g_odbc_lib, "SQLBindParameter");
    fn_SQLExecute          = (pfn_SQLExecute)dlsym(g_odbc_lib, "SQLExecute");
    fn_SQLFetch            = (pfn_SQLFetch)dlsym(g_odbc_lib, "SQLFetch");
    fn_SQLGetData          = (pfn_SQLGetData)dlsym(g_odbc_lib, "SQLGetData");
    fn_SQLGetDiagRecA      = (pfn_SQLGetDiagRecA)dlsym(g_odbc_lib, "SQLGetDiagRec");
    if (!fn_SQLGetDiagRecA) fn_SQLGetDiagRecA = (pfn_SQLGetDiagRecA)dlsym(g_odbc_lib, "SQLGetDiagRecA");

    if (!fn_SQLAllocHandle || !fn_SQLSetEnvAttr || !fn_SQLDriverConnectA || !fn_SQLExecute) {
        dlclose(g_odbc_lib);
        g_odbc_lib = NULL;
        return -1;
    }
    return 0;
}
#endif

#define LOG_TAG "[MSSQL] "

static pthread_mutex_t g_db_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mem_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_env_mutex = PTHREAD_MUTEX_INITIALIZER;

static SQLHENV g_env = SQL_NULL_HENV;
static SQLHDBC g_dbc = SQL_NULL_HDBC;
static int g_connected = 0;
static int g_configured = 0;
static int g_conn_lost = 0;
static db_settings_t g_cfg;
static char g_last_err[1024] = "";
static char g_ini_path[512] = DB_SETTINGS_FILE;
static int g_flusher_started = 0;
static volatile int g_flusher_stop = 0;

/* ------------------------------------------------------------------ */
/* Helpers: randomness, hashing                                        */
/* ------------------------------------------------------------------ */

static int os_random(void *buf, size_t n) {
#ifdef _WIN32
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(buf, 1, n, f);
    fclose(f);
    return r == n ? 0 : -1;
#endif
}

/* n hex characters + NUL */
static void random_hex(char *out, size_t n) {
    static const char hex[] = "0123456789abcdef";
    unsigned char raw[64];
    if (n > sizeof(raw) * 2) n = sizeof(raw) * 2;
    if (os_random(raw, (n + 1) / 2) != 0) {
        /* extremely unlikely; degrade to time-mixed values rather than fail */
        static unsigned int seed = 0;
        if (seed == 0) seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)out;
        for (size_t i = 0; i < (n + 1) / 2; i++) {
            seed = seed * 1664525u + 1013904223u;
            raw[i] = (unsigned char)(seed >> 16);
        }
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char b = raw[i / 2];
        out[i] = hex[(i & 1) ? (b & 0x0F) : (b >> 4)];
    }
    out[n] = '\0';
}

static void generate_salt(char *out_salt, size_t out_len) {
    if (out_len < 17) return;
    random_hex(out_salt, 16);
}

/* SHA256(salt + ":" + password) - unchanged scheme */
static void hash_password(const char *salt, const char *password, char *out_hash) {
    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s", salt, password);

    SHA256_CTX ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)combined, strlen(combined));
    sha256_final(&ctx, digest);

    for (int i = 0; i < 32; i++) sprintf(out_hash + (i * 2), "%02x", digest[i]);
    out_hash[64] = '\0';
}

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static void json_esc(const char *src, char *dst, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 7 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { dst[j++] = '\\'; dst[j++] = (char)c; }
        else if (c == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (c == '\t') { dst[j++] = '\\'; dst[j++] = 't'; }
        else if (c >= 32) dst[j++] = (char)c;
    }
    dst[j] = '\0';
}

/* ------------------------------------------------------------------ */
/* UTF-8 <-> UTF-16                                                    */
/* ------------------------------------------------------------------ */

static size_t utf8_to_u16(const char *s, uint16_t *dst, size_t cap) {
    size_t n = 0;
    if (cap == 0) return 0;
    while (s && *s && n + 2 < cap) {
        uint32_t cp;
        unsigned char c = (unsigned char)*s++;
        if (c < 0x80) cp = c;
        else if ((c & 0xE0) == 0xC0 && (s[0] & 0xC0) == 0x80) { cp = ((c & 0x1Fu) << 6) | (s[0] & 0x3Fu); s += 1; }
        else if ((c & 0xF0) == 0xE0 && (s[0] & 0xC0) == 0x80 && (s[1] & 0xC0) == 0x80) {
            cp = ((c & 0x0Fu) << 12) | ((s[0] & 0x3Fu) << 6) | (s[1] & 0x3Fu); s += 2;
        } else if ((c & 0xF8) == 0xF0 && (s[0] & 0xC0) == 0x80 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {
            cp = ((c & 0x07u) << 18) | ((s[0] & 0x3Fu) << 12) | ((s[1] & 0x3Fu) << 6) | (s[2] & 0x3Fu); s += 3;
        } else cp = '?';
        if (cp >= 0x10000) {
            cp -= 0x10000;
            dst[n++] = (uint16_t)(0xD800 + (cp >> 10));
            dst[n++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
        } else dst[n++] = (uint16_t)cp;
    }
    dst[n] = 0;
    return n;
}

static void u16_to_utf8(const uint16_t *w, size_t wlen, char *dst, size_t cap) {
    size_t j = 0;
    if (cap == 0) return;
    for (size_t i = 0; i < wlen; i++) {
        uint32_t cp = w[i];
        if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < wlen && w[i + 1] >= 0xDC00 && w[i + 1] < 0xE000) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (w[i + 1] - 0xDC00);
            i++;
        }
        if (cp < 0x80) { if (j + 1 >= cap) break; dst[j++] = (char)cp; }
        else if (cp < 0x800) { if (j + 2 >= cap) break; dst[j++] = (char)(0xC0 | (cp >> 6)); dst[j++] = (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { if (j + 3 >= cap) break; dst[j++] = (char)(0xE0 | (cp >> 12)); dst[j++] = (char)(0x80 | ((cp >> 6) & 0x3F)); dst[j++] = (char)(0x80 | (cp & 0x3F)); }
        else { if (j + 4 >= cap) break; dst[j++] = (char)(0xF0 | (cp >> 18)); dst[j++] = (char)(0x80 | ((cp >> 12) & 0x3F)); dst[j++] = (char)(0x80 | ((cp >> 6) & 0x3F)); dst[j++] = (char)(0x80 | (cp & 0x3F)); }
    }
    dst[j] = '\0';
}

/* ------------------------------------------------------------------ */
/* ODBC plumbing                                                       */
/* ------------------------------------------------------------------ */

#define Q_MAXP 8
typedef struct {
    SQLHDBC  dbc;
    SQLHSTMT h;
    uint16_t *wb[Q_MAXP];
    SQLLEN   ind[Q_MAXP];
    SQLBIGINT iv[Q_MAXP];
    int      np;
} q_t;

#define SQL_OK(rc) ((rc) == SQL_SUCCESS || (rc) == SQL_SUCCESS_WITH_INFO)

/* Fetch first diagnostic record: "[SQLSTATE] message". */
static void diag_text(SQLSMALLINT type, SQLHANDLE h, char *state_out, char *out, size_t outlen) {
    SQLCHAR state[8] = "", msg[768] = "";
    SQLINTEGER native = 0;
    SQLSMALLINT len = 0;
    if (state_out) state_out[0] = '\0';
    out[0] = '\0';
    if (!h) return;
    if (SQL_OK(SQLGetDiagRecA(type, h, 1, state, &native, msg, sizeof(msg), &len))) {
        if (state_out) { memcpy(state_out, state, 5); state_out[5] = '\0'; }
        snprintf(out, outlen, "[%s] %s", state, msg);
    }
}

static void note_error(const char *where, SQLSMALLINT type, SQLHANDLE h, int quiet) {
    char state[8], text[900];
    diag_text(type, h, state, text, sizeof(text));
    if (strncmp(state, "08", 2) == 0 || strcmp(state, "HYT00") == 0 || strcmp(state, "HYT01") == 0) {
        if (strncmp(state, "08", 2) == 0) g_conn_lost = 1;
    }
    snprintf(g_last_err, sizeof(g_last_err), "%s: %s", where, text);
    if (!quiet) log_msg("ERROR", LOG_TAG "%s: %s", where, text);
}

static int ensure_env(void) {
    int ok = 1;
#ifndef _WIN32
    if (odbc_load_dyn_lib() != 0) return -1;
#endif
    pthread_mutex_lock(&g_env_mutex);
    if (g_env == SQL_NULL_HENV) {
        if (!SQL_OK(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &g_env))) { g_env = SQL_NULL_HENV; ok = 0; }
        else SQLSetEnvAttr(g_env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3, 0);
    }
    pthread_mutex_unlock(&g_env_mutex);
    return ok ? 0 : -1;
}

static void odbc_free_dbc(SQLHDBC dbc) {
    if (dbc != SQL_NULL_HDBC) {
        SQLDisconnect(dbc);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    }
}

static void q_close(q_t *q) {
    if (q->h) SQLFreeHandle(SQL_HANDLE_STMT, q->h);
    for (int i = 0; i < q->np; i++) free(q->wb[i]);
    memset(q, 0, sizeof(*q));
}

static int q_open(q_t *q, SQLHDBC dbc, const char *sql, int quiet) {
    memset(q, 0, sizeof(*q));
    q->dbc = dbc;
    if (!SQL_OK(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &q->h))) {
        note_error("alloc statement", SQL_HANDLE_DBC, dbc, quiet);
        q->h = NULL;
        return -1;
    }
    SQLSetStmtAttr(q->h, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(uintptr_t)20, 0);
    if (!SQL_OK(SQLPrepareA(q->h, (SQLCHAR *)sql, SQL_NTS))) {
        note_error("prepare", SQL_HANDLE_STMT, q->h, quiet);
        q_close(q);
        return -1;
    }
    return 0;
}

static int q_text(q_t *q, const char *utf8) {
    if (q->np >= Q_MAXP) return -1;
    size_t n = utf8 ? strlen(utf8) : 0;
    uint16_t *w = (uint16_t *)malloc((n + 1) * sizeof(uint16_t));
    if (!w) return -1;
    size_t wl = utf8_to_u16(utf8 ? utf8 : "", w, n + 1);
    int i = q->np++;
    q->wb[i] = w;
    q->ind[i] = (SQLLEN)(wl * 2);
    SQLULEN colsize = wl == 0 ? 1 : (wl > 4000 ? 0 : wl);
    SQLRETURN rc = SQLBindParameter(q->h, (SQLUSMALLINT)(i + 1), SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
                                    colsize, 0, w, (SQLLEN)((wl + 1) * 2), &q->ind[i]);
    return SQL_OK(rc) ? 0 : -1;
}

static int q_int(q_t *q, int64_t v) {
    if (q->np >= Q_MAXP) return -1;
    int i = q->np++;
    q->wb[i] = NULL;
    q->iv[i] = (SQLBIGINT)v;
    q->ind[i] = 0;
    SQLRETURN rc = SQLBindParameter(q->h, (SQLUSMALLINT)(i + 1), SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT,
                                    0, 0, &q->iv[i], 0, &q->ind[i]);
    return SQL_OK(rc) ? 0 : -1;
}

/* returns 0 on success (including "no rows affected") */
static int q_exec(q_t *q, const char *where, int quiet) {
    SQLRETURN rc = SQLExecute(q->h);
    if (SQL_OK(rc) || rc == SQL_NO_DATA) return 0;
    note_error(where, SQL_HANDLE_STMT, q->h, quiet);
    return -1;
}

static int q_fetch(q_t *q) {
    SQLRETURN rc = SQLFetch(q->h);
    if (rc == SQL_NO_DATA) return 0;
    if (SQL_OK(rc)) return 1;
    note_error("fetch", SQL_HANDLE_STMT, q->h, 0);
    return -1;
}

static void q_col_text(q_t *q, int col, char *out, size_t outlen) {
    uint16_t wbuf[4096];
    SQLLEN ind = 0;
    out[0] = '\0';
    SQLRETURN rc = SQLGetData(q->h, (SQLUSMALLINT)col, SQL_C_WCHAR, wbuf, sizeof(wbuf), &ind);
    if (!SQL_OK(rc) || ind == SQL_NULL_DATA || ind < 0) return;
    size_t bytes = (size_t)ind;
    if (bytes > sizeof(wbuf) - 2) bytes = sizeof(wbuf) - 2;
    u16_to_utf8(wbuf, bytes / 2, out, outlen);
}

static int64_t q_col_int(q_t *q, int col) {
    SQLBIGINT v = 0;
    SQLLEN ind = 0;
    SQLRETURN rc = SQLGetData(q->h, (SQLUSMALLINT)col, SQL_C_SBIGINT, &v, 0, &ind);
    if (!SQL_OK(rc) || ind == SQL_NULL_DATA) return 0;
    return (int64_t)v;
}

/* One-shot helper for parameterless statements */
static int exec_direct(SQLHDBC dbc, const char *sql, int quiet) {
    q_t q;
    if (q_open(&q, dbc, sql, quiet) != 0) return -1;
    int rc = q_exec(&q, "execute", quiet);
    q_close(&q);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Settings (dbconfig.ini)                                             */
/* ------------------------------------------------------------------ */

void db_settings_defaults(db_settings_t *s) {
    memset(s, 0, sizeof(*s));
    copy_str(s->driver, sizeof(s->driver), "auto");
    copy_str(s->server, sizeof(s->server), "localhost");
    s->port = 1433;
    copy_str(s->database, sizeof(s->database), "AutoUpdateServer");
    copy_str(s->user, sizeof(s->user), "sa");
#ifdef _WIN32
    s->trusted = 0;
#endif
    s->encrypt = 1;
    s->trust_cert = 1;
    s->auto_create = 1;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

int db_settings_load(const char *ini_path, db_settings_t *s) {
    db_settings_defaults(s);
    FILE *f = fopen(ini_path && *ini_path ? ini_path : DB_SETTINGS_FILE, "r");
    if (!f) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '#' || *p == ';' || *p == '[' || *p == '\0') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = trim(p);
        char *v = trim(eq + 1);
        if (strcasecmp(k, "driver") == 0) copy_str(s->driver, sizeof(s->driver), v);
        else if (strcasecmp(k, "server") == 0) copy_str(s->server, sizeof(s->server), v);
        else if (strcasecmp(k, "port") == 0) s->port = atoi(v);
        else if (strcasecmp(k, "database") == 0) copy_str(s->database, sizeof(s->database), v);
        else if (strcasecmp(k, "user") == 0) copy_str(s->user, sizeof(s->user), v);
        else if (strcasecmp(k, "password") == 0) copy_str(s->password, sizeof(s->password), v);
        else if (strcasecmp(k, "trusted") == 0) s->trusted = atoi(v) != 0;
        else if (strcasecmp(k, "encrypt") == 0) s->encrypt = atoi(v) != 0;
        else if (strcasecmp(k, "trust_cert") == 0) s->trust_cert = atoi(v) != 0;
        else if (strcasecmp(k, "auto_create") == 0) s->auto_create = atoi(v) != 0;
    }
    fclose(f);
    return 0;
}

int db_settings_save(const char *ini_path, const db_settings_t *s) {
    FILE *f = fopen(ini_path && *ini_path ? ini_path : DB_SETTINGS_FILE, "w");
    if (!f) return -1;
    fprintf(f, "# Microsoft SQL Server connection settings (managed from Administration > Database)\n");
    fprintf(f, "# NOTE: this file contains the database password - restrict access to it.\n");
    fprintf(f, "[database]\n");
    fprintf(f, "driver = %s\n", s->driver);
    fprintf(f, "server = %s\n", s->server);
    fprintf(f, "port = %d\n", s->port);
    fprintf(f, "database = %s\n", s->database);
    fprintf(f, "user = %s\n", s->user);
    fprintf(f, "password = %s\n", s->password);
    fprintf(f, "trusted = %d\n", s->trusted ? 1 : 0);
    fprintf(f, "encrypt = %d\n", s->encrypt ? 1 : 0);
    fprintf(f, "trust_cert = %d\n", s->trust_cert ? 1 : 0);
    fprintf(f, "auto_create = %d\n", s->auto_create ? 1 : 0);
    fclose(f);
#ifndef _WIN32
    chmod(ini_path && *ini_path ? ini_path : DB_SETTINGS_FILE, 0600);
#endif
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connecting                                                          */
/* ------------------------------------------------------------------ */

static void append_kv(char *dst, size_t cap, const char *key, const char *val) {
    size_t l = strlen(dst);
    int needs_brace = (strpbrk(val, ";{}= ") != NULL) || val[0] == '\0';
    if (!needs_brace) {
        snprintf(dst + l, cap - l, "%s=%s;", key, val);
        return;
    }
    l += (size_t)snprintf(dst + l, cap - l, "%s={", key);
    for (const char *p = val; *p && l + 3 < cap; p++) {
        if (*p == '}') dst[l++] = '}';
        dst[l++] = *p;
    }
    if (l + 3 < cap) { dst[l++] = '}'; dst[l++] = ';'; }
    dst[l] = '\0';
}

static int driver_is_modern(const char *drv) {
    return strstr(drv, "ODBC Driver") != NULL;
}

/* Connect to server. use_master=1 connects to the 'master' database (used to create the target DB). */
static int odbc_connect(const db_settings_t *s, int use_master, SQLHDBC *out, char *err, size_t errlen, int quiet) {
    static const char *auto_drivers[] = {
        "ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server", "ODBC Driver 13 for SQL Server",
        "FreeTDS", "FreeTDS Driver", "tds",
        "SQL Server Native Client 11.0", "SQL Server", NULL
    };
    const char *single[2] = { s->driver, NULL };
    const char **drivers = (s->driver[0] == '\0' || strcasecmp(s->driver, "auto") == 0) ? auto_drivers : single;

    if (ensure_env() != 0) { copy_str(err, errlen, "Failed to initialise ODBC environment (is the ODBC driver manager installed?)"); return -1; }

    char first_err[900] = "";
    int all_missing = 1;

    for (int di = 0; drivers[di]; di++) {
        SQLHDBC dbc = SQL_NULL_HDBC;
        if (!SQL_OK(SQLAllocHandle(SQL_HANDLE_DBC, g_env, &dbc))) continue;
        SQLSetConnectAttr(dbc, SQL_ATTR_LOGIN_TIMEOUT, (SQLPOINTER)(uintptr_t)2, 0);

        char cs[1536] = "";
        append_kv(cs, sizeof(cs), "DRIVER", drivers[di]);

        char server[320];
        if (s->port > 0 && !strchr(s->server, '\\') && !strchr(s->server, ','))
            snprintf(server, sizeof(server), "%s,%d", s->server, s->port);
        else
            copy_str(server, sizeof(server), s->server);
        append_kv(cs, sizeof(cs), "SERVER", server);
        append_kv(cs, sizeof(cs), "DATABASE", use_master ? "master" : s->database);
        if (s->trusted) {
            append_kv(cs, sizeof(cs), "Trusted_Connection", "yes");
        } else {
            append_kv(cs, sizeof(cs), "UID", s->user);
            append_kv(cs, sizeof(cs), "PWD", s->password);
        }
        if (driver_is_modern(drivers[di])) {
            append_kv(cs, sizeof(cs), "Encrypt", s->encrypt ? "yes" : "no");
            append_kv(cs, sizeof(cs), "TrustServerCertificate", s->trust_cert ? "yes" : "no");
        }
        append_kv(cs, sizeof(cs), "APP", "AutoUpdate-Server");

        SQLCHAR outstr[1024];
        SQLSMALLINT outlen = 0;
        SQLRETURN rc = SQLDriverConnectA(dbc, NULL, (SQLCHAR *)cs, SQL_NTS, outstr, sizeof(outstr), &outlen, SQL_DRIVER_NOPROMPT);
        if (SQL_OK(rc)) {
            *out = dbc;
            return 0;
        }

        char state[8], text[900];
        diag_text(SQL_HANDLE_DBC, dbc, state, text, sizeof(text));
        if (strcmp(state, "IM002") != 0 && strcmp(state, "01000") != 0) all_missing = 0;
        if (strcmp(state, "IM002") != 0 && first_err[0] == '\0') copy_str(first_err, sizeof(first_err), text);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    }

    if (all_missing && first_err[0] == '\0') {
        copy_str(err, errlen, "No SQL Server ODBC driver found. Install 'ODBC Driver 18 for SQL Server' (Microsoft) and try again.");
    } else {
        copy_str(err, errlen, first_err[0] ? first_err : "Connection failed");
    }
    snprintf(g_last_err, sizeof(g_last_err), "connect: %s", err);
    if (!quiet) log_msg("ERROR", LOG_TAG "connect to '%s' failed: %s", s->server, err);
    return -1;
}

static int valid_db_name(const char *n) {
    if (!n || !*n || strlen(n) > 100) return 0;
    for (; *n; n++) if (!isalnum((unsigned char)*n) && *n != '_' && *n != '-' && *n != '.') return 0;
    return 1;
}

static int ensure_schema(SQLHDBC dbc) {
    static const char *stmts[] = {
        "IF OBJECT_ID(N'dbo.users', N'U') IS NULL CREATE TABLE dbo.users ("
        " id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,"
        " username NVARCHAR(128) NOT NULL,"
        " password_hash VARCHAR(64) NOT NULL,"
        " salt VARCHAR(32) NOT NULL,"
        " role NVARCHAR(32) NOT NULL CONSTRAINT DF_users_role DEFAULT N'admin',"
        " created_at BIGINT NOT NULL,"
        " CONSTRAINT UQ_users_username UNIQUE (username))",

        "IF OBJECT_ID(N'dbo.sessions', N'U') IS NULL CREATE TABLE dbo.sessions ("
        " token VARCHAR(64) NOT NULL PRIMARY KEY,"
        " username NVARCHAR(128) NOT NULL,"
        " role NVARCHAR(32) NOT NULL,"
        " expires_at BIGINT NOT NULL)",

        "IF OBJECT_ID(N'dbo.config', N'U') IS NULL CREATE TABLE dbo.config ("
        " cfg_key NVARCHAR(128) NOT NULL PRIMARY KEY,"
        " cfg_value NVARCHAR(MAX) NOT NULL)",

        "IF OBJECT_ID(N'dbo.app_logs', N'U') IS NULL CREATE TABLE dbo.app_logs ("
        " id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,"
        " ts BIGINT NOT NULL,"
        " level VARCHAR(16) NOT NULL,"
        " message NVARCHAR(1024) NOT NULL)",

        "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_app_logs_ts' AND object_id = OBJECT_ID(N'dbo.app_logs'))"
        " CREATE INDEX IX_app_logs_ts ON dbo.app_logs (ts DESC)",
        NULL
    };
    for (int i = 0; stmts[i]; i++) {
        if (exec_direct(dbc, stmts[i], 0) != 0) return -1;
    }

    /* Seed default admin when the users table is empty */
    q_t q;
    int count = -1;
    if (q_open(&q, dbc, "SELECT COUNT(*) FROM dbo.users", 0) == 0) {
        if (q_exec(&q, "count users", 0) == 0 && q_fetch(&q) == 1) count = (int)q_col_int(&q, 1);
        q_close(&q);
    }
    if (count == 0) {
        char salt[17], hash[65];
        generate_salt(salt, sizeof(salt));
        hash_password(salt, "admin123", hash);
        if (q_open(&q, dbc, "INSERT INTO dbo.users (username, password_hash, salt, role, created_at) VALUES (N'admin', ?, ?, N'admin', ?)", 0) == 0) {
            q_text(&q, hash); q_text(&q, salt); q_int(&q, (int64_t)time(NULL));
            if (q_exec(&q, "seed admin", 0) == 0)
                log_msg("INFO", LOG_TAG "Default admin account created with username 'admin' and password 'admin123'");
            q_close(&q);
        }
    }

    /* Clean expired sessions */
    if (q_open(&q, dbc, "DELETE FROM dbo.sessions WHERE expires_at < ?", 1) == 0) {
        q_int(&q, (int64_t)time(NULL));
        q_exec(&q, "clean sessions", 1);
        q_close(&q);
    }
    return 0;
}

/* Connect (creating the database if allowed) and make sure the schema exists. */
static int open_and_prepare(const db_settings_t *s, SQLHDBC *out, char *err, size_t errlen, int quiet) {
    SQLHDBC dbc = SQL_NULL_HDBC;
    char e1[900] = "";

    if (!s->server[0]) { copy_str(err, errlen, "Server name is required"); return -1; }
    if (!valid_db_name(s->database)) { copy_str(err, errlen, "Invalid database name (letters, digits, '_', '-' and '.' only)"); return -1; }

    if (odbc_connect(s, 0, &dbc, e1, sizeof(e1), s->auto_create ? 1 : quiet) != 0) {
        int created = 0;
        if (s->auto_create) {
            SQLHDBC mdb = SQL_NULL_HDBC;
            char e2[900];
            if (odbc_connect(s, 1, &mdb, e2, sizeof(e2), 1) == 0) {
                char sql[400];
                snprintf(sql, sizeof(sql), "IF DB_ID(N'%s') IS NULL CREATE DATABASE [%s]", s->database, s->database);
                if (exec_direct(mdb, sql, quiet) == 0) {
                    log_msg("INFO", LOG_TAG "Database '%s' created", s->database);
                    created = 1;
                }
                odbc_free_dbc(mdb);
            }
        }
        if (!created || odbc_connect(s, 0, &dbc, e1, sizeof(e1), quiet) != 0) {
            if (s->auto_create && !quiet) log_msg("ERROR", LOG_TAG "connect to '%s' failed: %s", s->server, e1);
            copy_str(err, errlen, e1);
            return -1;
        }
    }

    if (ensure_schema(dbc) != 0) {
        snprintf(err, errlen, "Connected, but schema initialisation failed: %s", g_last_err);
        odbc_free_dbc(dbc);
        return -1;
    }
    *out = dbc;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connection state                                                    */
/* ------------------------------------------------------------------ */

/* Locks the DB. Returns 1 when connected (caller must call db_leave), 0 otherwise (already unlocked). */
static int db_enter(void) {
    pthread_mutex_lock(&g_db_mutex);
    if (!g_connected) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }
    g_conn_lost = 0;
    return 1;
}

static void db_leave(void) {
    if (g_conn_lost) {
        log_msg("WARN", LOG_TAG "Connection to SQL Server lost - will retry in the background");
        odbc_free_dbc(g_dbc);
        g_dbc = SQL_NULL_HDBC;
        g_connected = 0;
        g_conn_lost = 0;
    }
    pthread_mutex_unlock(&g_db_mutex);
}

int db_is_connected(void) {
    pthread_mutex_lock(&g_db_mutex);
    int c = g_connected;
    pthread_mutex_unlock(&g_db_mutex);
    return c;
}

int db_is_configured(void) {
    pthread_mutex_lock(&g_db_mutex);
    int c = g_configured;
    pthread_mutex_unlock(&g_db_mutex);
    return c;
}

void db_get_settings(db_settings_t *out) {
    pthread_mutex_lock(&g_db_mutex);
    *out = g_cfg;
    pthread_mutex_unlock(&g_db_mutex);
}

void db_get_last_error(char *out, size_t len) {
    pthread_mutex_lock(&g_db_mutex);
    copy_str(out, len, g_last_err);
    pthread_mutex_unlock(&g_db_mutex);
}

static void swap_in_connection(SQLHDBC dbc, const db_settings_t *s) {
    pthread_mutex_lock(&g_db_mutex);
    SQLHDBC old = g_dbc;
    g_dbc = dbc;
    g_connected = 1;
    g_configured = 1;
    g_conn_lost = 0;
    g_cfg = *s;
    g_last_err[0] = '\0';
    pthread_mutex_unlock(&g_db_mutex);
    odbc_free_dbc(old);
}

int db_test_connection(const db_settings_t *s, char *msg, size_t msg_len) {
    SQLHDBC dbc = SQL_NULL_HDBC;
    char err[900] = "";
    if (!s->server[0]) { copy_str(msg, msg_len, "Server name is required"); return -1; }
    if (!valid_db_name(s->database)) { copy_str(msg, msg_len, "Invalid database name (letters, digits, '_', '-' and '.' only)"); return -1; }

    if (odbc_connect(s, 0, &dbc, err, sizeof(err), 1) == 0) {
        q_t q;
        char ver[256] = "";
        if (q_open(&q, dbc, "SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(64)) + N' ' + CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128))", 1) == 0) {
            if (q_exec(&q, "version", 1) == 0 && q_fetch(&q) == 1) q_col_text(&q, 1, ver, sizeof(ver));
            q_close(&q);
        }
        odbc_free_dbc(dbc);
        snprintf(msg, msg_len, "Connection successful. SQL Server %s", ver[0] ? ver : "(version unknown)");
        log_msg("INFO", LOG_TAG "Connection test succeeded for %s / %s", s->server, s->database);
        return 0;
    }

    if (s->auto_create) {
        SQLHDBC mdb = SQL_NULL_HDBC;
        char e2[900];
        if (odbc_connect(s, 1, &mdb, e2, sizeof(e2), 1) == 0) {
            odbc_free_dbc(mdb);
            snprintf(msg, msg_len, "Server reachable, but database '%s' does not exist yet. It will be created when you save.", s->database);
            return 0;
        }
    }
    copy_str(msg, msg_len, err);
    log_msg("WARN", LOG_TAG "Connection test failed for %s / %s: %s", s->server, s->database, err);
    return -1;
}

int db_apply_settings(const char *ini_path, const db_settings_t *s, char *err, size_t err_len) {
    SQLHDBC dbc = SQL_NULL_HDBC;
    char e[900] = "";
    const char *path = (ini_path && *ini_path) ? ini_path : g_ini_path;
    if (open_and_prepare(s, &dbc, e, sizeof(e), 0) != 0) {
        copy_str(err, err_len, e);
        return -1;
    }
    if (db_settings_save(path, s) != 0) {
        odbc_free_dbc(dbc);
        copy_str(err, err_len, "Connected, but could not write dbconfig.ini (check file permissions)");
        log_msg("ERROR", "Could not write database settings file '%s'", path);
        return -1;
    }
    swap_in_connection(dbc, s);
    log_msg("INFO", LOG_TAG "Database settings applied: server=%s database=%s auth=%s", s->server, s->database,
            s->trusted ? "windows" : "sql");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Background worker: mirror WARN/ERROR logs to DB + auto-reconnect    */
/* ------------------------------------------------------------------ */

static void flush_logs(void) {
    log_entry_t batch[100];
    pthread_mutex_lock(&g_db_mutex);
    int connected = g_connected;
    pthread_mutex_unlock(&g_db_mutex);
    if (!connected) return;

    int n = log_take_unpersisted(batch, 100);
    if (n <= 0) return;
    if (!db_enter()) return;
    for (int i = 0; i < n; i++) {
        if (strncmp(batch[i].msg, LOG_TAG, strlen(LOG_TAG)) == 0) continue; /* avoid feedback loops */
        q_t q;
        if (q_open(&q, g_dbc, "INSERT INTO dbo.app_logs (ts, level, message) VALUES (?, ?, ?)", 1) != 0) break;
        q_int(&q, batch[i].ts); q_text(&q, batch[i].level); q_text(&q, batch[i].msg);
        int rc = q_exec(&q, "log insert", 1);
        q_close(&q);
        if (rc != 0) break;
    }
    db_leave();
}

static void purge_old_logs(void) {
    if (!db_enter()) return;
    q_t q;
    if (q_open(&q, g_dbc, "DELETE FROM dbo.app_logs WHERE ts < ?", 1) == 0) {
        q_int(&q, (int64_t)time(NULL) - 30LL * 24 * 3600);
        q_exec(&q, "purge logs", 1);
        q_close(&q);
    }
    db_leave();
}

static void *db_worker(void *arg) {
    (void)arg;
    time_t last_try = time(NULL), last_purge = 0;
    int reported = 0;
    while (!g_flusher_stop) {
        SLEEP_SEC(3);
        if (g_flusher_stop) break;

        pthread_mutex_lock(&g_db_mutex);
        int connected = g_connected;
        db_settings_t cfg = g_cfg;
        pthread_mutex_unlock(&g_db_mutex);

        if (!connected) {
            if (time(NULL) - last_try >= 15) {
                last_try = time(NULL);
                SQLHDBC dbc = SQL_NULL_HDBC;
                char e[900];
                if (open_and_prepare(&cfg, &dbc, e, sizeof(e), 1) == 0) {
                    swap_in_connection(dbc, &cfg);
                    log_msg("INFO", LOG_TAG "Reconnected to SQL Server");
                    reported = 0;
                } else if (!reported) {
                    reported = 1;
                    log_msg("WARN", LOG_TAG "Database offline (%s). Retrying every 15s. Configure it under Administration > Database.", e);
                }
            }
            continue;
        }
        flush_logs();
        if (time(NULL) - last_purge > 3600) { last_purge = time(NULL); purge_old_logs(); }
    }
    return NULL;
}

int db_init(const char *ini_path) {
    copy_str(g_ini_path, sizeof(g_ini_path), (ini_path && *ini_path) ? ini_path : DB_SETTINGS_FILE);

    db_settings_t s;
    int have_file = (db_settings_load(g_ini_path, &s) == 0);
    pthread_mutex_lock(&g_db_mutex);
    g_cfg = s;
    g_configured = have_file;
    pthread_mutex_unlock(&g_db_mutex);

    if (!have_file)
        log_msg("WARN", LOG_TAG "No %s found - trying defaults (server=%s database=%s). Configure under Administration > Database.",
                g_ini_path, s.server, s.database);

    SQLHDBC dbc = SQL_NULL_HDBC;
    char err[900] = "";
    int rc = -1;
    if (open_and_prepare(&s, &dbc, err, sizeof(err), 0) == 0) {
        swap_in_connection(dbc, &s);
        log_msg("INFO", LOG_TAG "Connected to SQL Server '%s', database '%s'", s.server, s.database);
        rc = 0;
    } else {
        log_msg("ERROR", LOG_TAG "Database unavailable: %s - the server keeps running; fix the settings in Administration > Database.", err);
    }

    if (!g_flusher_started) {
        g_flusher_started = 1;
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, db_worker, NULL) != 0) log_msg("WARN", LOG_TAG "Could not start DB background worker");
        pthread_attr_destroy(&attr);
    }
    return rc;
}

void db_close(void) {
    g_flusher_stop = 1;
    flush_logs();
    pthread_mutex_lock(&g_db_mutex);
    if (g_dbc != SQL_NULL_HDBC) odbc_free_dbc(g_dbc);
    g_dbc = SQL_NULL_HDBC;
    g_connected = 0;
    pthread_mutex_unlock(&g_db_mutex);
}

/* ------------------------------------------------------------------ */
/* Users                                                               */
/* ------------------------------------------------------------------ */

int db_user_auth(const char *username, const char *password, char *out_role, size_t role_len) {
    if (!username || !password) return 0;
    if (!db_enter()) return 0;

    int authenticated = 0;
    q_t q;
    if (q_open(&q, g_dbc, "SELECT password_hash, salt, role FROM dbo.users WHERE username = ?", 0) == 0) {
        q_text(&q, username);
        if (q_exec(&q, "user auth", 0) == 0 && q_fetch(&q) == 1) {
            char db_hash[96], salt[64], role[64], computed[65];
            q_col_text(&q, 1, db_hash, sizeof(db_hash));
            q_col_text(&q, 2, salt, sizeof(salt));
            q_col_text(&q, 3, role, sizeof(role));
            hash_password(salt, password, computed);
            if (strcmp(db_hash, computed) == 0) {
                authenticated = 1;
                if (out_role && role_len > 0) copy_str(out_role, role_len, role[0] ? role : "admin");
            }
        }
        q_close(&q);
    }
    db_leave();
    return authenticated;
}

int db_user_create(const char *username, const char *password, const char *role) {
    if (!username || !password || !*username || !*password) return -1;

    char salt[17], hash[65];
    generate_salt(salt, sizeof(salt));
    hash_password(salt, password, hash);

    if (!db_enter()) return -1;
    int result = -1;
    q_t q;
    if (q_open(&q, g_dbc, "INSERT INTO dbo.users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)", 1) == 0) {
        q_text(&q, username); q_text(&q, hash); q_text(&q, salt);
        q_text(&q, (role && *role) ? role : "admin"); q_int(&q, (int64_t)time(NULL));
        result = q_exec(&q, "create user", 1);
        q_close(&q);
    }
    db_leave();
    return result == 0 ? 0 : -1;
}

int db_user_delete(const char *username) {
    if (!username) return -1;
    if (!db_enter()) return -1;
    int result = -1;
    q_t q;
    if (q_open(&q, g_dbc, "DELETE FROM dbo.users WHERE username = ?", 0) == 0) {
        q_text(&q, username);
        result = q_exec(&q, "delete user", 0);
        q_close(&q);
    }
    if (q_open(&q, g_dbc, "DELETE FROM dbo.sessions WHERE username = ?", 0) == 0) {
        q_text(&q, username);
        q_exec(&q, "delete user sessions", 0);
        q_close(&q);
    }
    db_leave();
    return result == 0 ? 0 : -1;
}

int db_user_change_password(const char *username, const char *new_password) {
    if (!username || !new_password || !*new_password) return -1;

    char salt[17], hash[65];
    generate_salt(salt, sizeof(salt));
    hash_password(salt, new_password, hash);

    if (!db_enter()) return -1;
    int result = -1;
    q_t q;
    if (q_open(&q, g_dbc, "UPDATE dbo.users SET password_hash = ?, salt = ? WHERE username = ?", 0) == 0) {
        q_text(&q, hash); q_text(&q, salt); q_text(&q, username);
        result = q_exec(&q, "change password", 0);
        q_close(&q);
    }
    db_leave();
    return result == 0 ? 0 : -1;
}

int db_user_list_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 16) return -1;
    if (!db_enter()) { snprintf(out_buf, max_len, "[]\n"); return -1; }

    size_t offset = (size_t)snprintf(out_buf, max_len, "[\n");
    int first = 1;
    q_t q;
    if (q_open(&q, g_dbc, "SELECT id, username, role, created_at FROM dbo.users ORDER BY id ASC", 0) == 0) {
        if (q_exec(&q, "list users", 0) == 0) {
            while (q_fetch(&q) == 1) {
                char user[256], role[64], eu[600], er[160], item[1024];
                int64_t id = q_col_int(&q, 1);
                q_col_text(&q, 2, user, sizeof(user));
                q_col_text(&q, 3, role, sizeof(role));
                int64_t created = q_col_int(&q, 4);
                json_esc(user, eu, sizeof(eu));
                json_esc(role[0] ? role : "admin", er, sizeof(er));
                int il = snprintf(item, sizeof(item), "%s  {\"id\": %lld, \"username\": \"%s\", \"role\": \"%s\", \"created_at\": %lld}",
                                  first ? "" : ",\n", (long long)id, eu, er, (long long)created);
                if (il > 0 && offset + (size_t)il + 4 < max_len) {
                    memcpy(out_buf + offset, item, (size_t)il);
                    offset += (size_t)il;
                    out_buf[offset] = '\0';
                }
                first = 0;
            }
        }
        q_close(&q);
    }
    db_leave();
    if (offset + 3 < max_len) snprintf(out_buf + offset, max_len - offset, "\n]\n");
    return 0;
}

int db_user_count(void) {
    if (!db_enter()) return 0;
    int count = 0;
    q_t q;
    if (q_open(&q, g_dbc, "SELECT COUNT(*) FROM dbo.users", 0) == 0) {
        if (q_exec(&q, "count users", 0) == 0 && q_fetch(&q) == 1) count = (int)q_col_int(&q, 1);
        q_close(&q);
    }
    db_leave();
    return count;
}

/* ------------------------------------------------------------------ */
/* Sessions (DB first, memory fallback while the DB is offline)        */
/* ------------------------------------------------------------------ */

#define MEM_SESSIONS 128
typedef struct { char token[40]; char user[128]; char role[32]; int64_t exp; } mem_session_t;
static mem_session_t g_mem_sess[MEM_SESSIONS];

static void mem_session_add(const char *token, const char *user, const char *role, int64_t exp) {
    pthread_mutex_lock(&g_mem_mutex);
    int slot = -1, oldest = 0;
    int64_t now = (int64_t)time(NULL);
    for (int i = 0; i < MEM_SESSIONS; i++) {
        if (g_mem_sess[i].token[0] == '\0' || g_mem_sess[i].exp <= now) { slot = i; break; }
        if (g_mem_sess[i].exp < g_mem_sess[oldest].exp) oldest = i;
    }
    if (slot < 0) slot = oldest;
    copy_str(g_mem_sess[slot].token, sizeof(g_mem_sess[slot].token), token);
    copy_str(g_mem_sess[slot].user, sizeof(g_mem_sess[slot].user), user);
    copy_str(g_mem_sess[slot].role, sizeof(g_mem_sess[slot].role), role);
    g_mem_sess[slot].exp = exp;
    pthread_mutex_unlock(&g_mem_mutex);
}

static int mem_session_find(const char *token, char *u, size_t ul, char *r, size_t rl) {
    int found = 0;
    int64_t now = (int64_t)time(NULL);
    pthread_mutex_lock(&g_mem_mutex);
    for (int i = 0; i < MEM_SESSIONS; i++) {
        if (g_mem_sess[i].token[0] && strcmp(g_mem_sess[i].token, token) == 0 && g_mem_sess[i].exp > now) {
            if (u && ul) copy_str(u, ul, g_mem_sess[i].user);
            if (r && rl) copy_str(r, rl, g_mem_sess[i].role);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mem_mutex);
    return found;
}

static void mem_session_remove(const char *token) {
    pthread_mutex_lock(&g_mem_mutex);
    for (int i = 0; i < MEM_SESSIONS; i++)
        if (strcmp(g_mem_sess[i].token, token) == 0) memset(&g_mem_sess[i], 0, sizeof(g_mem_sess[i]));
    pthread_mutex_unlock(&g_mem_mutex);
}

int db_session_create(const char *username, const char *role, char *out_token, size_t token_len) {
    if (!username || !out_token || token_len < 33) return -1;

    random_hex(out_token, 32);
    const char *r = (role && *role) ? role : "admin";
    int64_t expires = (int64_t)time(NULL) + (7 * 24 * 3600); /* 7 days */

    int stored = 0;
    if (db_enter()) {
        q_t q;
        if (q_open(&q, g_dbc, "INSERT INTO dbo.sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)", 0) == 0) {
            q_text(&q, out_token); q_text(&q, username); q_text(&q, r); q_int(&q, expires);
            stored = (q_exec(&q, "create session", 0) == 0);
            q_close(&q);
        }
        db_leave();
    }
    if (!stored) {
        mem_session_add(out_token, username, r, expires);
        log_msg("WARN", "Session for '%s' stored in memory only (database offline) - it will be lost on restart", username);
    }
    return 0;
}

int db_session_validate(const char *token, char *out_username, size_t user_len, char *out_role, size_t role_len) {
    if (!token || !*token || strlen(token) > 64) return 0;

    if (mem_session_find(token, out_username, user_len, out_role, role_len)) return 1;

    if (!db_enter()) return 0;
    int valid = 0;
    q_t q;
    if (q_open(&q, g_dbc, "SELECT username, role, expires_at FROM dbo.sessions WHERE token = ?", 0) == 0) {
        q_text(&q, token);
        if (q_exec(&q, "validate session", 0) == 0 && q_fetch(&q) == 1) {
            char user[256], role[64];
            q_col_text(&q, 1, user, sizeof(user));
            q_col_text(&q, 2, role, sizeof(role));
            int64_t expires = q_col_int(&q, 3);
            if (expires > (int64_t)time(NULL)) {
                valid = 1;
                if (out_username && user_len) copy_str(out_username, user_len, user);
                if (out_role && role_len) copy_str(out_role, role_len, role[0] ? role : "admin");
            }
        }
        q_close(&q);
    }
    db_leave();
    return valid;
}

int db_session_delete(const char *token) {
    if (!token) return -1;
    mem_session_remove(token);
    if (!db_enter()) return 0;
    int result = -1;
    q_t q;
    if (q_open(&q, g_dbc, "DELETE FROM dbo.sessions WHERE token = ?", 0) == 0) {
        q_text(&q, token);
        result = q_exec(&q, "delete session", 0);
        q_close(&q);
    }
    db_leave();
    return result == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Config key/value                                                    */
/* ------------------------------------------------------------------ */

int db_config_get(const char *key, char *out_val, size_t max_len, const char *default_val) {
    if (!key || !out_val || max_len == 0) return -1;
    copy_str(out_val, max_len, default_val ? default_val : "");

    if (!db_enter()) return 0;
    q_t q;
    if (q_open(&q, g_dbc, "SELECT cfg_value FROM dbo.config WHERE cfg_key = ?", 0) == 0) {
        q_text(&q, key);
        if (q_exec(&q, "config get", 0) == 0 && q_fetch(&q) == 1) q_col_text(&q, 1, out_val, max_len);
        q_close(&q);
    }
    db_leave();
    return 0;
}

int db_config_set(const char *key, const char *val) {
    if (!key || !val) return -1;
    if (!db_enter()) return -1;
    int result = -1;
    q_t q;
    if (q_open(&q, g_dbc,
               "UPDATE dbo.config SET cfg_value = ? WHERE cfg_key = ?;"
               " IF @@ROWCOUNT = 0 INSERT INTO dbo.config (cfg_key, cfg_value) VALUES (?, ?)", 0) == 0) {
        q_text(&q, val); q_text(&q, key); q_text(&q, key); q_text(&q, val);
        result = q_exec(&q, "config set", 0);
        q_close(&q);
    }
    db_leave();
    return result == 0 ? 0 : -1;
}

int db_config_get_int(const char *key, int default_val) {
    char buf[64], def[64];
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

/* ------------------------------------------------------------------ */
/* Persistent logs                                                     */
/* ------------------------------------------------------------------ */

int db_logs_query(db_log_row_t *out, int max_rows, const char *min_level, const char *search) {
    if (!out || max_rows <= 0) return 0;
    if (max_rows > 2000) max_rows = 2000;
    if (!db_enter()) return -1;

    int rank = log_level_rank(min_level);
    const char *lvl = rank >= 3 ? " AND level = 'ERROR'" : (rank == 2 ? " AND level IN ('WARN','ERROR')" : "");
    int has_search = (search && *search);

    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT TOP (%d) id, ts, level, message FROM dbo.app_logs WHERE 1=1%s%s ORDER BY id DESC",
             max_rows, lvl, has_search ? " AND message LIKE ? ESCAPE '\\'" : "");

    int n = 0;
    q_t q;
    if (q_open(&q, g_dbc, sql, 0) == 0) {
        if (has_search) {
            char pat[300];
            size_t j = 0;
            pat[j++] = '%';
            for (const char *p = search; *p && j + 4 < sizeof(pat); p++) {
                if (*p == '%' || *p == '_' || *p == '[' || *p == '\\') pat[j++] = '\\';
                pat[j++] = *p;
            }
            pat[j++] = '%';
            pat[j] = '\0';
            q_text(&q, pat);
        }
        if (q_exec(&q, "query logs", 0) == 0) {
            while (n < max_rows && q_fetch(&q) == 1) {
                out[n].id = q_col_int(&q, 1);
                out[n].ts = q_col_int(&q, 2);
                q_col_text(&q, 3, out[n].level, sizeof(out[n].level));
                q_col_text(&q, 4, out[n].msg, sizeof(out[n].msg));
                n++;
            }
        }
        q_close(&q);
    }
    db_leave();
    return n;
}

int db_logs_clear(void) {
    if (!db_enter()) return -1;
    int rc = exec_direct(g_dbc, "DELETE FROM dbo.app_logs", 0);
    db_leave();
    return rc;
}
