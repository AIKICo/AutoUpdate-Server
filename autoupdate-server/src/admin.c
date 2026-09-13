#include "admin.h"
#include "utils.h"
#include "sha256.h"
#include "md5.h"
#include "db.h"
#include "server.h"
#include "zip_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <dirent.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>

int admin_get_current_user(const http_request_t *req, const server_ctx_t *ctx, char *out_user, size_t ulen, char *out_role, size_t rlen) {
    if (out_user && ulen > 0) out_user[0] = '\0';
    if (out_role && rlen > 0) out_role[0] = '\0';

    /* 1. Cookie token */
    char cookie_token[128] = {0};
    if (http_get_cookie(req, "auth_token", cookie_token, sizeof(cookie_token)) == 0 && strlen(cookie_token) > 0) {
        if (db_session_validate(cookie_token, out_user, ulen, out_role, rlen) != 0) {
            return 1;
        }
    }

    /* 2. Authorization header: Bearer or Basic */
    if (strlen(req->auth_header) > 0) {
        if (strncasecmp(req->auth_header, "Bearer ", 7) == 0) {
            const char *token = req->auth_header + 7;
            while (*token == ' ') token++;
            if (db_session_validate(token, out_user, ulen, out_role, rlen) != 0) {
                return 1;
            }
        } else if (strncasecmp(req->auth_header, "Basic ", 6) == 0) {
            char decoded[256];
            if (base64_decode(req->auth_header + 6, decoded, sizeof(decoded)) >= 0) {
                char *colon = strchr(decoded, ':');
                if (colon) {
                    *colon = '\0';
                    char *u = decoded;
                    char *p = colon + 1;
                    if (db_user_auth(u, p, out_role, rlen) != 0) {
                        if (out_user) strncpy(out_user, u, ulen - 1);
                        return 1;
                    }
                    if (strlen(ctx->admin_pass) > 0 && strcmp(u, ctx->admin_user) == 0 && strcmp(p, ctx->admin_pass) == 0) {
                        if (out_user) strncpy(out_user, u, ulen - 1);
                        if (out_role) strncpy(out_role, "admin", rlen - 1);
                        return 1;
                    }
                }
            }
        }
    }

    return 0;
}

int admin_is_authorized(const http_request_t *req, const server_ctx_t *ctx) {
    char user[64], role[32];
    if (admin_get_current_user(req, ctx, user, sizeof(user), role, sizeof(role))) {
        return 1;
    }

    /* If no password set in ctx and no users in DB, allow */
    if (strlen(ctx->admin_pass) == 0 && db_user_count() == 0) {
        return 1;
    }

    return 0;
}

static void send_auth_required(socket_t sock) {
    http_send_json(sock, 401, "{\"error\": 401, \"message\": \"Authentication required\"}\n");
}

static int sanitize_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) > 128) return 0;
    if (strstr(name, "..") || strchr(name, '/') || strchr(name, '\\')) return 0;
    for (size_t i = 0; i < strlen(name); i++) {
        char c = name[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.') return 0;
    }
    return 1;
}

static void get_form_param(const char *body, const char *key, char *out, size_t out_len) {
    out[0] = '\0';
    if (!body || !key) return;

    size_t klen = strlen(key);
    const char *p = body;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val = p + klen + 1;
            const char *amp = strchr(val, '&');
            size_t vlen = amp ? (size_t)(amp - val) : strlen(val);
            char enc[1024];
            if (vlen >= sizeof(enc)) vlen = sizeof(enc) - 1;
            memcpy(enc, val, vlen);
            enc[vlen] = '\0';
            url_decode(enc, out, out_len);
            return;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
}

static void get_body_param(const char *body, const char *key, char *out, size_t out_len) {
    out[0] = '\0';
    if (!body || !key) return;

    const char *b = body;
    while (*b == ' ' || *b == '\t' || *b == '\r' || *b == '\n') b++;
    if (*b == '{') {
        char search_key[128];
        snprintf(search_key, sizeof(search_key), "\"%s\"", key);
        const char *p = strstr(b, search_key);
        if (p) {
            p += strlen(search_key);
            while (*p == ' ' || *p == ':' || *p == '\t') p++;
            if (*p == '"') {
                p++;
                const char *end = strchr(p, '"');
                if (end) {
                    size_t len = (size_t)(end - p);
                    if (len >= out_len) len = out_len - 1;
                    memcpy(out, p, len);
                    out[len] = '\0';
                    return;
                }
            } else {
                const char *end = p;
                while (*end && *end != ',' && *end != '}' && *end != ' ' && *end != '\r' && *end != '\n') end++;
                size_t len = (size_t)(end - p);
                if (len >= out_len) len = out_len - 1;
                memcpy(out, p, len);
                out[len] = '\0';
                return;
            }
        }
    }

    get_form_param(body, key, out, out_len);
}

static void get_query_param(const char *query, const char *key, char *out, size_t out_len) {
    out[0] = '\0';
    if (!query || !key) return;

    char search_key[128];
    snprintf(search_key, sizeof(search_key), "%s=", key);
    const char *p = strstr(query, search_key);
    if (!p) {
        /* try key at start of query */
        if (strncmp(query, search_key, strlen(search_key)) == 0) p = query;
        else return;
    }
    const char *val = p + strlen(search_key);
    const char *amp = strchr(val, '&');
    size_t vlen = amp ? (size_t)(amp - val) : strlen(val);
    char enc[512];
    if (vlen >= sizeof(enc)) vlen = sizeof(enc) - 1;
    memcpy(enc, val, vlen);
    enc[vlen] = '\0';
    url_decode(enc, out, out_len);
}

static void json_escape(const char *src, char *dst, size_t dst_len) {
    if (!src || !dst || dst_len == 0) return;
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 2 < dst_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\';
            dst[j++] = '"';
        } else if (c == '\\') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\';
            dst[j++] = '\\';
        } else if (c == '\n') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c == '\r') {
            /* ignore CR */
        } else if (c == '\t') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\';
            dst[j++] = 't';
        } else if (c >= 32) {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static void normalize_slashes(char *path) {
#ifdef _WIN32
    if (!path) return;
    for (char *p = path; *p; p++) {
        if (*p == '/') *p = '\\';
    }
#else
    (void)path;
#endif
}

/* Recursively delete directory in pure C with attribute clearing */
static int delete_directory_recursive(const char *dir_path) {
    if (!dir_path || strlen(dir_path) == 0) return -1;
#ifndef _WIN32
    chmod(dir_path, 0777);
#endif
    DIR *d = opendir(dir_path);
    if (!d) {
#ifdef _WIN32
        SetFileAttributesA(dir_path, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileA(dir_path) == 0) remove(dir_path);
#else
        unlink(dir_path);
        remove(dir_path);
#endif
        struct stat st;
        return (stat(dir_path, &st) != 0) ? 0 : -1;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char subpath[1024];
        snprintf(subpath, sizeof(subpath), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (stat(subpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                delete_directory_recursive(subpath);
            } else {
#ifdef _WIN32
                SetFileAttributesA(subpath, FILE_ATTRIBUTE_NORMAL);
                if (DeleteFileA(subpath) == 0) remove(subpath);
#else
                chmod(subpath, 0777);
                unlink(subpath);
                remove(subpath);
#endif
            }
        } else {
#ifdef _WIN32
            SetFileAttributesA(subpath, FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileA(subpath) == 0) remove(subpath);
#else
            chmod(subpath, 0777);
            unlink(subpath);
            remove(subpath);
#endif
        }
    }
    closedir(d);

#ifdef _WIN32
    SetFileAttributesA(dir_path, FILE_ATTRIBUTE_NORMAL);
    if (_rmdir(dir_path) != 0) {
        RemoveDirectoryA(dir_path);
    }
#else
    rmdir(dir_path);
#endif

    /* Secondary fallback if directory still exists */
    struct stat check_st;
    if (stat(dir_path, &check_st) == 0) {
#ifdef _WIN32
        char norm_dir[1024];
        strncpy(norm_dir, dir_path, sizeof(norm_dir) - 1);
        norm_dir[sizeof(norm_dir) - 1] = '\0';
        normalize_slashes(norm_dir);
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "cmd.exe /c attrib -r -s -h \"%s\\*\" /s /d >nul 2>&1 & cmd.exe /c rmdir /s /q \"%s\" >nul 2>&1", norm_dir, norm_dir);
        run_hidden_command(cmd);
#else
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "rm -rf \"%s\" >/dev/null 2>&1", dir_path);
        int rc = system(cmd);
        (void)rc;
#endif
    }

    return (stat(dir_path, &check_st) != 0) ? 0 : -1;
}

/* Helper to search UTF-16 string in binary buffer and extract following UTF-16 value */
static int pe_find_utf16_val(const unsigned char *data, size_t len, const char *key, char *out, size_t out_len) {
    out[0] = '\0';
    if (!data || len == 0 || !key || out_len == 0) return 0;
    size_t klen = strlen(key);
    unsigned char wkey[256];
    size_t wlen = 0;
    for (size_t i = 0; i < klen && wlen + 2 < sizeof(wkey); i++) {
        wkey[wlen++] = (unsigned char)key[i];
        wkey[wlen++] = 0;
    }

    for (size_t i = 0; i + wlen + 4 <= len; i += 2) {
        if (memcmp(data + i, wkey, wlen) == 0) {
            size_t val_start = i + wlen;
            while (val_start + 2 <= len && data[val_start] == 0 && data[val_start+1] == 0) {
                val_start += 2;
            }
            size_t j = 0;
            while (val_start + 2 <= len && j + 1 < out_len) {
                unsigned char c1 = data[val_start];
                unsigned char c2 = data[val_start+1];
                if (c1 == 0 && c2 == 0) break;
                if (c2 == 0 && (c1 >= 32 && c1 <= 126)) {
                    out[j++] = (char)c1;
                } else if (c2 == 0 && c1 >= 128) {
                    out[j++] = (char)c1;
                } else if (c2 != 0) {
                    out[j++] = '?';
                }
                val_start += 2;
            }
            out[j] = '\0';
            if (strlen(out) > 0) return 1;
        }
    }
    return 0;
}

static const char *str_case_contains(const char *haystack, const char *needle);

/* Clean and normalize version string (remove 'v', git commit hashes like +sha or @sha, spaces, replace commas with dots) */
static void sanitize_version_string(char *ver, size_t max_len) {
    if (!ver || max_len == 0) return;
    char *p = ver;
    while (*p == ' ' || *p == '\t' || *p == 'v' || *p == 'V') p++;
    if (p != ver) memmove(ver, p, strlen(p) + 1);

    char *plus = strchr(ver, '+');
    if (plus) *plus = '\0';
    char *at = strchr(ver, '@');
    if (at) *at = '\0';
    char *space = strchr(ver, ' ');
    if (space) *space = '\0';

    for (size_t i = 0; ver[i]; i++) {
        if (ver[i] == ',') ver[i] = '.';
    }

    size_t len = strlen(ver);
    while (len > 0 && (ver[len - 1] == '.' || ver[len - 1] == ' ' || ver[len - 1] == '\r' || ver[len - 1] == '\n')) {
        ver[--len] = '\0';
    }
}

/* Traverse PE Resource Directory to locate the RT_VERSION (type 16) data entry */
static int pe_find_version_resource_data(const unsigned char *rdata, size_t rdata_len, uint32_t rsrc_rva,
                                         uint32_t *out_data_offset, uint32_t *out_data_size) {
    if (!rdata || rdata_len < 32 || !out_data_offset || !out_data_size) return 0;

    /* Root Resource Directory */
    uint16_t num_named = (uint16_t)(rdata[12] | (rdata[13] << 8));
    uint16_t num_id = (uint16_t)(rdata[14] | (rdata[15] << 8));
    uint32_t total_entries = (uint32_t)num_named + (uint32_t)num_id;

    uint32_t rt_version_subdir_offset = 0;
    int found_rt_ver = 0;

    for (uint32_t e = 0; e < total_entries && (16 + e * 8 + 8) <= rdata_len; e++) {
        uint32_t entry_offset = 16 + e * 8;
        uint32_t name = (uint32_t)(rdata[entry_offset] | (rdata[entry_offset+1] << 8) |
                                  (rdata[entry_offset+2] << 16) | (rdata[entry_offset+3] << 24));
        uint32_t data = (uint32_t)(rdata[entry_offset+4] | (rdata[entry_offset+5] << 8) |
                                  (rdata[entry_offset+6] << 16) | (rdata[entry_offset+7] << 24));

        /* RT_VERSION has ID 16 */
        if (name == 16 && (data & 0x80000000)) {
            rt_version_subdir_offset = data & 0x7FFFFFFF;
            found_rt_ver = 1;
            break;
        }
    }

    if (!found_rt_ver || rt_version_subdir_offset + 16 > rdata_len) return 0;

    /* Level 2: Name/ID Directory */
    const unsigned char *l2 = rdata + rt_version_subdir_offset;
    uint16_t l2_named = (uint16_t)(l2[12] | (l2[13] << 8));
    uint16_t l2_id = (uint16_t)(l2[14] | (l2[15] << 8));
    if ((l2_named + l2_id) == 0 || rt_version_subdir_offset + 16 + 8 > rdata_len) return 0;

    uint32_t l2_data = (uint32_t)(l2[16+4] | (l2[16+5] << 8) | (l2[16+6] << 16) | (l2[16+7] << 24));
    uint32_t l3_offset = l2_data & 0x7FFFFFFF;
    if (l3_offset + 16 > rdata_len) return 0;

    /* Level 3: Language Directory */
    const unsigned char *l3 = rdata + l3_offset;
    uint16_t l3_named = (uint16_t)(l3[12] | (l3[13] << 8));
    uint16_t l3_id = (uint16_t)(l3[14] | (l3[15] << 8));
    if ((l3_named + l3_id) == 0 || l3_offset + 16 + 8 > rdata_len) return 0;

    uint32_t data_entry_offset = (uint32_t)(l3[16+4] | (l3[16+5] << 8) | (l3[16+6] << 16) | (l3[16+7] << 24));
    data_entry_offset &= 0x7FFFFFFF;
    if (data_entry_offset + 16 > rdata_len) return 0;

    /* PE_RESOURCE_DATA_ENTRY */
    const unsigned char *de = rdata + data_entry_offset;
    uint32_t data_rva = (uint32_t)(de[0] | (de[1] << 8) | (de[2] << 16) | (de[3] << 24));
    uint32_t data_size = (uint32_t)(de[4] | (de[5] << 8) | (de[6] << 16) | (de[7] << 24));

    if (data_rva < rsrc_rva) return 0;
    uint32_t rsrc_rel_offset = data_rva - rsrc_rva;
    if (rsrc_rel_offset >= rdata_len) return 0;

    *out_data_offset = rsrc_rel_offset;
    *out_data_size = data_size;
    return 1;
}

#ifdef _WIN32
static int pe_inspect_windows_native(const char *filepath, pe_details_t *details) {
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeA(filepath, &dummy);
    if (size == 0) return 0;

    void *data = malloc(size);
    if (!data) return 0;

    int found = 0;
    if (GetFileVersionInfoA(filepath, 0, size, data)) {
        VS_FIXEDFILEINFO *ffi = NULL;
        UINT len = 0;
        if (VerQueryValueA(data, "\\", (LPVOID*)&ffi, &len) && ffi && len >= sizeof(VS_FIXEDFILEINFO)) {
            WORD v1 = HIWORD(ffi->dwFileVersionMS);
            WORD v2 = LOWORD(ffi->dwFileVersionMS);
            WORD v3 = HIWORD(ffi->dwFileVersionLS);
            WORD v4 = LOWORD(ffi->dwFileVersionLS);
            if (v1 != 0 || v2 != 0 || v3 != 0 || v4 != 0) {
                snprintf(details->file_version, sizeof(details->file_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                snprintf(details->product_version, sizeof(details->product_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                strncpy(details->detection_method, "Windows Native API (GetFileVersionInfo)", sizeof(details->detection_method) - 1);
                found = 1;
            }
        }

        struct {
            WORD wLanguage;
            WORD wCodePage;
        } *lpTranslate = NULL;
        UINT cbTranslate = 0;
        char subBlock[128];
        char *strVal = NULL;
        UINT strLen = 0;

        char lang_prefixes[8][16];
        int num_langs = 0;

        if (VerQueryValueA(data, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) && cbTranslate >= sizeof(*lpTranslate)) {
            int max_pairs = (int)(cbTranslate / sizeof(*lpTranslate));
            for (int p = 0; p < max_pairs && num_langs < 4; p++) {
                snprintf(lang_prefixes[num_langs++], 16, "%04x%04x", lpTranslate[p].wLanguage, lpTranslate[p].wCodePage);
            }
        }
        if (num_langs == 0) {
            strncpy(lang_prefixes[num_langs++], "040904b0", 15);
            strncpy(lang_prefixes[num_langs++], "000004b0", 15);
            strncpy(lang_prefixes[num_langs++], "040904e4", 15);
            strncpy(lang_prefixes[num_langs++], "04090000", 15);
        }

        for (int l = 0; l < num_langs; l++) {
            snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%s\\FileVersion", lang_prefixes[l]);
            if (VerQueryValueA(data, subBlock, (LPVOID*)&strVal, &strLen) && strVal && strLen > 0) {
                while (*strVal == ' ') strVal++;
                if (strlen(strVal) > 0) {
                    strncpy(details->file_version, strVal, sizeof(details->file_version) - 1);
                    strncpy(details->detection_method, "Windows Native API (FileVersion)", sizeof(details->detection_method) - 1);
                    found = 1;
                    break;
                }
            }
        }

        for (int l = 0; l < num_langs; l++) {
            snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%s\\ProductVersion", lang_prefixes[l]);
            if (VerQueryValueA(data, subBlock, (LPVOID*)&strVal, &strLen) && strVal && strLen > 0) {
                while (*strVal == ' ') strVal++;
                if (strlen(strVal) > 0) {
                    strncpy(details->product_version, strVal, sizeof(details->product_version) - 1);
                    break;
                }
            }
        }

        for (int l = 0; l < num_langs; l++) {
            snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%s\\FileDescription", lang_prefixes[l]);
            if (VerQueryValueA(data, subBlock, (LPVOID*)&strVal, &strLen) && strVal && strLen > 0) {
                while (*strVal == ' ') strVal++;
                if (strlen(strVal) > 0) {
                    strncpy(details->file_description, strVal, sizeof(details->file_description) - 1);
                    break;
                }
            }
        }

        for (int l = 0; l < num_langs; l++) {
            snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%s\\CompanyName", lang_prefixes[l]);
            if (VerQueryValueA(data, subBlock, (LPVOID*)&strVal, &strLen) && strVal && strLen > 0) {
                while (*strVal == ' ') strVal++;
                if (strlen(strVal) > 0) {
                    strncpy(details->company_name, strVal, sizeof(details->company_name) - 1);
                    break;
                }
            }
        }

        for (int l = 0; l < num_langs; l++) {
            snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%s\\OriginalFilename", lang_prefixes[l]);
            if (VerQueryValueA(data, subBlock, (LPVOID*)&strVal, &strLen) && strVal && strLen > 0) {
                while (*strVal == ' ') strVal++;
                if (strlen(strVal) > 0) {
                    if (strstr(strVal, ".dll") || strstr(strVal, ".DLL") || strchr(details->product_version, '+')) {
                        strncpy(details->runtime, ".NET Windows AppHost", sizeof(details->runtime) - 1);
                    }
                    break;
                }
            }
        }
    }

    free(data);
    return found;
}
#endif

/* Deep PE Executable Inspector */
int inspect_pe_executable(const char *filepath, pe_details_t *details) {
    if (!filepath || !details) return -1;
    memset(details, 0, sizeof(*details));

    const char *slash = strrchr(filepath, '/');
    const char *bslash = strrchr(filepath, '\\');
    const char *base = slash > bslash ? slash + 1 : (bslash ? bslash + 1 : filepath);
    strncpy(details->exe_name, base, sizeof(details->exe_name) - 1);

    struct stat st;
    if (stat(filepath, &st) == 0) {
        details->file_size = (uint64_t)st.st_size;
    }

    /* Defaults */
    strncpy(details->architecture, "Unknown", sizeof(details->architecture) - 1);
    strncpy(details->subsystem, "Windows Binary", sizeof(details->subsystem) - 1);
    strncpy(details->runtime, "Native Binary", sizeof(details->runtime) - 1);
    strncpy(details->file_version, "1.0.0.0", sizeof(details->file_version) - 1);
    strncpy(details->product_version, "1.0.0.0", sizeof(details->product_version) - 1);
    strncpy(details->file_description, "Application Executable", sizeof(details->file_description) - 1);
    strncpy(details->company_name, "Standard Release", sizeof(details->company_name) - 1);
    strncpy(details->detection_method, "Default Fallback", sizeof(details->detection_method) - 1);

    /* 1. Portable Raw PE Header Parsing (Arch, Subsystem, .NET CLR, and .rsrc Table) */
    uint32_t rsrc_rva = 0;
    uint32_t rsrc_size = 0;
    uint32_t rsrc_file_offset = 0;
    uint32_t rsrc_disk_size = 0;

    FILE *f = fopen(filepath, "rb");
    if (f) {
        unsigned char dos_hdr[64];
        if (fread(dos_hdr, 1, sizeof(dos_hdr), f) == sizeof(dos_hdr) &&
            dos_hdr[0] == 'M' && dos_hdr[1] == 'Z') {
            int32_t e_lfanew = (int32_t)(dos_hdr[60] | (dos_hdr[61] << 8) | (dos_hdr[62] << 16) | (dos_hdr[63] << 24));
            if (e_lfanew > 0 && fseek(f, e_lfanew, SEEK_SET) == 0) {
                unsigned char nt_sig[4];
                if (fread(nt_sig, 1, 4, f) == 4 && nt_sig[0] == 'P' && nt_sig[1] == 'E' && nt_sig[2] == 0 && nt_sig[3] == 0) {
                    unsigned char fh[20];
                    if (fread(fh, 1, 20, f) == 20) {
                        uint16_t machine = (uint16_t)(fh[0] | (fh[1] << 8));
                        uint16_t num_sections = (uint16_t)(fh[2] | (fh[3] << 8));
                        if (machine == 0x8664) {
                            strncpy(details->architecture, "x64 (64-bit AMD64)", sizeof(details->architecture) - 1);
                        } else if (machine == 0x014c) {
                            strncpy(details->architecture, "x86 (32-bit)", sizeof(details->architecture) - 1);
                        } else if (machine == 0xAA64) {
                            strncpy(details->architecture, "ARM64 (64-bit)", sizeof(details->architecture) - 1);
                        } else if (machine == 0x01c0) {
                            strncpy(details->architecture, "ARM (32-bit)", sizeof(details->architecture) - 1);
                        } else {
                            snprintf(details->architecture, sizeof(details->architecture), "Machine 0x%04X", machine);
                        }

                        uint16_t opt_size = (uint16_t)(fh[16] | (fh[17] << 8));
                        if (opt_size >= 68) {
                            unsigned char opt[256];
                            size_t read_opt = fread(opt, 1, opt_size > sizeof(opt) ? sizeof(opt) : opt_size, f);
                            if (read_opt >= 70) {
                                uint16_t opt_magic = (uint16_t)(opt[0] | (opt[1] << 8));
                                uint16_t subsys = (uint16_t)(opt[68] | (opt[69] << 8));
                                if (subsys == 2) {
                                    strncpy(details->subsystem, "Windows GUI Application", sizeof(details->subsystem) - 1);
                                } else if (subsys == 3) {
                                    strncpy(details->subsystem, "Console Application (CUI)", sizeof(details->subsystem) - 1);
                                }

                                uint32_t clr_rva = 0;
                                if (opt_magic == 0x010B) { /* PE32 */
                                    if (read_opt >= 120) {
                                        rsrc_rva = (uint32_t)(opt[112] | (opt[113] << 8) | (opt[114] << 16) | (opt[115] << 24));
                                        rsrc_size = (uint32_t)(opt[116] | (opt[117] << 8) | (opt[118] << 16) | (opt[119] << 24));
                                    }
                                    if (read_opt >= 212) {
                                        clr_rva = (uint32_t)(opt[208] | (opt[209] << 8) | (opt[210] << 16) | (opt[211] << 24));
                                    }
                                } else if (opt_magic == 0x020B) { /* PE32+ (64-bit) */
                                    if (read_opt >= 136) {
                                        rsrc_rva = (uint32_t)(opt[128] | (opt[129] << 8) | (opt[130] << 16) | (opt[131] << 24));
                                        rsrc_size = (uint32_t)(opt[132] | (opt[133] << 8) | (opt[134] << 16) | (opt[135] << 24));
                                    }
                                    if (read_opt >= 228) {
                                        clr_rva = (uint32_t)(opt[224] | (opt[225] << 8) | (opt[226] << 16) | (opt[227] << 24));
                                    }
                                }

                                if (clr_rva != 0) {
                                    strncpy(details->runtime, ".NET CLR Managed Assembly", sizeof(details->runtime) - 1);
                                } else {
                                    strncpy(details->runtime, "Native Windows Binary", sizeof(details->runtime) - 1);
                                }
                            }
                        }

                        /* Locate Section Headers table to map rsrc_rva to file offset */
                        long sec_table_offset = e_lfanew + 4 + 20 + opt_size;
                        if (rsrc_rva > 0 && fseek(f, sec_table_offset, SEEK_SET) == 0) {
                            for (uint16_t si = 0; si < num_sections; si++) {
                                unsigned char sec_hdr[40];
                                if (fread(sec_hdr, 1, 40, f) != 40) break;
                                uint32_t vSize = (uint32_t)(sec_hdr[8] | (sec_hdr[9] << 8) | (sec_hdr[10] << 16) | (sec_hdr[11] << 24));
                                uint32_t vAddr = (uint32_t)(sec_hdr[12] | (sec_hdr[13] << 8) | (sec_hdr[14] << 16) | (sec_hdr[15] << 24));
                                uint32_t rawSize = (uint32_t)(sec_hdr[16] | (sec_hdr[17] << 8) | (sec_hdr[18] << 16) | (sec_hdr[19] << 24));
                                uint32_t rawOffset = (uint32_t)(sec_hdr[20] | (sec_hdr[21] << 8) | (sec_hdr[22] << 16) | (sec_hdr[23] << 24));

                                if (rsrc_rva >= vAddr && rsrc_rva < (vAddr + vSize)) {
                                    rsrc_file_offset = rawOffset + (rsrc_rva - vAddr);
                                    rsrc_disk_size = rawSize;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        fclose(f);
    }

    /* 2. Windows Native Version API (Gold Standard on Windows) */
#ifdef _WIN32
    if (pe_inspect_windows_native(filepath, details)) {
        log_msg("INFO", "Windows Native API extracted version for '%s': v%s", details->exe_name, details->file_version);
    }
#endif

    /* 3. Cross-Platform PE Resource Directory Tree Parsing (Linux / Cross-Platform) */
    if (strcmp(details->detection_method, "Default Fallback") == 0 && rsrc_file_offset > 0 && rsrc_size > 0) {
        FILE *rf = fopen(filepath, "rb");
        if (rf) {
            if (fseek(rf, rsrc_file_offset, SEEK_SET) == 0) {
                size_t to_read = rsrc_size < rsrc_disk_size ? rsrc_size : rsrc_disk_size;
                if (to_read > 16 * 1024 * 1024) to_read = 16 * 1024 * 1024;
                unsigned char *rdata = (unsigned char *)malloc(to_read);
                if (rdata) {
                    size_t rd = fread(rdata, 1, to_read, rf);

                    /* A. Locate RT_VERSION (type 16) specifically via Resource Directory Tree */
                    uint32_t ver_rel_offset = 0;
                    uint32_t ver_blob_size = 0;
                    if (pe_find_version_resource_data(rdata, rd, rsrc_rva, &ver_rel_offset, &ver_blob_size) &&
                        ver_rel_offset + 16 <= rd) {
                        const unsigned char *vblob = rdata + ver_rel_offset;
                        size_t vblob_len = (ver_rel_offset + ver_blob_size <= rd) ? ver_blob_size : (rd - ver_rel_offset);

                        /* Search VS_FIXEDFILEINFO in the true application version blob */
                        for (size_t i = 0; i + 16 <= vblob_len; i++) {
                            if (vblob[i] == 0xBD && vblob[i+1] == 0x04 && vblob[i+2] == 0xEF && vblob[i+3] == 0xFE) {
                                uint32_t ms = (uint32_t)vblob[i+8] | ((uint32_t)vblob[i+9] << 8) | ((uint32_t)vblob[i+10] << 16) | ((uint32_t)vblob[i+11] << 24);
                                uint32_t ls = (uint32_t)vblob[i+12] | ((uint32_t)vblob[i+13] << 8) | ((uint32_t)vblob[i+14] << 16) | ((uint32_t)vblob[i+15] << 24);
                                uint16_t v1 = (uint16_t)(ms >> 16);
                                uint16_t v2 = (uint16_t)(ms & 0xFFFF);
                                uint16_t v3 = (uint16_t)(ls >> 16);
                                uint16_t v4 = (uint16_t)(ls & 0xFFFF);
                                if (v1 != 0 || v2 != 0 || v3 != 0 || v4 != 0) {
                                    snprintf(details->file_version, sizeof(details->file_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                                    snprintf(details->product_version, sizeof(details->product_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                                    strncpy(details->detection_method, "PE Resource Directory Tree (RT_VERSION)", sizeof(details->detection_method) - 1);
                                    break;
                                }
                            }
                        }

                        /* Extract rich metadata from the true version blob */
                        char str_val[256];
                        if (pe_find_utf16_val(vblob, vblob_len, "FileVersion", str_val, sizeof(str_val))) {
                            strncpy(details->file_version, str_val, sizeof(details->file_version) - 1);
                            strncpy(details->detection_method, "PE Resource StringFileInfo (FileVersion)", sizeof(details->detection_method) - 1);
                        }
                        if (pe_find_utf16_val(vblob, vblob_len, "ProductVersion", str_val, sizeof(str_val))) {
                            strncpy(details->product_version, str_val, sizeof(details->product_version) - 1);
                        }
                        if (pe_find_utf16_val(vblob, vblob_len, "FileDescription", str_val, sizeof(str_val))) {
                            strncpy(details->file_description, str_val, sizeof(details->file_description) - 1);
                        }
                        if (pe_find_utf16_val(vblob, vblob_len, "CompanyName", str_val, sizeof(str_val))) {
                            strncpy(details->company_name, str_val, sizeof(details->company_name) - 1);
                        }
                        if (pe_find_utf16_val(vblob, vblob_len, "OriginalFilename", str_val, sizeof(str_val))) {
                            if (strstr(str_val, ".dll") || strstr(str_val, ".DLL") || strchr(details->product_version, '+')) {
                                strncpy(details->runtime, ".NET Windows AppHost", sizeof(details->runtime) - 1);
                            }
                        }
                    }

                    /* B. Fallback Linear Scan in .rsrc, skipping Microsoft runtime helper DLLs (mscordaccore.dll etc.) */
                    if (strcmp(details->detection_method, "Default Fallback") == 0) {
                        for (size_t i = 0; i + 16 <= rd; i++) {
                            if (rdata[i] == 0xBD && rdata[i+1] == 0x04 && rdata[i+2] == 0xEF && rdata[i+3] == 0xFE) {
                                size_t check_len = (i + 1500 <= rd) ? 1500 : (rd - i);
                                char check_str[256] = {0};
                                if (pe_find_utf16_val(rdata + i, check_len, "OriginalFilename", check_str, sizeof(check_str))) {
                                    if (strcasecmp(check_str, "mscordaccore.dll") == 0 || strcasecmp(check_str, "createdump.exe") == 0) {
                                        continue; /* Skip Microsoft runtime helper */
                                    }
                                }
                                if (pe_find_utf16_val(rdata + i, check_len, "CompanyName", check_str, sizeof(check_str))) {
                                    if (strcasecmp(check_str, "Microsoft Corporation") == 0 &&
                                        !str_case_contains(details->exe_name, "microsoft")) {
                                        continue; /* Skip generic Microsoft component */
                                    }
                                }

                                uint32_t ms = (uint32_t)rdata[i+8] | ((uint32_t)rdata[i+9] << 8) | ((uint32_t)rdata[i+10] << 16) | ((uint32_t)rdata[i+11] << 24);
                                uint32_t ls = (uint32_t)rdata[i+12] | ((uint32_t)rdata[i+13] << 8) | ((uint32_t)rdata[i+14] << 16) | ((uint32_t)rdata[i+15] << 24);
                                uint16_t v1 = (uint16_t)(ms >> 16);
                                uint16_t v2 = (uint16_t)(ms & 0xFFFF);
                                uint16_t v3 = (uint16_t)(ls >> 16);
                                uint16_t v4 = (uint16_t)(ls & 0xFFFF);
                                if (v1 != 0 || v2 != 0 || v3 != 0 || v4 != 0) {
                                    snprintf(details->file_version, sizeof(details->file_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                                    snprintf(details->product_version, sizeof(details->product_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                                    strncpy(details->detection_method, "PE Resource (.rsrc VS_FIXEDFILEINFO)", sizeof(details->detection_method) - 1);

                                    char str_val[256];
                                    if (pe_find_utf16_val(rdata + i, check_len, "FileVersion", str_val, sizeof(str_val))) {
                                        strncpy(details->file_version, str_val, sizeof(details->file_version) - 1);
                                    }
                                    if (pe_find_utf16_val(rdata + i, check_len, "ProductVersion", str_val, sizeof(str_val))) {
                                        strncpy(details->product_version, str_val, sizeof(details->product_version) - 1);
                                    }
                                    if (pe_find_utf16_val(rdata + i, check_len, "FileDescription", str_val, sizeof(str_val))) {
                                        strncpy(details->file_description, str_val, sizeof(details->file_description) - 1);
                                    }
                                    if (pe_find_utf16_val(rdata + i, check_len, "CompanyName", str_val, sizeof(str_val))) {
                                        strncpy(details->company_name, str_val, sizeof(details->company_name) - 1);
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    free(rdata);
                }
            }
            fclose(rf);
        }
    }

    /* 4. Cross-Platform Chunked Full File Scan Fallback for non-standard binaries */
    if (strcmp(details->detection_method, "Default Fallback") == 0) {
        FILE *f2 = fopen(filepath, "rb");
        if (f2) {
            const size_t chunk_size = 1024 * 1024; /* 1 MB chunks */
            unsigned char *chunk = (unsigned char *)malloc(chunk_size + 64);
            if (chunk) {
                size_t prev_overlap = 0;
                while (1) {
                    size_t read_bytes = fread(chunk + prev_overlap, 1, chunk_size, f2);
                    size_t total_buf = prev_overlap + read_bytes;
                    if (total_buf < 16) break;

                    for (size_t i = 0; i + 16 <= total_buf; i++) {
                        if (chunk[i] == 0xBD && chunk[i+1] == 0x04 && chunk[i+2] == 0xEF && chunk[i+3] == 0xFE) {
                            size_t check_len = (i + 1500 <= total_buf) ? 1500 : (total_buf - i);
                            char check_str[256] = {0};
                            if (pe_find_utf16_val(chunk + i, check_len, "OriginalFilename", check_str, sizeof(check_str))) {
                                if (strcasecmp(check_str, "mscordaccore.dll") == 0 || strcasecmp(check_str, "createdump.exe") == 0) {
                                    continue;
                                }
                            }
                            if (pe_find_utf16_val(chunk + i, check_len, "CompanyName", check_str, sizeof(check_str))) {
                                if (strcasecmp(check_str, "Microsoft Corporation") == 0 &&
                                    !str_case_contains(details->exe_name, "microsoft")) {
                                    continue;
                                }
                            }

                            uint32_t ms = (uint32_t)chunk[i+8] | ((uint32_t)chunk[i+9] << 8) | ((uint32_t)chunk[i+10] << 16) | ((uint32_t)chunk[i+11] << 24);
                            uint32_t ls = (uint32_t)chunk[i+12] | ((uint32_t)chunk[i+13] << 8) | ((uint32_t)chunk[i+14] << 16) | ((uint32_t)chunk[i+15] << 24);
                            uint16_t v1 = (uint16_t)(ms >> 16);
                            uint16_t v2 = (uint16_t)(ms & 0xFFFF);
                            uint16_t v3 = (uint16_t)(ls >> 16);
                            uint16_t v4 = (uint16_t)(ls & 0xFFFF);
                            if (v1 != 0 || v2 != 0 || v3 != 0 || v4 != 0) {
                                snprintf(details->file_version, sizeof(details->file_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                                snprintf(details->product_version, sizeof(details->product_version), "%u.%u.%u.%u", v1, v2, v3, v4);
                                strncpy(details->detection_method, "Cross-Platform Full PE Scan (0xFEEF04BD)", sizeof(details->detection_method) - 1);
                                break;
                            }
                        }
                    }

                    if (strcmp(details->detection_method, "Default Fallback") != 0 || read_bytes == 0) {
                        break;
                    }

                    /* Keep last 32 bytes for overlap */
                    prev_overlap = total_buf >= 32 ? 32 : total_buf;
                    memmove(chunk, chunk + total_buf - prev_overlap, prev_overlap);
                }
                free(chunk);
            }
            fclose(f2);
        }
    }

    /* Sanitize and normalize version strings (strip commit hash suffix, extra spaces, commas to dots) */
    sanitize_version_string(details->file_version, sizeof(details->file_version));
    sanitize_version_string(details->product_version, sizeof(details->product_version));

    snprintf(details->summary, sizeof(details->summary),
             "%s [%s, %s, %s] -> v%s",
             details->exe_name, details->architecture, details->subsystem, details->runtime, details->file_version);

    return 0;
}

static int get_exe_version(const char *filepath, char *out_ver, size_t out_len) {
    pe_details_t details;
    if (inspect_pe_executable(filepath, &details) == 0) {
        strncpy(out_ver, details.file_version, out_len - 1);
        out_ver[out_len - 1] = '\0';
        return 0;
    }
    return -1;
}

static const char *str_case_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;
    for (; *haystack; haystack++) {
#ifdef _WIN32
        if (_strnicmp(haystack, needle, nlen) == 0) return haystack;
#else
        if (strncasecmp(haystack, needle, nlen) == 0) return haystack;
#endif
    }
    return NULL;
}

/* Strip architecture / OS suffix from app name:
   e.g. SmartPurchaseDocManager-win-x64 -> SmartPurchaseDocManager */
static void strip_app_suffix(const char *app, char *out, size_t out_len) {
    strncpy(out, app, out_len - 1);
    out[out_len - 1] = '\0';

    const char *suffixes[] = {
        "-win-x64", "_win-x64", ".win-x64", "-win-x86", "_win-x86",
        "-win-arm64", "_win-arm64", "-windows-x64", "_windows-x64",
        "-windows", "_windows", "-linux-x64", "_linux-x64",
        "-win", "_win", "-x64", "_x64", "-x86", "_x86",
        NULL
    };

    for (int i = 0; suffixes[i]; i++) {
        size_t slen = strlen(suffixes[i]);
        size_t olen = strlen(out);
        if (olen > slen) {
#ifdef _WIN32
            if (_stricmp(out + olen - slen, suffixes[i]) == 0) {
#else
            if (strcasecmp(out + olen - slen, suffixes[i]) == 0) {
#endif
                out[olen - slen] = '\0';
                break;
            }
        }
    }
}

/* Score candidate executable based on similarity to preferred_app */
static int score_candidate_exe(const char *filename, const char *preferred_app, const char *stripped_app) {
    const char *slash = strrchr(filename, '/');
    const char *bslash = strrchr(filename, '\\');
    const char *base = slash > bslash ? slash + 1 : (bslash ? bslash + 1 : filename);
    size_t blen = strlen(base);
    if (blen < 4) return 0;
#ifdef _WIN32
    if (_stricmp(base + blen - 4, ".exe") != 0) return 0;
#else
    if (strcasecmp(base + blen - 4, ".exe") != 0) return 0;
#endif

    if (str_case_contains(base, "createdump") ||
        str_case_contains(base, "unins") ||
        str_case_contains(base, "setup") ||
        str_case_contains(base, "installer") ||
        str_case_contains(base, "vc_redist") ||
        str_case_contains(base, "dxwebsetup")) {
        return 10;
    }

    char expected_full[256];
    snprintf(expected_full, sizeof(expected_full), "%s.exe", preferred_app);

    char expected_clean[256];
    snprintf(expected_clean, sizeof(expected_clean), "%s.exe", stripped_app);

#ifdef _WIN32
    if (_stricmp(base, expected_full) == 0) return 100;
    if (_stricmp(base, expected_clean) == 0) return 90;
#else
    if (strcasecmp(base, expected_full) == 0) return 100;
    if (strcasecmp(base, expected_clean) == 0) return 90;
#endif

    size_t slen = strlen(stripped_app);
    if (slen > 0) {
#ifdef _WIN32
        if (_strnicmp(base, stripped_app, slen) == 0) return 80;
#else
        if (strncasecmp(base, stripped_app, slen) == 0) return 80;
#endif
        if (str_case_contains(base, stripped_app)) return 70;
    }

    return 50;
}

/* Unzip archive into target directory with fast targeted extraction and pure C zip reader */
static int extract_zip_archive(const char *zip_path, const char *dest_dir, const char *preferred_app) {
    /* Step 1: Ultra-fast targeted extraction via pure-C zip_reader */
    char best_entry[1024] = {0};
    if (zip_find_best_executable(zip_path, preferred_app, best_entry, sizeof(best_entry))) {
        log_msg("INFO", "Identified primary executable entry in archive: '%s'", best_entry);
        const char *slash = strrchr(best_entry, '/');
        const char *bslash = strrchr(best_entry, '\\');
        const char *base_name = slash > bslash ? slash + 1 : (bslash ? bslash + 1 : best_entry);

        char target_out[1024];
        snprintf(target_out, sizeof(target_out), "%s/%s", dest_dir, base_name);
        if (zip_extract_entry(zip_path, best_entry, target_out) == 0) {
            log_msg("INFO", "Pure-C targeted extraction succeeded for '%s'", target_out);
            return 0;
        }
    }

    /* Step 2: Full archive extraction via pure-C zip_reader */
    log_msg("INFO", "Extracting full zip archive '%s' via pure C...", zip_path);
    if (zip_extract_all(zip_path, dest_dir) == 0) {
        return 0;
    }

    /* Step 3: Platform OS tool fallbacks if zip had unsupported features (e.g. Zip64) */
#ifdef _WIN32
    char norm_zip[1024], norm_dest[1024];
    strncpy(norm_zip, zip_path, sizeof(norm_zip) - 1);
    strncpy(norm_dest, dest_dir, sizeof(norm_dest) - 1);
    normalize_slashes(norm_zip);
    normalize_slashes(norm_dest);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "tar.exe -xf \"%s\" -C \"%s\"", norm_zip, norm_dest);
    if (run_hidden_command(cmd) == 0) return 0;

    snprintf(cmd, sizeof(cmd), "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Expand-Archive -LiteralPath '%s' -DestinationPath '%s' -Force\"", norm_zip, norm_dest);
    return run_hidden_command(cmd);
#else
    char cmd[2048];
    /* Try python3 zipfile module */
    snprintf(cmd, sizeof(cmd), "python3 -c \"import zipfile, sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])\" \"%s\" \"%s\" >/dev/null 2>&1", zip_path, dest_dir);
    if (system(cmd) == 0) return 0;

    /* Try unzip */
    snprintf(cmd, sizeof(cmd), "unzip -q -o \"%s\" -d \"%s\" >/dev/null 2>&1", zip_path, dest_dir);
    if (system(cmd) == 0) return 0;

    /* Try tar */
    snprintf(cmd, sizeof(cmd), "tar -xf \"%s\" -C \"%s\" >/dev/null 2>&1", zip_path, dest_dir);
    return system(cmd);
#endif
}

/* Recursively find best candidate .exe file */
static void find_target_executable_recursive(const char *dir_path, const char *preferred_app, const char *stripped_app,
                                            char *best_exe, int *best_score, int depth) {
    if (depth > 6) return;
    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char subpath[1024];
        snprintf(subpath, sizeof(subpath), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (stat(subpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                find_target_executable_recursive(subpath, preferred_app, stripped_app, best_exe, best_score, depth + 1);
            } else {
                int sc = score_candidate_exe(ent->d_name, preferred_app, stripped_app);
                if (sc > *best_score) {
                    *best_score = sc;
                    strncpy(best_exe, subpath, 1023);
                    best_exe[1023] = '\0';
                }
            }
        }
    }
    closedir(d);
}

static int find_target_executable(const char *dir_path, const char *preferred_base, char *out_exe, size_t max_len) {
    out_exe[0] = '\0';
    char stripped_app[128] = {0};
    if (preferred_base) {
        strip_app_suffix(preferred_base, stripped_app, sizeof(stripped_app));
    }
    int best_score = 0;
    char best_path[1024] = {0};
    find_target_executable_recursive(dir_path, preferred_base ? preferred_base : "", stripped_app, best_path, &best_score, 0);
    if (best_score > 0 && best_path[0] != '\0') {
        strncpy(out_exe, best_path, max_len - 1);
        out_exe[max_len - 1] = '\0';
        return 1;
    }
    return 0;
}


/* Fallback Embedded HTML Dashboard */
const char *admin_get_embedded_html(void) {
    return "<!DOCTYPE html>\n"
           "<html lang=\"en\" dir=\"ltr\">\n"
           "<head>\n"
           "<meta charset=\"UTF-8\">\n"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
           "<title>AutoUpdater.NET - Multi-Application Web Server</title>\n"
           "<style>\n"
           ":root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; --border: #334155; --success: #22c55e; --btn: #0284c7; --danger: #ef4444; }\n"
           "* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }\n"
           "body { background: var(--bg); color: var(--text); padding: 20px; line-height: 1.6; }\n"
           ".container { max-width: 1100px; margin: 0 auto; }\n"
           "header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; flex-wrap:wrap; gap:10px; }\n"
           "h1 { font-size: 1.4rem; color: var(--accent); display: flex; align-items: center; gap: 10px; }\n"
           ".badge { background: #065f46; color: #34d399; font-size: 0.8rem; padding: 4px 10px; border-radius: 9999px; font-weight: bold; }\n"
           ".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }\n"
           ".card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }\n"
           ".card-title { font-size: 0.85rem; color: #94a3b8; margin-bottom: 6px; }\n"
           ".card-value { font-size: 1.5rem; font-weight: bold; color: var(--text); }\n"
           ".section { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }\n"
           "h2 { font-size: 1.15rem; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 8px; color: var(--accent); }\n"
           ".app-selector-bar { display: flex; align-items: center; gap: 12px; background: #132742; padding: 12px 18px; border-radius: 8px; margin-bottom: 20px; flex-wrap: wrap; }\n"
           "select, input, textarea { background: #0f172a; border: 1px solid var(--border); border-radius: 6px; padding: 9px 12px; color: #fff; font-size: 0.9rem; }\n"
           "button { background: var(--btn); color: #fff; border: none; padding: 9px 18px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.2s; }\n"
           "button:hover { opacity: 0.9; }\n"
           ".btn-danger { background: var(--danger); padding: 5px 10px; font-size: 0.8rem; }\n"
           ".btn-secondary { background: #334155; padding: 5px 10px; font-size: 0.8rem; }\n"
           "table { width: 100%; border-collapse: collapse; margin-top: 10px; text-align: left; font-size: 0.88rem; }\n"
           "th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); }\n"
           "th { background: #182234; color: #94a3b8; }\n"
           "code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; display: inline-block; font-size: 0.85rem; }\n"
           "pre { background: #0f172a; border: 1px solid var(--border); padding: 15px; border-radius: 8px; overflow-x: auto; color: #38bdf8; font-family: Consolas, monospace; margin-top: 10px; }\n"
           "</style>\n"
           "</head>\n"
           "<body>\n"
           "<div class=\"container\">\n"
           "<header>\n"
           "  <h1><span>⚡</span> AutoUpdater.NET Server</h1>\n"
           "  <span class=\"badge\">● Online (Multi-App Enabled)</span>\n"
           "</header>\n"
           "\n"
           "<div class=\"app-selector-bar\">\n"
           "  <label style=\"font-weight:bold;\">📁 Current Application / Folder:</label>\n"
           "  <select id=\"currentApp\" onchange=\"onAppChange()\" style=\"min-width:200px;\">\n"
           "    <option value=\"\">Root Repository</option>\n"
           "  </select>\n"
           "  <button type=\"button\" onclick=\"promptNewApp()\">➕ New App Folder</button>\n"
           "</div>\n"
           "\n"
           "<div class=\"grid\">\n"
           "  <div class=\"card\"><div class=\"card-title\">Server Status</div><div class=\"card-value\" id=\"st-status\">Active</div></div>\n"
           "  <div class=\"card\"><div class=\"card-title\">Uptime</div><div class=\"card-value\" id=\"st-uptime\">...</div></div>\n"
           "  <div class=\"card\"><div class=\"card-title\">Total Requests</div><div class=\"card-value\" id=\"st-requests\">0</div></div>\n"
           "  <div class=\"card\"><div class=\"card-title\">Total Data Sent</div><div class=\"card-value\" id=\"st-bytes\">0 MB</div></div>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\" style=\"border:2px solid var(--accent); background:#132742;\">\n"
           "  <h2>⚡ 1-Click Publish from Zip (Auto Version & Persistent URL)</h2>\n"
           "  <form id=\"embZipForm\" onsubmit=\"publishZip(event)\" style=\"display:grid; grid-template-columns:1fr 1fr; gap:12px;\">\n"
           "    <div><label>Application Name (English):</label><input type=\"text\" id=\"embZipApp\" placeholder=\"e.g. MyPOSApp\" required></div>\n"
           "    <div><label>Select .zip Package:</label><input type=\"file\" id=\"embZipFile\" accept=\".zip\" required></div>\n"
           "    <div style=\"grid-column: span 2;\"><button type=\"submit\" id=\"btnEmbZip\" style=\"background:#0284c7; width:100%;\">🚀 Upload Zip, Extract Version & Auto-Publish</button></div>\n"
           "  </form>\n"
           "  <div id=\"embZipRes\" style=\"display:none; margin-top:14px; background:#0f172a; padding:12px; border-radius:6px; border:1px solid var(--success);\">\n"
           "    <div style=\"color:#34d399; font-weight:bold;\">✅ Version: <span id=\"embVer\"></span></div>\n"
           "    <div style=\"margin-top:8px;\"><label>Persistent AutoUpdater.xml URL:</label><input type=\"text\" id=\"embUrl\" readonly style=\"width:100%; color:var(--accent); font-weight:bold;\" onclick=\"this.select()\"></div>\n"
           "  </div>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\">\n"
           "  <h2>📦 Manual Publish for Selected App</h2>\n"
           "  <form id=\"genForm\" onsubmit=\"generateConfig(event)\" style=\"display:grid; grid-template-columns:1fr 1fr; gap:12px;\">\n"
           "    <div>\n"
           "      <label>Application / Subfolder Name:</label>\n"
           "      <input type=\"text\" id=\"appName\" required>\n"
           "    </div>\n"
           "    <div>\n"
           "      <label>Release Version:</label>\n"
           "      <input type=\"text\" id=\"appVer\" value=\"1.0.0.0\" required>\n"
           "    </div>\n"
           "    <div>\n"
           "      <label>Package File (Setup.zip or Setup.exe):</label>\n"
           "      <input type=\"text\" id=\"fileUrl\" required>\n"
           "    </div>\n"
           "    <div>\n"
           "      <label>Checksum Algorithm:</label>\n"
           "      <select id=\"hashAlgo\">\n"
           "        <option value=\"SHA256\">SHA256 (Recommended)</option>\n"
           "        <option value=\"MD5\">MD5</option>\n"
           "      </select>\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <label>Checksum Hash Value:</label>\n"
           "      <input type=\"text\" id=\"hashVal\" placeholder=\"Auto-filled when selecting a file below\">\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <label>Mandatory Update:</label>\n"
           "      <select id=\"mandatory\">\n"
           "        <option value=\"false\">No (Optional update)</option>\n"
           "        <option value=\"true\">Yes (Mandatory update)</option>\n"
           "      </select>\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <label>Changelog / Release Notes:</label>\n"
           "      <textarea id=\"changelog\" rows=\"2\">- Performance improvements&#10;- Bug fixes</textarea>\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <button type=\"submit\">Generate & Save AutoUpdater.xml & AutoUpdater.json</button>\n"
           "    </div>\n"
           "  </form>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\">\n"
           "  <h2>📁 Files in Current Folder</h2>\n"
           "  <input type=\"file\" id=\"tableReplaceInput\" style=\"display:none;\" onchange=\"executeTableFileReplace(event)\">\n"
           "  <div style=\"margin-bottom: 12px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;\">\n"
           "    <input type=\"file\" id=\"uploadFile\" style=\"max-width:320px;\">\n"
           "    <select id=\"uploadTargetOverride\" style=\"max-width:240px;\"><option value=\"\">-- Upload as New File --</option></select>\n"
           "    <button type=\"button\" onclick=\"uploadSelectedFile()\">⬆️ Upload / Replace</button>\n"
           "  </div>\n"
           "  <table id=\"filesTable\">\n"
           "    <thead><tr><th>File Name</th><th>Folder</th><th>Size</th><th>SHA-256 Checksum</th><th>Download</th><th>Action</th></tr></thead>\n"
           "    <tbody><tr><td colspan=\"6\" style=\"text-align:center;\">Loading...</td></tr></tbody>\n"
           "  </table>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\" id=\"editorSection\">\n"
           "  <h2>📝 AutoUpdater.xml &amp; Config Editor</h2>\n"
           "  <div style=\"display:flex; gap:10px; margin-bottom:10px; flex-wrap:wrap; align-items:center;\">\n"
           "    <select id=\"editorTargetFile\" onchange=\"loadEditorFile()\">\n"
           "      <option value=\"AutoUpdater.xml\">AutoUpdater.xml</option>\n"
           "      <option value=\"AutoUpdater.json\">AutoUpdater.json</option>\n"
           "      <option value=\"changelog.html\">changelog.html</option>\n"
           "    </select>\n"
           "    <button type=\"button\" class=\"btn-secondary\" onclick=\"loadEditorFile()\">📥 Load Content</button>\n"
           "    <button type=\"button\" class=\"btn-secondary\" onclick=\"saveEditorFile()\">💾 Save Changes</button>\n"
           "    <span id=\"editorStatus\" style=\"font-size:0.85rem; color:#94a3b8;\"></span>\n"
           "  </div>\n"
           "  <textarea id=\"fileEditorText\" style=\"width:100%; min-height:240px; background:#080c14; color:#38bdf8; font-family:Consolas,monospace; font-size:0.9rem; padding:12px; border:1px solid #334155; border-radius:6px;\" placeholder=\"AutoUpdater.xml content will appear here...\"></textarea>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\">\n"
           "  <h2>💻 C# Client Code Integration</h2>\n"
           "  <pre><code id=\"csharpCode\"></code></pre>\n"
           "</div>\n"
           "</div>\n"
           "\n"
           "<script>\n"
           "let targetReplaceApp = '', targetReplaceName = '';\n"
           "function promptReplaceFile(app, name) { targetReplaceApp = app; targetReplaceName = name; const inp = document.getElementById('tableReplaceInput'); inp.value=''; inp.click(); }\n"
           "function executeTableFileReplace(e) {\n"
           "  const fi = e.target; if (!fi.files || !fi.files[0]) return;\n"
           "  if (!confirm(`Replace ${targetReplaceName} with ${fi.files[0].name}? Existing file will be overwritten.`)) { fi.value=''; return; }\n"
           "  fetch('/api/upload?app=' + encodeURIComponent(targetReplaceApp) + '&name=' + encodeURIComponent(targetReplaceName), { method:'POST', body:fi.files[0] })\n"
           "  .then(r=>r.json()).then(res=>{\n"
           "    alert(`File replaced successfully!\\nSHA-256: ${res.sha256}`);\n"
           "    loadFiles(); fi.value='';\n"
           "    if (confirm('Update AutoUpdater.xml with this checksum?')) autoUpdateXmlChecksum(targetReplaceApp, res.sha256);\n"
           "  }).catch(e=>alert(e));\n"
           "}\n"
           "function autoUpdateXmlChecksum(app, sha) {\n"
           "  fetch('/api/get_file_content?app=' + encodeURIComponent(app) + '&name=AutoUpdater.xml')\n"
           "  .then(r=>r.text()).then(xml=>{\n"
           "    let updated = xml.replace(/<checksum\\b[^>]*>.*?<\\/checksum>/is, `<checksum algorithm=\"SHA256\">${sha}</checksum>`);\n"
           "    return fetch('/api/save_file_content?app=' + encodeURIComponent(app) + '&name=AutoUpdater.xml', { method:'POST', body:updated });\n"
           "  }).then(()=>{ alert('AutoUpdater.xml checksum updated!'); loadEditorFile(); }).catch(e=>alert(e));\n"
           "}\n"
           "function openInEditor(app, name) {\n"
           "  const sel = document.getElementById('editorTargetFile');\n"
           "  let f=false; for(let i=0;i<sel.options.length;i++) if(sel.options[i].value===name) f=true;\n"
           "  if(!f) { const opt=document.createElement('option'); opt.value=name; opt.text=name; sel.add(opt); }\n"
           "  sel.value = name; loadEditorFile(); document.getElementById('editorSection').scrollIntoView();\n"
           "}\n"
           "function loadEditorFile() {\n"
           "  const app = document.getElementById('currentApp').value, name = document.getElementById('editorTargetFile').value;\n"
           "  const st = document.getElementById('editorStatus'); st.innerText = 'Loading...';\n"
           "  fetch('/api/get_file_content?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name))\n"
           "  .then(r=>r.ok?r.text():'').then(txt=>{ document.getElementById('fileEditorText').value = txt; st.innerText = `Loaded (${txt.length} bytes)`; })\n"
           "  .catch(()=>{ st.innerText = 'File not found'; });\n"
           "}\n"
           "function saveEditorFile() {\n"
           "  const app = document.getElementById('currentApp').value, name = document.getElementById('editorTargetFile').value;\n"
           "  const body = document.getElementById('fileEditorText').value;\n"
           "  fetch('/api/save_file_content?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name), { method:'POST', body:body })\n"
           "  .then(r=>r.json()).then(res=>{ alert(res.message || 'Saved'); loadFiles(); }).catch(e=>alert(e));\n"
           "}\n"
           "function updateStats() {\n"
           "  fetch('/api/stats').then(r=>r.json()).then(d=>{\n"
           "    const sec = d.uptime_sec, h = Math.floor(sec/3600), m = Math.floor((sec%3600)/60), s = sec%60;\n"
           "    document.getElementById('st-uptime').innerText = `${h}h ${m}m ${s}s`;\n"
           "    document.getElementById('st-requests').innerText = d.total_requests;\n"
           "    document.getElementById('st-bytes').innerText = d.total_bytes_str;\n"
           "  }).catch(()=>{});\n"
           "}\n"
           "\n"
           "function loadApps() {\n"
           "  fetch('/api/apps').then(r=>r.json()).then(apps=>{\n"
           "    const sel = document.getElementById('currentApp');\n"
           "    const cur = sel.value;\n"
           "    sel.innerHTML = '<option value=\"\">Root Repository</option>' + apps.map(a => `<option value=\"${a}\">${a}</option>`).join('');\n"
           "    if (apps.includes(cur)) sel.value = cur;\n"
           "    onAppChange();\n"
           "  }).catch(()=>{});\n"
           "}\n"
           "\n"
           "function promptNewApp() {\n"
           "  const name = prompt('Enter new application / folder name (e.g. Accounting, CRM):');\n"
           "  if (!name || !name.trim()) return;\n"
           "  fetch('/api/create_app?name=' + encodeURIComponent(name.trim()), { method: 'POST' })\n"
           "  .then(r=>r.json()).then(res=>{\n"
           "    alert(res.message || 'Folder created successfully.');\n"
           "    loadApps();\n"
           "  }).catch(e=>alert('Error: ' + e));\n"
           "}\n"
           "\n"
           "function onAppChange() {\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  document.getElementById('appName').value = app || 'MyApplication';\n"
           "  loadFiles();\n"
           "  loadEditorFile();\n"
           "  updateCSharpCode();\n"
           "}\n"
           "\n"
           "function loadFiles() {\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  fetch('/api/files?app=' + encodeURIComponent(app)).then(r=>r.json()).then(files=>{\n"
           "    const ov = document.getElementById('uploadTargetOverride');\n"
           "    if(ov) ov.innerHTML = '<option value=\"\">-- Upload as New File --</option>' + files.map(f=>`<option value=\"${f.name}\">Replace: ${f.name}</option>`).join('');\n"
           "    const tbody = document.querySelector('#filesTable tbody');\n"
           "    if (!files || files.length === 0) {\n"
           "      tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align:center;\">No files found in this folder.</td></tr>';\n"
           "      return;\n"
           "    }\n"
           "    tbody.innerHTML = files.map(f => {\n"
           "      const isText = f.name.endsWith('.xml')||f.name.endsWith('.json')||f.name.endsWith('.html');\n"
           "      return `<tr>\n"
           "        <td><strong>${f.name}</strong></td>\n"
           "        <td><code>${f.app ? f.app : 'Root'}</code></td>\n"
           "        <td>${f.size_str}</td>\n"
           "        <td><code title=\"${f.sha256}\">${f.sha256.substring(0,16)}...</code> <button class=\"btn-secondary\" onclick=\"useHash('${f.name}','${f.sha256}')\">Select</button></td>\n"
           "        <td><a href=\"${f.url}\" target=\"_blank\" style=\"color:var(--accent);\">Download</a></td>\n"
           "        <td>\n"
           "          <button class=\"btn-secondary\" onclick=\"promptReplaceFile('${f.app}','${f.name}')\" style=\"background:#d97706;\">🔁 Replace</button>\n"
           "          ${isText ? `<button class=\"btn-secondary\" onclick=\"openInEditor('${f.app}','${f.name}')\">✏️ Edit</button>` : ''}\n"
           "          <button class=\"btn-danger\" onclick=\"deleteFile('${f.app}','${f.name}')\">Delete</button>\n"
           "        </td>\n"
           "      </tr>`;\n"
           "    }).join('');\n"
           "  }).catch(()=>{});\n"
           "}\n"
           "\n"
           "function useHash(name, hash) {\n"
           "  document.getElementById('fileUrl').value = name;\n"
           "  document.getElementById('hashVal').value = hash;\n"
           "}\n"
           "\n"
           "function uploadSelectedFile() {\n"
           "  const fi = document.getElementById('uploadFile');\n"
           "  if (!fi.files || !fi.files[0]) { alert('Please select a file first.'); return; }\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  const f = fi.files[0];\n"
           "  const ov = document.getElementById('uploadTargetOverride').value;\n"
           "  const name = ov ? ov : f.name;\n"
           "  const url = '/api/upload?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name);\n"
           "  fetch(url, { method: 'POST', body: f }).then(r=>r.json()).then(res=>{\n"
           "    alert('Upload/Replace successful: ' + res.filename);\n"
           "    useHash(res.filename, res.sha256);\n"
           "    loadFiles();\n"
           "    fi.value = '';\n"
           "    if (confirm('Update AutoUpdater.xml with this checksum?')) autoUpdateXmlChecksum(app, res.sha256);\n"
           "  }).catch(e=>alert('Upload error: ' + e));\n"
           "}\n"
           "\n"
           "function generateConfig(e) {\n"
           "  e.preventDefault();\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  const body = new URLSearchParams({\n"
           "    app_name: app || document.getElementById('appName').value,\n"
           "    version: document.getElementById('appVer').value,\n"
           "    file_url: document.getElementById('fileUrl').value,\n"
           "    hash_algo: document.getElementById('hashAlgo').value,\n"
           "    hash_val: document.getElementById('hashVal').value,\n"
           "    mandatory: document.getElementById('mandatory').value,\n"
           "    changelog: document.getElementById('changelog').value\n"
           "  }).toString();\n"
           "  fetch('/api/generate_config', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:body })\n"
           "  .then(r=>r.json()).then(res=>{\n"
           "    alert(res.message || 'Configurations saved successfully.');\n"
           "    loadFiles();\n"
           "    loadEditorFile();\n"
           "  }).catch(e=>alert('Error: ' + e));\n"
           "}\n"
           "\n"
           "function deleteFile(app, name) {\n"
           "  if (!confirm('Delete file ' + name + '?')) return;\n"
           "  fetch('/api/delete?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name), { method: 'POST' })\n"
           "  .then(r=>r.json()).then(()=>loadFiles()).catch(e=>alert(e));\n"
           "}\n"
           "\n"
           "function updateCSharpCode() {\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  const host = window.location.host || 'your-linux-server:8080';\n"
           "  const xmlPath = app ? `http://${host}/${app}/AutoUpdater.xml` : `http://${host}/AutoUpdater.xml`;\n"
           "  const jsonPath = app ? `http://${host}/${app}/AutoUpdater.json` : `http://${host}/AutoUpdater.json`;\n"
           "  document.getElementById('csharpCode').innerText =\n"
           "`// AutoUpdater.NET client code for \"${app || 'Root'}\":\\nusing AutoUpdaterDotNET;\\n\\nAutoUpdater.Start(\"${xmlPath}\");\\n\\n// Or JSON format:\\n// AutoUpdater.Start(\"${jsonPath}\");`;\n"
           "}\n"
           "\n"
           "loadApps();\n"
           "updateStats();\n"
           "setInterval(updateStats, 3000);\n"
           "</script>\n"
           "</body>\n"
           "</html>\n";
}

int admin_handle_request(socket_t sock, const http_request_t *req, server_ctx_t *ctx) {
    /* 1. Serve Web Admin Dashboard */
    if (strcmp(req->path, "/admin") == 0 || strcmp(req->path, "/admin/") == 0) {
        /* Check if external index.html exists in webroot */
        char custom_path[1024];
        snprintf(custom_path, sizeof(custom_path), "%s/admin/index.html", ctx->webroot_dir);
        size_t sz = 0;
        char *custom_html = read_entire_file(custom_path, &sz);
        if (custom_html) {
            http_send_response(sock, 200, "OK", "text/html; charset=utf-8", NULL, custom_html, sz);
            free(custom_html);
            return 0;
        }

        /* Use embedded fallback */
        const char *embedded = admin_get_embedded_html();
        return http_send_response(sock, 200, "OK", "text/html; charset=utf-8", NULL, embedded, strlen(embedded));
    }

    /* 1a. API: Login (SQLite-backed with salted SHA-256) */
    if (strcmp(req->path, "/api/login") == 0 && req->method == HTTP_METHOD_POST) {
        char username[128] = {0};
        char password[128] = {0};
        get_body_param(req->body, "username", username, sizeof(username));
        get_body_param(req->body, "password", password, sizeof(password));

        if (strlen(username) == 0 && strlen(req->query) > 0) {
            get_query_param(req->query, "username", username, sizeof(username));
            get_query_param(req->query, "password", password, sizeof(password));
        }

        if (strlen(username) == 0 || strlen(password) == 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Username and password are required.\"}\n");
        }

        char role[32] = "user";
        int auth_ok = 0;

        if (db_user_auth(username, password, role, sizeof(role)) != 0) {
            auth_ok = 1;
        } else if (strlen(ctx->admin_pass) > 0 && strcmp(username, ctx->admin_user) == 0 && strcmp(password, ctx->admin_pass) == 0) {
            /* Auto-seed default admin into SQLite if needed */
            strncpy(role, "admin", sizeof(role) - 1);
            db_user_create(username, password, "admin");
            auth_ok = 1;
        }

        if (!auth_ok) {
            log_msg("WARN", "Failed login attempt for user '%s'", username);
            return http_send_json(sock, 401, "{\"success\": false, \"message\": \"Invalid username or password.\"}\n");
        }

        char token[128] = {0};
        if (db_session_create(username, role, token, sizeof(token)) != 0) {
            return http_send_error(sock, 500, "Failed to create session token");
        }

        char cookie_hdr[256];
        snprintf(cookie_hdr, sizeof(cookie_hdr), "Set-Cookie: auth_token=%s; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax\r\n", token);

        char resp[512];
        snprintf(resp, sizeof(resp), "{\"success\": true, \"token\": \"%s\", \"username\": \"%s\", \"role\": \"%s\"}\n", token, username, role);

        log_msg("INFO", "User logged in: %s (role: %s)", username, role);
        return http_send_response(sock, 200, "OK", "application/json; charset=utf-8", cookie_hdr, resp, strlen(resp));
    }

    /* 1b. API: Logout */
    if (strcmp(req->path, "/api/logout") == 0 && req->method == HTTP_METHOD_POST) {
        char cookie_token[128] = {0};
        if (http_get_cookie(req, "auth_token", cookie_token, sizeof(cookie_token)) == 0) {
            db_session_delete(cookie_token);
        }
        const char *clear_cookie = "Set-Cookie: auth_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax\r\n";
        return http_send_response(sock, 200, "OK", "application/json; charset=utf-8", clear_cookie, "{\"success\": true, \"message\": \"Logged out successfully.\"}\n", 48);
    }

    /* 1c. API: Current Session Status (Who am I) */
    if (strcmp(req->path, "/api/me") == 0 && req->method == HTTP_METHOD_GET) {
        char username[64] = {0};
        char role[32] = {0};
        if (admin_get_current_user(req, ctx, username, sizeof(username), role, sizeof(role))) {
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"logged_in\": true, \"username\": \"%s\", \"role\": \"%s\"}\n", username, role);
            return http_send_json(sock, 200, resp);
        }
        return http_send_json(sock, 200, "{\"logged_in\": false}\n");
    }

    /* 1d. API: List Users (SQLite) */
    if (strcmp(req->path, "/api/users") == 0 && req->method == HTTP_METHOD_GET) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }
        char user_json[16384];
        if (db_user_list_json(user_json, sizeof(user_json)) != 0) {
            return http_send_error(sock, 500, "Failed to load user list");
        }
        return http_send_json(sock, 200, user_json);
    }

    /* 1e. API: Create User */
    if (strcmp(req->path, "/api/users/create") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char username[128] = {0};
        char password[128] = {0};
        char role[32] = "user";
        get_body_param(req->body, "username", username, sizeof(username));
        get_body_param(req->body, "password", password, sizeof(password));
        get_body_param(req->body, "role", role, sizeof(role));

        if (strlen(username) < 3 || !sanitize_name(username)) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Username must be at least 3 alphanumeric characters.\"}\n");
        }
        if (strlen(password) < 4) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Password must be at least 4 characters.\"}\n");
        }
        if (strlen(role) == 0) strncpy(role, "user", sizeof(role) - 1);

        if (db_user_create(username, password, role) != 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"User already exists or failed to create user.\"}\n");
        }

        log_msg("INFO", "New user created: %s (role: %s)", username, role);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"User created successfully.\"}\n");
    }

    /* 1f. API: Delete User */
    if (strcmp(req->path, "/api/users/delete") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char username[128] = {0};
        get_body_param(req->body, "username", username, sizeof(username));
        if (strlen(username) == 0 && strlen(req->query) > 0) {
            get_query_param(req->query, "username", username, sizeof(username));
        }

        if (strlen(username) == 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Username is required.\"}\n");
        }

        char curr_user[64] = {0}, curr_role[32] = {0};
        admin_get_current_user(req, ctx, curr_user, sizeof(curr_user), curr_role, sizeof(curr_role));
        if (strcmp(curr_user, username) == 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"You cannot delete your own account.\"}\n");
        }

        if (db_user_delete(username) != 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Failed to delete user or user not found.\"}\n");
        }

        log_msg("INFO", "User deleted: %s", username);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"User deleted successfully.\"}\n");
    }

    /* 1g. API: Change Password */
    if (strcmp(req->path, "/api/users/change_password") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char username[128] = {0};
        char new_password[128] = {0};
        get_body_param(req->body, "username", username, sizeof(username));
        get_body_param(req->body, "password", new_password, sizeof(new_password));

        if (strlen(username) == 0 || strlen(new_password) < 4) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Valid username and new password (min 4 chars) required.\"}\n");
        }

        if (db_user_change_password(username, new_password) != 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Failed to update password for user.\"}\n");
        }

        log_msg("INFO", "Password updated for user: %s", username);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"Password updated successfully.\"}\n");
    }

    /* 1h. API: Get Settings */
    if (strcmp(req->path, "/api/settings") == 0 && req->method == HTTP_METHOD_GET) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char esc_path[2048];
        json_escape(ctx->updates_dir, esc_path, sizeof(esc_path));

        char resp[2560];
        snprintf(resp, sizeof(resp), "{\"port\": %d, \"storage_path\": \"%s\", \"updates_dir\": \"%s\", \"version\": \"2.0.0\"}\n",
                 ctx->port, esc_path, esc_path);
        return http_send_json(sock, 200, resp);
    }

    /* 1i. API: Change Server Port */
    if (strcmp(req->path, "/api/settings/port") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char port_str[32] = {0};
        get_body_param(req->body, "port", port_str, sizeof(port_str));
        if (strlen(port_str) == 0 && strlen(req->query) > 0) {
            get_query_param(req->query, "port", port_str, sizeof(port_str));
        }

        int new_port = atoi(port_str);
        if (new_port <= 0 || new_port > 65535) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Invalid port number (1-65535).\"}\n");
        }

        if (new_port == ctx->port) {
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"success\": true, \"port\": %d, \"message\": \"Port is already set to %d.\"}\n", new_port, new_port);
            return http_send_json(sock, 200, resp);
        }

        /* Save to SQLite */
        db_config_set_int("port", new_port);

        /* Send response BEFORE port switch so the browser receives HTTP 200 */
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"success\": true, \"port\": %d, \"message\": \"Port changed. Server re-binding to new port.\"}\n", new_port);
        http_send_json(sock, 200, resp);

        /* Re-bind server socket */
        log_msg("INFO", "Port change requested via UI: Re-binding server to port %d...", new_port);
        server_change_port(ctx, new_port);
        return 0;
    }

    /* 1j. API: Change Storage Path (Supports /api/settings/storage and /api/settings/storage_path) */
    if ((strcmp(req->path, "/api/settings/storage") == 0 || strcmp(req->path, "/api/settings/storage_path") == 0) && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char new_path[1024] = {0};
        get_body_param(req->body, "storage_path", new_path, sizeof(new_path));
        if (strlen(new_path) == 0) {
            get_body_param(req->body, "updates_dir", new_path, sizeof(new_path));
        }
        if (strlen(new_path) == 0) {
            get_body_param(req->body, "path", new_path, sizeof(new_path));
        }
        if (strlen(new_path) == 0 && strlen(req->query) > 0) {
            get_query_param(req->query, "storage_path", new_path, sizeof(new_path));
            if (strlen(new_path) == 0) {
                get_query_param(req->query, "updates_dir", new_path, sizeof(new_path));
            }
        }

        if (strlen(new_path) == 0) {
            return http_send_json(sock, 400, "{\"success\": false, \"message\": \"Storage path cannot be empty.\"}\n");
        }

        /* Save to SQLite */
        db_config_set("updates_dir", new_path);

        /* Apply to server */
        server_set_storage_path(ctx, new_path);

        log_msg("INFO", "Updates storage directory changed to: %s", ctx->updates_dir);
        char esc_path[2048];
        json_escape(ctx->updates_dir, esc_path, sizeof(esc_path));

        char resp[2560];
        snprintf(resp, sizeof(resp), "{\"success\": true, \"storage_path\": \"%s\", \"message\": \"Storage path updated successfully.\"}\n", esc_path);
        return http_send_json(sock, 200, resp);
    }

    /* 2. API: Server Statistics */
    if (strcmp(req->path, "/api/stats") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }
        uint64_t now = (uint64_t)time(NULL);
        uint64_t uptime = (now >= ctx->start_time) ? (now - ctx->start_time) : 0;
        char bytes_str[32];
        format_bytes(ctx->total_bytes_sent, bytes_str, sizeof(bytes_str));

        char json[512];
        snprintf(json, sizeof(json),
            "{\"uptime_sec\": %llu, \"total_requests\": %llu, \"total_bytes\": %llu, "
            "\"total_bytes_str\": \"%s\", \"active_connections\": %d, \"port\": %d, \"version\": \"2.0.0\"}\n",
            (unsigned long long)uptime,
            (unsigned long long)ctx->total_requests,
            (unsigned long long)ctx->total_bytes_sent,
            bytes_str,
            ctx->active_connections,
            ctx->port
        );
        return http_send_json(sock, 200, json);
    }

    /* 3. API: List Application Folders */
    if (strcmp(req->path, "/api/apps") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }
        DIR *d = opendir(ctx->updates_dir);
        if (!d) {
            return http_send_json(sock, 200, "[]\n");
        }

        char *resp = malloc(65536);
        if (!resp) { closedir(d); return http_send_error(sock, 500, "Out of memory"); }
        strcpy(resp, "[\n");
        int first = 1;

        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0 || dir->d_name[0] == '.') continue;

            char subpath[1024];
            snprintf(subpath, sizeof(subpath), "%s/%s", ctx->updates_dir, dir->d_name);

            struct stat st;
            if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
                char item[512];
                snprintf(item, sizeof(item), "%s  \"%s\"", first ? "" : ",\n", dir->d_name);
                strcat(resp, item);
                first = 0;
            }
        }
        closedir(d);
        strcat(resp, "\n]\n");

        int ret = http_send_json(sock, 200, resp);
        free(resp);
        return ret;
    }

    /* 4. API: Create New Application Folder */
    if (strcmp(req->path, "/api/create_app") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) { send_auth_required(sock); return 0; }

        char app_name[128] = {0};
        get_query_param(req->query, "name", app_name, sizeof(app_name));
        if (strlen(app_name) == 0) {
            get_form_param(req->body, "name", app_name, sizeof(app_name));
        }

        if (!sanitize_name(app_name)) {
            return http_send_error(sock, 400, "Invalid application folder name");
        }

        char app_dir[1024];
        snprintf(app_dir, sizeof(app_dir), "%s/%s", ctx->updates_dir, app_name);
        MKDIR(app_dir);

        log_msg("INFO", "Created application folder: %s", app_name);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"Application folder created successfully.\"}\n");
    }

    /* 5. API: Delete Application Folder */
    if (strcmp(req->path, "/api/delete_app") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) { send_auth_required(sock); return 0; }

        char app_name[128] = {0};
        get_query_param(req->query, "name", app_name, sizeof(app_name));
        if (strlen(app_name) == 0) {
            get_query_param(req->query, "app", app_name, sizeof(app_name));
        }
        if (strlen(app_name) == 0 && req->body) {
            get_body_param(req->body, "name", app_name, sizeof(app_name));
            if (strlen(app_name) == 0) {
                get_body_param(req->body, "app", app_name, sizeof(app_name));
            }
        }
        if (strlen(app_name) == 0 || !sanitize_name(app_name)) {
            return http_send_error(sock, 400, "Invalid application folder name");
        }

        char app_dir[1024];
        snprintf(app_dir, sizeof(app_dir), "%s/%s", ctx->updates_dir, app_name);

        int del_rc = delete_directory_recursive(app_dir);
        struct stat check_st;
        if (del_rc != 0 || stat(app_dir, &check_st) == 0) {
            log_msg("ERROR", "Failed to delete application folder from disk: %s", app_dir);
            return http_send_json(sock, 500, "{\"success\": false, \"message\": \"Failed to delete application folder from disk. Access denied or files locked.\"}\n");
        }

        log_msg("INFO", "Deleted entire application package from disk: %s", app_name);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"Entire application package deleted successfully from disk.\"}\n");
    }


    /* 6. API: List Files in Updates Repository (Supports Filtering by App Folder) */
    if (strcmp(req->path, "/api/files") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }
        char app_filter[128] = {0};
        get_query_param(req->query, "app", app_filter, sizeof(app_filter));

        char scan_dir[1024];
        if (strlen(app_filter) > 0 && sanitize_name(app_filter)) {
            snprintf(scan_dir, sizeof(scan_dir), "%s/%s", ctx->updates_dir, app_filter);
        } else {
            strncpy(scan_dir, ctx->updates_dir, sizeof(scan_dir) - 1);
        }

        DIR *d = opendir(scan_dir);
        if (!d) {
            return http_send_json(sock, 200, "[]\n");
        }

        char *resp = malloc(131072);
        if (!resp) { closedir(d); return http_send_error(sock, 500, "Out of memory"); }
        strcpy(resp, "[\n");
        int first = 1;

        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
            if (dir->d_name[0] == '.') continue;

            char fpath[1024];
            snprintf(fpath, sizeof(fpath), "%s/%s", scan_dir, dir->d_name);

            struct stat st;
            if (stat(fpath, &st) != 0 || S_ISDIR(st.st_mode)) continue;

            char sha256_hex[65] = {0};
            char md5_hex[33] = {0};
            sha256_file(fpath, sha256_hex);
            md5_file(fpath, md5_hex);

            char sz_str[32];
            format_bytes((uint64_t)st.st_size, sz_str, sizeof(sz_str));

            char url_path[512];
            if (strlen(app_filter) > 0) {
                snprintf(url_path, sizeof(url_path), "/%s/%s", app_filter, dir->d_name);
            } else {
                snprintf(url_path, sizeof(url_path), "/%s", dir->d_name);
            }

            char item[2048];
            snprintf(item, sizeof(item),
                "%s  {\"name\": \"%s\", \"app\": \"%s\", \"url\": \"%s\", \"size\": %llu, \"size_str\": \"%s\", \"sha256\": \"%s\", \"md5\": \"%s\", \"mtime\": %ld}\n",
                first ? "" : ",\n",
                dir->d_name,
                app_filter,
                url_path,
                (unsigned long long)st.st_size,
                sz_str,
                sha256_hex,
                md5_hex,
                (long)st.st_mtime
            );

            strcat(resp, item);
            first = 0;
        }
        closedir(d);
        strcat(resp, "]\n");

        int ret = http_send_json(sock, 200, resp);
        free(resp);
        return ret;
    }

    /* 7. API: Generate AutoUpdater.xml and AutoUpdater.json for Specific App */
    if (strcmp(req->path, "/api/generate_config") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char version[64] = {0};
        char file_url[256] = {0};
        char hash_algo[32] = "SHA256";
        char hash_val[128] = {0};
        char mandatory[16] = "false";
        char changelog[1024] = {0};

        get_form_param(req->body, "app_name", app_name, sizeof(app_name));
        get_form_param(req->body, "version", version, sizeof(version));
        get_form_param(req->body, "file_url", file_url, sizeof(file_url));
        get_form_param(req->body, "hash_algo", hash_algo, sizeof(hash_algo));
        get_form_param(req->body, "hash_val", hash_val, sizeof(hash_val));
        get_form_param(req->body, "mandatory", mandatory, sizeof(mandatory));
        get_form_param(req->body, "changelog", changelog, sizeof(changelog));

        if (strlen(version) == 0 || strlen(file_url) == 0) {
            return http_send_error(sock, 400, "Missing required parameters (version, file_url)");
        }

        char target_dir[1024];
        char url_prefix[256] = "";
        if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            snprintf(target_dir, sizeof(target_dir), "%s/%s", ctx->updates_dir, app_name);
            MKDIR(target_dir);
            snprintf(url_prefix, sizeof(url_prefix), "/%s", app_name);
        } else {
            strncpy(target_dir, ctx->updates_dir, sizeof(target_dir) - 1);
        }

        char download_url[512];
        if (strstr(file_url, "://") == NULL) {
            if (file_url[0] == '/') {
                strncpy(download_url, file_url, sizeof(download_url) - 1);
            } else {
                snprintf(download_url, sizeof(download_url), "%s/%s", url_prefix, file_url);
            }
        } else {
            strncpy(download_url, file_url, sizeof(download_url) - 1);
        }

        char changelog_url[256];
        snprintf(changelog_url, sizeof(changelog_url), "%s/changelog.html", url_prefix);

        /* 1) changelog.html */
        char changelog_path[1024];
        snprintf(changelog_path, sizeof(changelog_path), "%s/changelog.html", target_dir);
        FILE *fc = fopen(changelog_path, "w");
        if (fc) {
            fprintf(fc, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Release Notes v%s</title>"
                        "<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:24px;line-height:1.6;background:#0b0f19;color:#f1f5f9;}"
                        "h2{color:#38bdf8;border-bottom:1px solid #24324f;padding-bottom:8px;}"
                        "pre{background:#151d30;border:1px solid #24324f;padding:16px;border-radius:8px;font-family:Consolas,monospace;color:#38bdf8;overflow-x:auto;white-space:pre-wrap;}</style></head><body>"
                        "<h2>Release Notes v%s</h2><pre>%s</pre></body></html>\n",
                        version, version, changelog);
            fclose(fc);
        }

        /* 2) AutoUpdater.xml */
        char xml_path[1024];
        snprintf(xml_path, sizeof(xml_path), "%s/AutoUpdater.xml", target_dir);
        FILE *fx = fopen(xml_path, "w");
        if (fx) {
            fprintf(fx, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fprintf(fx, "<item>\n");
            fprintf(fx, "    <version>%s</version>\n", version);
            fprintf(fx, "    <url>%s</url>\n", download_url);
            fprintf(fx, "    <changelog>%s</changelog>\n", changelog_url);
            fprintf(fx, "    <mandatory>%s</mandatory>\n", (strcmp(mandatory, "true") == 0) ? "true" : "false");
            if (strlen(hash_val) > 0) {
                fprintf(fx, "    <checksum algorithm=\"%s\">%s</checksum>\n", hash_algo, hash_val);
            }
            fprintf(fx, "</item>\n");
            fclose(fx);
        }

        /* 3) AutoUpdater.json */
        char json_path[1024];
        snprintf(json_path, sizeof(json_path), "%s/AutoUpdater.json", target_dir);
        FILE *fj = fopen(json_path, "w");
        if (fj) {
            fprintf(fj, "{\n");
            fprintf(fj, "  \"version\": \"%s\",\n", version);
            fprintf(fj, "  \"url\": \"%s\",\n", download_url);
            fprintf(fj, "  \"changelog\": \"%s\",\n", changelog_url);
            fprintf(fj, "  \"mandatory\": {\n");
            fprintf(fj, "    \"mode\": %d\n", (strcmp(mandatory, "true") == 0) ? 1 : 0);
            fprintf(fj, "  }%s\n", (strlen(hash_val) > 0) ? "," : "");
            if (strlen(hash_val) > 0) {
                fprintf(fj, "  \"checksum\": {\n");
                fprintf(fj, "    \"value\": \"%s\",\n", hash_val);
                fprintf(fj, "    \"hashingAlgorithm\": \"%s\"\n", hash_algo);
                fprintf(fj, "  }\n");
            }
            fprintf(fj, "}\n");
            fclose(fj);
        }

        log_msg("INFO", "AutoUpdater config generated for app '%s' version %s", app_name, version);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"AutoUpdater.xml and AutoUpdater.json generated successfully.\"}\n");
    }

    /* 7a. API: Inspect Package and List All Executables (for operator selection) */
    if (strcmp(req->path, "/api/inspect_package") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));

        char inspect_zip_path[1024] = {0};
        char temp_inspect_dir[1024] = {0};
        int is_temp = 0;

        if (req->method == HTTP_METHOD_POST && req->body && req->body_len >= 22) {
            /* Inspect uploaded package directly */
            snprintf(temp_inspect_dir, sizeof(temp_inspect_dir), "%s/_inspect_%lu", ctx->updates_dir, (unsigned long)time(NULL));
            MKDIR(temp_inspect_dir);

            int is_exe = (req->body_len >= 64 && (unsigned char)req->body[0] == 'M' && (unsigned char)req->body[1] == 'Z');
            if (is_exe) {
                snprintf(inspect_zip_path, sizeof(inspect_zip_path), "%s/uploaded.exe", temp_inspect_dir);
            } else {
                snprintf(inspect_zip_path, sizeof(inspect_zip_path), "%s/uploaded.zip", temp_inspect_dir);
            }

            FILE *f = fopen(inspect_zip_path, "wb");
            if (!f) {
                return http_send_error(sock, 500, "Cannot write temporary inspection file");
            }
            fwrite(req->body, 1, req->body_len, f);
            fclose(f);
            is_temp = 1;
        } else if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            /* Inspect already uploaded app in updates dir */
            snprintf(inspect_zip_path, sizeof(inspect_zip_path), "%s/%s/%s.zip", ctx->updates_dir, app_name, app_name);
            struct stat st;
            if (stat(inspect_zip_path, &st) != 0) {
                snprintf(inspect_zip_path, sizeof(inspect_zip_path), "%s/%s/%s.exe", ctx->updates_dir, app_name, app_name);
                if (stat(inspect_zip_path, &st) != 0) {
                    return http_send_json(sock, 404, "{\"success\": false, \"message\": \"Package not found for application.\"}\n");
                }
            }
        } else {
            return http_send_error(sock, 400, "No package file uploaded or app parameter specified");
        }

        /* Check if inspect_zip_path is a raw EXE */
        int is_raw_exe = 0;
        FILE *chk = fopen(inspect_zip_path, "rb");
        if (chk) {
            unsigned char sig[2];
            if (fread(sig, 1, 2, chk) == 2 && sig[0] == 'M' && sig[1] == 'Z') {
                is_raw_exe = 1;
            }
            fclose(chk);
        }

        char *resp = malloc(65536);
        if (!resp) {
            if (is_temp && temp_inspect_dir[0]) {
                delete_directory_recursive(temp_inspect_dir);
            }
            return http_send_error(sock, 500, "Out of memory");
        }

        if (is_raw_exe) {
            pe_details_t pe;
            memset(&pe, 0, sizeof(pe));
            inspect_pe_executable(inspect_zip_path, &pe);

            const char *slash = strrchr(inspect_zip_path, '/');
            if (!slash) slash = strrchr(inspect_zip_path, '\\');
            const char *bname = slash ? slash + 1 : inspect_zip_path;

            char esc_exe[256], esc_arch[128], esc_runtime[128], esc_fver[128], esc_pver[128], esc_desc[256];
            json_escape(bname, esc_exe, sizeof(esc_exe));
            json_escape(pe.architecture, esc_arch, sizeof(esc_arch));
            json_escape(pe.runtime, esc_runtime, sizeof(esc_runtime));
            json_escape(pe.file_version, esc_fver, sizeof(esc_fver));
            json_escape(pe.product_version, esc_pver, sizeof(esc_pver));
            json_escape(pe.file_description, esc_desc, sizeof(esc_desc));

            snprintf(resp, 65536,
                "{\n"
                "  \"success\": true,\n"
                "  \"count\": 1,\n"
                "  \"recommended_exe\": \"%s\",\n"
                "  \"recommended_version\": \"%s\",\n"
                "  \"executables\": [\n"
                "    {\n"
                "      \"name\": \"%s\",\n"
                "      \"path\": \"%s\",\n"
                "      \"size\": %llu,\n"
                "      \"version\": \"%s\",\n"
                "      \"product_version\": \"%s\",\n"
                "      \"description\": \"%s\",\n"
                "      \"architecture\": \"%s\",\n"
                "      \"runtime\": \"%s\",\n"
                "      \"is_recommended\": true,\n"
                "      \"score\": 100\n"
                "    }\n"
                "  ]\n"
                "}\n",
                esc_exe, esc_fver,
                esc_exe, esc_exe, (unsigned long long)pe.file_size,
                esc_fver, esc_pver, esc_desc, esc_arch, esc_runtime);
        } else {
            /* ZIP archive: list all .exe entries */
            zip_exe_entry_t entries[32];
            int num_entries = zip_list_executable_entries(inspect_zip_path, app_name, entries, 32);

            char temp_work_dir[1024];
            snprintf(temp_work_dir, sizeof(temp_work_dir), "%s/_work_%lu", ctx->updates_dir, (unsigned long)time(NULL));
            MKDIR(temp_work_dir);

            int buf_offset = snprintf(resp, 65536,
                "{\n"
                "  \"success\": true,\n"
                "  \"count\": %d,\n",
                num_entries);

            char rec_exe[256] = "Not found";
            char rec_ver[64] = "1.0.0.0";

            int exe_items_offset = snprintf(resp + buf_offset, 65536 - buf_offset, "  \"executables\": [\n");
            buf_offset += exe_items_offset;

            for (int i = 0; i < num_entries; i++) {
                char temp_extracted_exe[1024];
                snprintf(temp_extracted_exe, sizeof(temp_extracted_exe), "%s/%s", temp_work_dir, entries[i].file_name);

                pe_details_t pe;
                memset(&pe, 0, sizeof(pe));

                if (zip_extract_entry(inspect_zip_path, entries[i].entry_path, temp_extracted_exe) == 0) {
                    inspect_pe_executable(temp_extracted_exe, &pe);
#ifdef _WIN32
                    SetFileAttributesA(temp_extracted_exe, FILE_ATTRIBUTE_NORMAL);
                    if (DeleteFileA(temp_extracted_exe) == 0) remove(temp_extracted_exe);
#else
                    chmod(temp_extracted_exe, 0777);
                    unlink(temp_extracted_exe);
                    remove(temp_extracted_exe);
#endif
                }

                if (i == 0) {
                    strncpy(rec_exe, entries[i].file_name, sizeof(rec_exe) - 1);
                    strncpy(rec_ver, (strlen(pe.file_version) > 0) ? pe.file_version : "1.0.0.0", sizeof(rec_ver) - 1);
                }

                char esc_name[256], esc_path[1024], esc_arch[128], esc_runtime[128], esc_fver[128], esc_pver[128], esc_desc[256];
                json_escape(entries[i].file_name, esc_name, sizeof(esc_name));
                json_escape(entries[i].entry_path, esc_path, sizeof(esc_path));
                json_escape(pe.architecture, esc_arch, sizeof(esc_arch));
                json_escape(pe.runtime, esc_runtime, sizeof(esc_runtime));
                json_escape((strlen(pe.file_version) > 0) ? pe.file_version : "1.0.0.0", esc_fver, sizeof(esc_fver));
                json_escape(pe.product_version, esc_pver, sizeof(esc_pver));
                json_escape(pe.file_description, esc_desc, sizeof(esc_desc));

                int item_len = snprintf(resp + buf_offset, 65536 - buf_offset,
                    "    {\n"
                    "      \"name\": \"%s\",\n"
                    "      \"path\": \"%s\",\n"
                    "      \"size\": %llu,\n"
                    "      \"version\": \"%s\",\n"
                    "      \"product_version\": \"%s\",\n"
                    "      \"description\": \"%s\",\n"
                    "      \"architecture\": \"%s\",\n"
                    "      \"runtime\": \"%s\",\n"
                    "      \"is_recommended\": %s,\n"
                    "      \"score\": %d\n"
                    "    }%s\n",
                    esc_name, esc_path, (unsigned long long)entries[i].uncompressed_size,
                    esc_fver, esc_pver, esc_desc, esc_arch, esc_runtime,
                    (i == 0) ? "true" : "false",
                    entries[i].score,
                    (i < num_entries - 1) ? "," : "");

                buf_offset += item_len;
            }

            delete_directory_recursive(temp_work_dir);

            char esc_rec_exe[256], esc_rec_ver[64];
            json_escape(rec_exe, esc_rec_exe, sizeof(esc_rec_exe));
            json_escape(rec_ver, esc_rec_ver, sizeof(esc_rec_ver));

            snprintf(resp + buf_offset, 65536 - buf_offset,
                "  ],\n"
                "  \"recommended_exe\": \"%s\",\n"
                "  \"recommended_version\": \"%s\"\n"
                "}\n",
                esc_rec_exe, esc_rec_ver);
        }

        if (is_temp && temp_inspect_dir[0]) {
            delete_directory_recursive(temp_inspect_dir);
        }

        int ret = http_send_json(sock, 200, resp);
        free(resp);
        return ret;
    }

    /* 7b. API: 1-Click Publish from Zip with Auto Version Extraction */
    if (strcmp(req->path, "/api/publish_zip") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char mandatory[16] = "false";
        char changelog[2048] = {0};
        char custom_version[64] = {0};
        char target_exe[256] = {0};

        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "mandatory", mandatory, sizeof(mandatory));
        get_query_param(req->query, "changelog", changelog, sizeof(changelog));
        get_query_param(req->query, "version", custom_version, sizeof(custom_version));
        get_query_param(req->query, "target_exe", target_exe, sizeof(target_exe));

        if (strlen(app_name) == 0 || !sanitize_name(app_name)) {
            return http_send_error(sock, 400, "Invalid application name (English alphanumeric, dashes/underscores only)");
        }

        if (!req->body || req->body_len < 22) {
            return http_send_error(sock, 400, "Empty or invalid package file uploaded");
        }

        char app_dir[1024];
        snprintf(app_dir, sizeof(app_dir), "%s/%s", ctx->updates_dir, app_name);
        MKDIR(app_dir);

        int is_raw_exe = (req->body_len >= 64 && (unsigned char)req->body[0] == 'M' && (unsigned char)req->body[1] == 'Z');

        char zip_filename[256];
        char zip_dest_path[1024];
        char detected_version[64] = {0};
        char detected_exe_name[256] = "Not found";
        pe_details_t pe_info;
        memset(&pe_info, 0, sizeof(pe_info));

        if (is_raw_exe) {
            /* Direct .EXE binary upload */
            snprintf(zip_filename, sizeof(zip_filename), "%s.exe", app_name);
            snprintf(zip_dest_path, sizeof(zip_dest_path), "%s/%s", app_dir, zip_filename);

            FILE *ef = fopen(zip_dest_path, "wb");
            if (!ef) {
                return http_send_error(sock, 500, "Cannot write executable binary to disk");
            }
            fwrite(req->body, 1, req->body_len, ef);
            fclose(ef);

            strncpy(detected_exe_name, zip_filename, sizeof(detected_exe_name) - 1);
            if (inspect_pe_executable(zip_dest_path, &pe_info) == 0) {
                strncpy(detected_version, pe_info.file_version, sizeof(detected_version) - 1);
                log_msg("INFO", "Direct EXE PE Analysis complete: %s", pe_info.summary);
            }
        } else {
            /* ZIP archive package upload */
            snprintf(zip_filename, sizeof(zip_filename), "%s.zip", app_name);
            snprintf(zip_dest_path, sizeof(zip_dest_path), "%s/%s", app_dir, zip_filename);

            FILE *zf = fopen(zip_dest_path, "wb");
            if (!zf) {
                return http_send_error(sock, 500, "Cannot write update zip file to disk");
            }
            fwrite(req->body, 1, req->body_len, zf);
            fclose(zf);

            /* Unpack into temporary directory to detect executable and version */
            char temp_unpack_dir[1024];
            snprintf(temp_unpack_dir, sizeof(temp_unpack_dir), "%s/_tmp_%lu", app_dir, (unsigned long)time(NULL));
            MKDIR(temp_unpack_dir);

            int extracted = 0;

            /* Check if operator chose a specific target_exe */
            if (strlen(target_exe) > 0) {
                char target_entry[1024] = {0};
                if (zip_find_executable_entry(zip_dest_path, target_exe, target_entry, sizeof(target_entry))) {
                    const char *slash = strrchr(target_entry, '/');
                    if (!slash) slash = strrchr(target_entry, '\\');
                    const char *bname = slash ? slash + 1 : target_entry;

                    char target_out[1024];
                    snprintf(target_out, sizeof(target_out), "%s/%s", temp_unpack_dir, bname);
                    if (zip_extract_entry(zip_dest_path, target_entry, target_out) == 0) {
                        strncpy(detected_exe_name, bname, sizeof(detected_exe_name) - 1);
                        if (inspect_pe_executable(target_out, &pe_info) == 0) {
                            strncpy(detected_version, pe_info.file_version, sizeof(detected_version) - 1);
                            log_msg("INFO", "Operator-selected executable '%s' extracted & analyzed: %s", bname, pe_info.summary);
                            extracted = 1;
                        }
                    }
                }
            }

            if (!extracted) {
                log_msg("INFO", "Unpacking package for application '%s' to inspect binary...", app_name);
                if (extract_zip_archive(zip_dest_path, temp_unpack_dir, app_name) == 0) {
                    char found_exe_path[1024] = {0};
                    if (find_target_executable(temp_unpack_dir, app_name, found_exe_path, sizeof(found_exe_path))) {
                        const char *s = strrchr(found_exe_path, '/');
                        if (!s) s = strrchr(found_exe_path, '\\');
                        if (s) strncpy(detected_exe_name, s + 1, sizeof(detected_exe_name) - 1);
                        else strncpy(detected_exe_name, found_exe_path, sizeof(detected_exe_name) - 1);

                        if (inspect_pe_executable(found_exe_path, &pe_info) == 0) {
                            strncpy(detected_version, pe_info.file_version, sizeof(detected_version) - 1);
                            log_msg("INFO", "PE Analysis complete: %s", pe_info.summary);
                        }
                    } else {
                        log_msg("WARN", "No suitable .exe binary found in package for '%s'", app_name);
                    }
                } else {
                    log_msg("WARN", "Zip extraction failed or timed out for '%s'", app_name);
                }
            }
            delete_directory_recursive(temp_unpack_dir);
        }

        /* Calculate SHA256 and MD5 of the package (either zip or exe) */
        char sha256_hex[65] = {0};
        char md5_hex[33] = {0};
        sha256_file(zip_dest_path, sha256_hex);
        md5_file(zip_dest_path, md5_hex);

        /* If no exe was analyzed, fill defaults */
        if (pe_info.exe_name[0] == '\0') {
            strncpy(pe_info.exe_name, detected_exe_name, sizeof(pe_info.exe_name) - 1);
            strncpy(pe_info.architecture, "Unknown", sizeof(pe_info.architecture) - 1);
            strncpy(pe_info.subsystem, "Unknown", sizeof(pe_info.subsystem) - 1);
            strncpy(pe_info.runtime, "Unknown", sizeof(pe_info.runtime) - 1);
            strncpy(pe_info.file_version, (strlen(detected_version) > 0) ? detected_version : "1.0.0.0", sizeof(pe_info.file_version) - 1);
            strncpy(pe_info.product_version, pe_info.file_version, sizeof(pe_info.product_version) - 1);
            strncpy(pe_info.file_description, "Application Package", sizeof(pe_info.file_description) - 1);
            strncpy(pe_info.company_name, "Standard Publisher", sizeof(pe_info.company_name) - 1);
            strncpy(pe_info.detection_method, "Archive Scan Fallback", sizeof(pe_info.detection_method) - 1);
            snprintf(pe_info.summary, sizeof(pe_info.summary), "%s -> v%s", pe_info.exe_name, pe_info.file_version);
        }

        /* Determine final version */
        char final_version[64] = "1.0.0.0";
        if (strlen(custom_version) > 0) {
            strncpy(final_version, custom_version, sizeof(final_version) - 1);
        } else if (strlen(detected_version) > 0) {
            strncpy(final_version, detected_version, sizeof(final_version) - 1);
        }

        /* Default changelog if empty */
        if (strlen(changelog) == 0) {
            strncpy(changelog, "- Performance improvements and bug fixes\n- Stability enhancements", sizeof(changelog) - 1);
        }

        /* 1) Write changelog.html */
        char changelog_path[1024];
        snprintf(changelog_path, sizeof(changelog_path), "%s/changelog.html", app_dir);
        FILE *fc = fopen(changelog_path, "w");
        if (fc) {
            fprintf(fc, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>%s Release v%s</title>"
                        "<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:24px;line-height:1.6;background:#0b0f19;color:#f1f5f9;}"
                        "h2{color:#38bdf8;border-bottom:1px solid #24324f;padding-bottom:8px;}"
                        "pre{background:#151d30;border:1px solid #24324f;padding:16px;border-radius:8px;font-family:Consolas,monospace;color:#38bdf8;white-space:pre-wrap;}</style></head><body>"
                        "<h2>%s - Release Notes v%s</h2><pre>%s</pre></body></html>\n",
                        app_name, final_version, app_name, final_version, changelog);
            fclose(fc);
        }

        /* Determine host for full persistent URLs */
        char host_buf[256];
        if (strlen(req->host_header) > 0) {
            strncpy(host_buf, req->host_header, sizeof(host_buf) - 1);
            host_buf[sizeof(host_buf) - 1] = '\0';
        } else {
            snprintf(host_buf, sizeof(host_buf), "localhost:%d", ctx->port);
        }

        char xml_url[512];
        snprintf(xml_url, sizeof(xml_url), "http://%s/%s/AutoUpdater.xml", host_buf, app_name);

        char zip_url[512];
        snprintf(zip_url, sizeof(zip_url), "http://%s/%s/%s", host_buf, app_name, zip_filename);

        char changelog_url[512];
        snprintf(changelog_url, sizeof(changelog_url), "http://%s/%s/changelog.html", host_buf, app_name);

        /* 2) Write AutoUpdater.xml (URL matches persistent zip_url) */
        char xml_path[1024];
        snprintf(xml_path, sizeof(xml_path), "%s/AutoUpdater.xml", app_dir);
        FILE *fx = fopen(xml_path, "w");
        if (fx) {
            fprintf(fx, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fprintf(fx, "<item>\n");
            fprintf(fx, "    <version>%s</version>\n", final_version);
            fprintf(fx, "    <url>%s</url>\n", zip_url);
            fprintf(fx, "    <changelog>%s</changelog>\n", changelog_url);
            fprintf(fx, "    <mandatory>%s</mandatory>\n", (strcmp(mandatory, "true") == 0) ? "true" : "false");
            if (strlen(detected_exe_name) > 0) {
                fprintf(fx, "    <executable>%s</executable>\n", detected_exe_name);
            }
            fprintf(fx, "    <checksum algorithm=\"SHA256\">%s</checksum>\n", sha256_hex);
            fprintf(fx, "</item>\n");
            fclose(fx);
        }

        /* 3) Write AutoUpdater.json */
        char json_path[1024];
        snprintf(json_path, sizeof(json_path), "%s/AutoUpdater.json", app_dir);
        FILE *fj = fopen(json_path, "w");
        if (fj) {
            fprintf(fj, "{\n");
            fprintf(fj, "  \"version\": \"%s\",\n", final_version);
            fprintf(fj, "  \"url\": \"%s\",\n", zip_url);
            fprintf(fj, "  \"changelog\": \"%s\",\n", changelog_url);
            if (strlen(detected_exe_name) > 0) {
                fprintf(fj, "  \"executable\": \"%s\",\n", detected_exe_name);
            }
            fprintf(fj, "  \"mandatory\": {\n");
            fprintf(fj, "    \"mode\": %d\n", (strcmp(mandatory, "true") == 0) ? 1 : 0);
            fprintf(fj, "  },\n");
            fprintf(fj, "  \"checksum\": {\n");
            fprintf(fj, "    \"value\": \"%s\",\n", sha256_hex);
            fprintf(fj, "    \"hashingAlgorithm\": \"SHA256\"\n");
            fprintf(fj, "  }\n");
            fprintf(fj, "}\n");
            fclose(fj);
        }

        log_msg("INFO", "Published 1-click update for app '%s' version %s (exe: %s, sha256: %s)",
                app_name, final_version, detected_exe_name, sha256_hex);

        /* JSON-escaped strings for safe output */
        char esc_exe[256], esc_arch[128], esc_subsys[128], esc_runtime[128];
        char esc_fver[128], esc_pver[128], esc_desc[256], esc_comp[256], esc_method[256], esc_sum[512];

        json_escape(pe_info.exe_name, esc_exe, sizeof(esc_exe));
        json_escape(pe_info.architecture, esc_arch, sizeof(esc_arch));
        json_escape(pe_info.subsystem, esc_subsys, sizeof(esc_subsys));
        json_escape(pe_info.runtime, esc_runtime, sizeof(esc_runtime));
        json_escape(pe_info.file_version, esc_fver, sizeof(esc_fver));
        json_escape(pe_info.product_version, esc_pver, sizeof(esc_pver));
        json_escape(pe_info.file_description, esc_desc, sizeof(esc_desc));
        json_escape(pe_info.company_name, esc_comp, sizeof(esc_comp));
        json_escape(pe_info.detection_method, esc_method, sizeof(esc_method));
        json_escape(pe_info.summary, esc_sum, sizeof(esc_sum));

        char resp[4096];
        snprintf(resp, sizeof(resp),
            "{\n"
            "  \"success\": true,\n"
            "  \"app\": \"%s\",\n"
            "  \"version\": \"%s\",\n"
            "  \"exe_name\": \"%s\",\n"
            "  \"zip_file\": \"%s\",\n"
            "  \"size\": %zu,\n"
            "  \"sha256\": \"%s\",\n"
            "  \"md5\": \"%s\",\n"
            "  \"xml_url\": \"%s\",\n"
            "  \"zip_url\": \"%s\",\n"
            "  \"csharp_code\": \"AutoUpdater.Start(\\\"%s\\\");\",\n"
            "  \"pe_info\": {\n"
            "    \"exe_name\": \"%s\",\n"
            "    \"exe_size\": %llu,\n"
            "    \"architecture\": \"%s\",\n"
            "    \"subsystem\": \"%s\",\n"
            "    \"runtime\": \"%s\",\n"
            "    \"file_version\": \"%s\",\n"
            "    \"product_version\": \"%s\",\n"
            "    \"file_description\": \"%s\",\n"
            "    \"company_name\": \"%s\",\n"
            "    \"detection_method\": \"%s\",\n"
            "    \"summary\": \"%s\"\n"
            "  }\n"
            "}\n",
            app_name, final_version, detected_exe_name, zip_filename, req->body_len,
            sha256_hex, md5_hex, xml_url, zip_url, xml_url,
            esc_exe, (unsigned long long)pe_info.file_size,
            esc_arch, esc_subsys, esc_runtime,
            esc_fver, esc_pver,
            esc_desc, esc_comp,
            esc_method, esc_sum);

        return http_send_json(sock, 200, resp);
    }

    /* 8. API: File Upload into App Folder */
    if (strcmp(req->path, "/api/upload") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[256] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0) {
            snprintf(filename, sizeof(filename), "update_%ld.bin", (long)time(NULL));
        }

        if (!sanitize_name(filename)) {
            return http_send_error(sock, 400, "Invalid filename");
        }

        char dest_dir[1024];
        if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            snprintf(dest_dir, sizeof(dest_dir), "%s/%s", ctx->updates_dir, app_name);
            MKDIR(dest_dir);
        } else {
            strncpy(dest_dir, ctx->updates_dir, sizeof(dest_dir) - 1);
        }

        char dest_path[1024];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir, filename);
        int already_existed = (access(dest_path, 0) == 0);

        FILE *f = fopen(dest_path, "wb");
        if (!f) {
            return http_send_error(sock, 500, "Cannot write file to disk");
        }

        if (req->body && req->body_len > 0) {
            fwrite(req->body, 1, req->body_len, f);
        }
        fclose(f);

        char sha256_hex[65] = {0};
        char md5_hex[33] = {0};
        sha256_file(dest_path, sha256_hex);
        md5_file(dest_path, md5_hex);

        log_msg("INFO", "File %s [%s]: %s (%zu bytes) SHA256: %s",
                already_existed ? "replaced" : "uploaded",
                strlen(app_name) > 0 ? app_name : "Root", filename, req->body_len, sha256_hex);

        char resp[512];
        snprintf(resp, sizeof(resp), "{\"success\": true, \"replaced\": %s, \"app\": \"%s\", \"filename\": \"%s\", \"size\": %zu, \"sha256\": \"%s\", \"md5\": \"%s\"}\n",
                 already_existed ? "true" : "false",
                 app_name, filename, req->body_len, sha256_hex, md5_hex);
        return http_send_json(sock, 200, resp);
    }

    /* 9. API: Delete File from App Folder */
    if (strcmp(req->path, "/api/delete") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[256] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0 && req->body) {
            get_body_param(req->body, "name", filename, sizeof(filename));
            if (strlen(app_name) == 0) {
                get_body_param(req->body, "app", app_name, sizeof(app_name));
            }
        }

        if (strlen(filename) == 0) {
            /* If no filename specified, check if full app folder was requested */
            if (strlen(app_name) > 0 && sanitize_name(app_name)) {
                char app_dir[1024];
                snprintf(app_dir, sizeof(app_dir), "%s/%s", ctx->updates_dir, app_name);
                int del_rc = delete_directory_recursive(app_dir);
                struct stat check_st;
                if (del_rc != 0 || stat(app_dir, &check_st) == 0) {
                    log_msg("ERROR", "Failed to delete application folder from disk: %s", app_dir);
                    return http_send_json(sock, 500, "{\"success\": false, \"message\": \"Failed to delete application folder from disk.\"}\n");
                }
                log_msg("INFO", "Deleted application folder from disk: %s", app_name);
                return http_send_json(sock, 200, "{\"success\": true, \"message\": \"Application folder deleted successfully.\"}\n");
            }
            return http_send_error(sock, 400, "Filename or application name is required");
        }

        if (!sanitize_name(filename)) {
            return http_send_error(sock, 400, "Invalid filename");
        }

        char target_path[1024];
        if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            snprintf(target_path, sizeof(target_path), "%s/%s/%s", ctx->updates_dir, app_name, filename);
        } else {
            snprintf(target_path, sizeof(target_path), "%s/%s", ctx->updates_dir, filename);
        }

        struct stat st;
        if (stat(target_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                delete_directory_recursive(target_path);
            } else {
#ifdef _WIN32
                SetFileAttributesA(target_path, FILE_ATTRIBUTE_NORMAL);
                if (DeleteFileA(target_path) == 0) {
                    remove(target_path);
                }
#else
                chmod(target_path, 0777);
                unlink(target_path);
                remove(target_path);
#endif
            }
        } else {
#ifdef _WIN32
            SetFileAttributesA(target_path, FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileA(target_path) == 0) {
                remove(target_path);
            }
#else
            unlink(target_path);
            remove(target_path);
#endif
        }

        struct stat check_st;
        if (stat(target_path, &check_st) == 0) {
            log_msg("ERROR", "Failed to delete file/folder from disk: %s", target_path);
            return http_send_json(sock, 500, "{\"success\": false, \"message\": \"Failed to delete file from disk. Access denied or file locked.\"}\n");
        }

        log_msg("INFO", "File deleted from disk: %s", target_path);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"File deleted successfully.\"}\n");
    }

    /* 10. API: Get File Content (for in-browser XML/JSON/HTML editing) */
    if (strcmp(req->path, "/api/get_file_content") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[128] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0) {
            strncpy(filename, "AutoUpdater.xml", sizeof(filename) - 1);
        }

        if (!sanitize_name(filename) || (strlen(app_name) > 0 && !sanitize_name(app_name))) {
            return http_send_error(sock, 400, "Invalid file or application name");
        }

        char fpath[1024];
        if (strlen(app_name) > 0) {
            snprintf(fpath, sizeof(fpath), "%s/%s/%s", ctx->updates_dir, app_name, filename);
        } else {
            snprintf(fpath, sizeof(fpath), "%s/%s", ctx->updates_dir, filename);
        }

        size_t file_sz = 0;
        char *content = read_entire_file(fpath, &file_sz);
        if (!content) {
            return http_send_error(sock, 404, "File not found");
        }

        const char *content_type = "text/plain; charset=utf-8";
        if (strstr(filename, ".xml")) content_type = "application/xml; charset=utf-8";
        else if (strstr(filename, ".json")) content_type = "application/json; charset=utf-8";
        else if (strstr(filename, ".html")) content_type = "text/html; charset=utf-8";

        http_send_response(sock, 200, "OK", content_type, NULL, content, file_sz);
        free(content);
        return 0;
    }

    /* 11. API: Save File Content (for in-browser XML/JSON/HTML editing) */
    if (strcmp(req->path, "/api/save_file_content") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[128] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0) {
            strncpy(filename, "AutoUpdater.xml", sizeof(filename) - 1);
        }

        if (!sanitize_name(filename) || (strlen(app_name) > 0 && !sanitize_name(app_name))) {
            return http_send_error(sock, 400, "Invalid file or application name");
        }

        char target_dir[1024];
        if (strlen(app_name) > 0) {
            snprintf(target_dir, sizeof(target_dir), "%s/%s", ctx->updates_dir, app_name);
            MKDIR(target_dir);
        } else {
            strncpy(target_dir, ctx->updates_dir, sizeof(target_dir) - 1);
        }

        char fpath[1024];
        snprintf(fpath, sizeof(fpath), "%s/%s", target_dir, filename);

        FILE *f = fopen(fpath, "wb");
        if (!f) {
            return http_send_error(sock, 500, "Cannot write file to disk");
        }

        if (req->body && req->body_len > 0) {
            fwrite(req->body, 1, req->body_len, f);
        }
        fclose(f);

        log_msg("INFO", "Saved file content: %s (%zu bytes)", fpath, req->body_len);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"File saved successfully.\"}\n");
    }

    if (strncmp(req->path, "/api/", 5) == 0) {
        log_msg("WARN", "API route not found: %s %s", req->method_str, req->path);
        return http_send_json(sock, 404, "{\"error\": 404, \"message\": \"API route not found.\"}\n");
    }

    return -1;
}
