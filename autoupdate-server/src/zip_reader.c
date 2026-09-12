#include "zip_reader.h"
#include "puff.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define MKDIR_ONE(p) _mkdir(p)
#else
#include <unistd.h>
#define MKDIR_ONE(p) mkdir(p, 0755)
#endif

/* Helper: read 16-bit little-endian */
static inline uint16_t read_le16(const unsigned char *b) {
    return (uint16_t)(b[0] | (b[1] << 8));
}

/* Helper: read 32-bit little-endian */
static inline uint32_t read_le32(const unsigned char *b) {
    return (uint32_t)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));
}

/* Create all missing parent directories */
static void ensure_parent_dir_exists(const char *filepath) {
    char dir[1024];
    strncpy(dir, filepath, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';

    char *last_slash = strrchr(dir, '/');
    char *last_bslash = strrchr(dir, '\\');
    char *s = last_slash > last_bslash ? last_slash : last_bslash;
    if (!s) return;
    *s = '\0';

    for (char *p = dir + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char tmp = *p;
            *p = '\0';
            MKDIR_ONE(dir);
            *p = tmp;
        }
    }
    MKDIR_ONE(dir);
}

/* Case-insensitive string search */
static const char *str_case_str(const char *haystack, const char *needle) {
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

/* Calculate score for an executable entry relative to preferred_app */
static int score_executable_candidate(const char *entry_name, const char *preferred_app, const char *stripped_app) {
    const char *slash = strrchr(entry_name, '/');
    const char *bslash = strrchr(entry_name, '\\');
    const char *base = slash > bslash ? slash + 1 : (bslash ? bslash + 1 : entry_name);
    size_t blen = strlen(base);
    if (blen < 4) return 0;

    /* Check if it ends with .exe */
#ifdef _WIN32
    if (_stricmp(base + blen - 4, ".exe") != 0) return 0;
#else
    if (strcasecmp(base + blen - 4, ".exe") != 0) return 0;
#endif

    char base_no_ext[256];
    strncpy(base_no_ext, base, sizeof(base_no_ext) - 1);
    base_no_ext[sizeof(base_no_ext) - 1] = '\0';
    if (blen - 4 < sizeof(base_no_ext)) {
        base_no_ext[blen - 4] = '\0';
    }

    /* Excluded binaries get very low score */
    if (str_case_str(base, "createdump") != 0 ||
        str_case_str(base, "unins") != 0 ||
        str_case_str(base, "setup") != 0 ||
        str_case_str(base, "installer") != 0 ||
        str_case_str(base, "vc_redist") != 0 ||
        str_case_str(base, "dxwebsetup") != 0) {
        return 10;
    }

    char expected_full[256];
    snprintf(expected_full, sizeof(expected_full), "%s.exe", preferred_app);

    char expected_clean[256];
    snprintf(expected_clean, sizeof(expected_clean), "%s.exe", stripped_app);

    /* 1. Exact match with original preferred_app.exe */
#ifdef _WIN32
    if (_stricmp(base, expected_full) == 0) return 100;
#else
    if (strcasecmp(base, expected_full) == 0) return 100;
#endif

    /* 2. Exact match with stripped base name */
#ifdef _WIN32
    if (_stricmp(base, expected_clean) == 0) return 90;
#else
    if (strcasecmp(base, expected_clean) == 0) return 90;
#endif

    /* 3. Base name without ext equals stripped app */
#ifdef _WIN32
    if (_stricmp(base_no_ext, stripped_app) == 0) return 90;
#else
    if (strcasecmp(base_no_ext, stripped_app) == 0) return 90;
#endif

    /* 4. Starts with stripped app */
    size_t slen = strlen(stripped_app);
    if (slen > 0) {
#ifdef _WIN32
        if (_strnicmp(base, stripped_app, slen) == 0) return 80;
#else
        if (strncasecmp(base, stripped_app, slen) == 0) return 80;
#endif
    }

    /* 5. Contains stripped app */
    if (slen > 0 && str_case_str(base, stripped_app) != NULL) {
        return 70;
    }

    /* 6. Standard binary */
    return 50;
}

/* Locate End-of-Central-Directory (EOCD) record */
static int find_eocd(FILE *f, uint32_t *out_cd_offset, uint32_t *out_cd_size, uint16_t *out_total_entries) {
    if (fseek(f, 0, SEEK_END) != 0) return -1;
    long fsize = ftell(f);
    if (fsize < 22) return -1;

    long max_search = fsize > 65557 ? 65557 : fsize;
    long search_start = fsize - max_search;
    if (fseek(f, search_start, SEEK_SET) != 0) return -1;

    unsigned char *buf = (unsigned char *)malloc((size_t)max_search);
    if (!buf) return -1;

    size_t read_bytes = fread(buf, 1, (size_t)max_search, f);
    long eocd_pos = -1;
    for (long i = (long)read_bytes - 22; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4B && buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            eocd_pos = i;
            break;
        }
    }

    if (eocd_pos < 0) {
        free(buf);
        return -1;
    }

    const unsigned char *p = buf + eocd_pos;
    *out_total_entries = read_le16(p + 10);
    *out_cd_size = read_le32(p + 12);
    *out_cd_offset = read_le32(p + 16);

    free(buf);
    return 0;
}

/* List all executable entries sorted by relevance score */
int zip_list_executable_entries(const char *zip_path, const char *preferred_app, zip_exe_entry_t *out_entries, int max_entries) {
    if (!zip_path || !out_entries || max_entries <= 0) return 0;

    FILE *f = fopen(zip_path, "rb");
    if (!f) return 0;

    uint32_t cd_offset = 0, cd_size = 0;
    uint16_t total_entries = 0;
    if (find_eocd(f, &cd_offset, &cd_size, &total_entries) != 0) {
        fclose(f);
        return 0;
    }

    if (fseek(f, cd_offset, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    char stripped_app[128] = {0};
    if (preferred_app) {
        strip_app_suffix(preferred_app, stripped_app, sizeof(stripped_app));
    }

    int count = 0;

    for (uint16_t i = 0; i < total_entries; i++) {
        unsigned char hdr[46];
        if (fread(hdr, 1, 46, f) != 46) break;
        if (hdr[0] != 0x50 || hdr[1] != 0x4B || hdr[2] != 0x01 || hdr[3] != 0x02) break;

        uint32_t crc = read_le32(hdr + 16);
        uint32_t uncomp_size = read_le32(hdr + 24);
        uint16_t name_len = read_le16(hdr + 28);
        uint16_t extra_len = read_le16(hdr + 30);
        uint16_t comment_len = read_le16(hdr + 32);

        char name[1024];
        size_t to_read = name_len < sizeof(name) - 1 ? name_len : sizeof(name) - 1;
        if (fread(name, 1, to_read, f) != to_read) break;
        name[to_read] = '\0';
        if (name_len > to_read) {
            fseek(f, name_len - to_read, SEEK_CUR);
        }

        if (extra_len + comment_len > 0) {
            fseek(f, extra_len + comment_len, SEEK_CUR);
        }

        size_t nlen = strlen(name);
        if (nlen < 4) continue;
        const char *ext = name + nlen - 4;
#ifdef _WIN32
        if (_stricmp(ext, ".exe") != 0) continue;
#else
        if (strcasecmp(ext, ".exe") != 0) continue;
#endif

        if (count < max_entries) {
            strncpy(out_entries[count].entry_path, name, sizeof(out_entries[count].entry_path) - 1);
            out_entries[count].entry_path[sizeof(out_entries[count].entry_path) - 1] = '\0';

            const char *slash = strrchr(name, '/');
            const char *bslash = strrchr(name, '\\');
            const char *base = slash > bslash ? slash + 1 : (bslash ? bslash + 1 : name);
            strncpy(out_entries[count].file_name, base, sizeof(out_entries[count].file_name) - 1);
            out_entries[count].file_name[sizeof(out_entries[count].file_name) - 1] = '\0';

            out_entries[count].uncompressed_size = uncomp_size;
            out_entries[count].crc32 = crc;
            out_entries[count].score = score_executable_candidate(name, preferred_app ? preferred_app : "", stripped_app);
            count++;
        }
    }

    fclose(f);

    /* Sort entries descending by score */
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (out_entries[j].score > out_entries[i].score) {
                zip_exe_entry_t tmp = out_entries[i];
                out_entries[i] = out_entries[j];
                out_entries[j] = tmp;
            }
        }
    }

    return count;
}

/* Find specific executable by name or path */
int zip_find_executable_entry(const char *zip_path, const char *target_exe, char *out_entry_path, size_t max_len) {
    if (!zip_path || !target_exe || !out_entry_path || max_len == 0) return 0;
    out_entry_path[0] = '\0';

    zip_exe_entry_t list[64];
    int n = zip_list_executable_entries(zip_path, NULL, list, 64);
    if (n <= 0) return 0;

    /* 1. Exact match on entry_path */
    for (int i = 0; i < n; i++) {
#ifdef _WIN32
        if (_stricmp(list[i].entry_path, target_exe) == 0) {
#else
        if (strcasecmp(list[i].entry_path, target_exe) == 0) {
#endif
            strncpy(out_entry_path, list[i].entry_path, max_len - 1);
            out_entry_path[max_len - 1] = '\0';
            return 1;
        }
    }

    /* 2. Match on base file_name */
    for (int i = 0; i < n; i++) {
#ifdef _WIN32
        if (_stricmp(list[i].file_name, target_exe) == 0) {
#else
        if (strcasecmp(list[i].file_name, target_exe) == 0) {
#endif
            strncpy(out_entry_path, list[i].entry_path, max_len - 1);
            out_entry_path[max_len - 1] = '\0';
            return 1;
        }
    }

    return 0;
}

/* Find best executable inside ZIP Central Directory */
int zip_find_best_executable(const char *zip_path, const char *preferred_app, char *out_entry_path, size_t max_len) {
    if (!zip_path || !preferred_app || !out_entry_path || max_len == 0) return 0;
    out_entry_path[0] = '\0';

    zip_exe_entry_t list[64];
    int n = zip_list_executable_entries(zip_path, preferred_app, list, 64);
    if (n > 0) {
        strncpy(out_entry_path, list[0].entry_path, max_len - 1);
        out_entry_path[max_len - 1] = '\0';
        return 1;
    }
    return 0;
}

/* Extract a single entry by exact name */
int zip_extract_entry(const char *zip_path, const char *entry_name, const char *dest_path) {
    if (!zip_path || !entry_name || !dest_path) return -1;

    FILE *f = fopen(zip_path, "rb");
    if (!f) return -1;

    uint32_t cd_offset = 0, cd_size = 0;
    uint16_t total_entries = 0;
    if (find_eocd(f, &cd_offset, &cd_size, &total_entries) != 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, cd_offset, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    int found = 0;
    uint16_t method = 0;
    uint32_t comp_size = 0;
    uint32_t uncomp_size = 0;
    uint32_t local_hdr_offset = 0;

    for (uint16_t i = 0; i < total_entries; i++) {
        unsigned char hdr[46];
        if (fread(hdr, 1, 46, f) != 46) break;
        if (hdr[0] != 0x50 || hdr[1] != 0x4B || hdr[2] != 0x01 || hdr[3] != 0x02) break;

        method = read_le16(hdr + 10);
        comp_size = read_le32(hdr + 20);
        uncomp_size = read_le32(hdr + 24);
        uint16_t name_len = read_le16(hdr + 28);
        uint16_t extra_len = read_le16(hdr + 30);
        uint16_t comment_len = read_le16(hdr + 32);
        local_hdr_offset = read_le32(hdr + 42);

        char name[1024];
        size_t to_read = name_len < sizeof(name) - 1 ? name_len : sizeof(name) - 1;
        if (fread(name, 1, to_read, f) != to_read) break;
        name[to_read] = '\0';
        if (name_len > to_read) {
            fseek(f, name_len - to_read, SEEK_CUR);
        }
        if (extra_len + comment_len > 0) {
            fseek(f, extra_len + comment_len, SEEK_CUR);
        }

        if (strcmp(name, entry_name) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        fclose(f);
        return -1;
    }

    /* Seek to Local File Header */
    if (fseek(f, local_hdr_offset, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    unsigned char lhdr[30];
    if (fread(lhdr, 1, 30, f) != 30 || lhdr[0] != 0x50 || lhdr[1] != 0x4B || lhdr[2] != 0x03 || lhdr[3] != 0x04) {
        fclose(f);
        return -1;
    }

    uint16_t lname_len = read_le16(lhdr + 26);
    uint16_t lextra_len = read_le16(lhdr + 28);
    fseek(f, lname_len + lextra_len, SEEK_CUR);

    ensure_parent_dir_exists(dest_path);

    /* Method 0: Stored (Uncompressed) */
    if (method == 0) {
        FILE *out = fopen(dest_path, "wb");
        if (!out) { fclose(f); return -1; }

        unsigned char buf[16384];
        uint32_t remaining = comp_size;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
            size_t rd = fread(buf, 1, chunk, f);
            if (rd == 0) break;
            fwrite(buf, 1, rd, out);
            remaining -= (uint32_t)rd;
        }
        fclose(out);
        fclose(f);
        return 0;
    }

    /* Method 8: Deflated */
    if (method == 8) {
        unsigned char *comp_buf = (unsigned char *)malloc(comp_size);
        if (!comp_buf) { fclose(f); return -1; }

        if (fread(comp_buf, 1, comp_size, f) != comp_size) {
            free(comp_buf);
            fclose(f);
            return -1;
        }
        fclose(f);

        unsigned char *uncomp_buf = (unsigned char *)malloc(uncomp_size > 0 ? uncomp_size : 1);
        if (!uncomp_buf) {
            free(comp_buf);
            return -1;
        }

        unsigned long dest_len = uncomp_size;
        unsigned long src_len = comp_size;
        int res = puff(uncomp_buf, &dest_len, comp_buf, &src_len);
        free(comp_buf);

        if (res != 0) {
            free(uncomp_buf);
            return -1;
        }

        FILE *out = fopen(dest_path, "wb");
        if (!out) {
            free(uncomp_buf);
            return -1;
        }
        fwrite(uncomp_buf, 1, dest_len, out);
        fclose(out);
        free(uncomp_buf);
        return 0;
    }

    fclose(f);
    return -1; /* Unsupported compression method */
}

/* Extract all files to dest_dir */
int zip_extract_all(const char *zip_path, const char *dest_dir) {
    if (!zip_path || !dest_dir) return -1;

    FILE *f = fopen(zip_path, "rb");
    if (!f) return -1;

    uint32_t cd_offset = 0, cd_size = 0;
    uint16_t total_entries = 0;
    if (find_eocd(f, &cd_offset, &cd_size, &total_entries) != 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, cd_offset, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    /* Store entries metadata in memory */
    typedef struct {
        char name[512];
        uint16_t method;
        uint32_t comp_size;
        uint32_t uncomp_size;
        uint32_t local_hdr_offset;
    } entry_info_t;

    entry_info_t *entries = (entry_info_t *)malloc(sizeof(entry_info_t) * total_entries);
    if (!entries) {
        fclose(f);
        return -1;
    }

    int valid_count = 0;
    for (uint16_t i = 0; i < total_entries; i++) {
        unsigned char hdr[46];
        if (fread(hdr, 1, 46, f) != 46) break;
        if (hdr[0] != 0x50 || hdr[1] != 0x4B || hdr[2] != 0x01 || hdr[3] != 0x02) break;

        entries[valid_count].method = read_le16(hdr + 10);
        entries[valid_count].comp_size = read_le32(hdr + 20);
        entries[valid_count].uncomp_size = read_le32(hdr + 24);
        uint16_t name_len = read_le16(hdr + 28);
        uint16_t extra_len = read_le16(hdr + 30);
        uint16_t comment_len = read_le16(hdr + 32);
        entries[valid_count].local_hdr_offset = read_le32(hdr + 42);

        size_t to_read = name_len < sizeof(entries[valid_count].name) - 1 ? name_len : sizeof(entries[valid_count].name) - 1;
        if (fread(entries[valid_count].name, 1, to_read, f) != to_read) break;
        entries[valid_count].name[to_read] = '\0';
        if (name_len > to_read) {
            fseek(f, name_len - to_read, SEEK_CUR);
        }
        if (extra_len + comment_len > 0) {
            fseek(f, extra_len + comment_len, SEEK_CUR);
        }
        valid_count++;
    }

    int success_count = 0;
    for (int i = 0; i < valid_count; i++) {
        char out_path[1024];
        snprintf(out_path, sizeof(out_path), "%s/%s", dest_dir, entries[i].name);

        size_t elen = strlen(entries[i].name);
        if (elen > 0 && (entries[i].name[elen - 1] == '/' || entries[i].name[elen - 1] == '\\')) {
            ensure_parent_dir_exists(out_path);
            MKDIR_ONE(out_path);
            continue;
        }

        if (fseek(f, entries[i].local_hdr_offset, SEEK_SET) != 0) continue;

        unsigned char lhdr[30];
        if (fread(lhdr, 1, 30, f) != 30 || lhdr[0] != 0x50 || lhdr[1] != 0x4B || lhdr[2] != 0x03 || lhdr[3] != 0x04) {
            continue;
        }

        uint16_t lname_len = read_le16(lhdr + 26);
        uint16_t lextra_len = read_le16(lhdr + 28);
        fseek(f, lname_len + lextra_len, SEEK_CUR);

        ensure_parent_dir_exists(out_path);

        if (entries[i].method == 0) {
            FILE *out = fopen(out_path, "wb");
            if (out) {
                unsigned char buf[16384];
                uint32_t remaining = entries[i].comp_size;
                while (remaining > 0) {
                    size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                    size_t rd = fread(buf, 1, chunk, f);
                    if (rd == 0) break;
                    fwrite(buf, 1, rd, out);
                    remaining -= (uint32_t)rd;
                }
                fclose(out);
                success_count++;
            }
        } else if (entries[i].method == 8) {
            unsigned char *comp_buf = (unsigned char *)malloc(entries[i].comp_size);
            if (comp_buf) {
                if (fread(comp_buf, 1, entries[i].comp_size, f) == entries[i].comp_size) {
                    unsigned char *uncomp_buf = (unsigned char *)malloc(entries[i].uncomp_size > 0 ? entries[i].uncomp_size : 1);
                    if (uncomp_buf) {
                        unsigned long dest_len = entries[i].uncomp_size;
                        unsigned long src_len = entries[i].comp_size;
                        if (puff(uncomp_buf, &dest_len, comp_buf, &src_len) == 0) {
                            FILE *out = fopen(out_path, "wb");
                            if (out) {
                                fwrite(uncomp_buf, 1, dest_len, out);
                                fclose(out);
                                success_count++;
                            }
                        }
                        free(uncomp_buf);
                    }
                }
                free(comp_buf);
            }
        }
    }

    free(entries);
    fclose(f);
    return (success_count > 0 || valid_count == 0) ? 0 : -1;
}
