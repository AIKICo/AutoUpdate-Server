#ifndef ZIP_READER_H
#define ZIP_READER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char entry_path[1024];
    char file_name[256];
    uint64_t uncompressed_size;
    uint32_t crc32;
    int score;
} zip_exe_entry_t;

/*
 * Lists all executable files (.exe) inside a ZIP archive, sorted by relevance score.
 * Returns the number of executable candidates found.
 */
int zip_list_executable_entries(const char *zip_path, const char *preferred_app, zip_exe_entry_t *out_entries, int max_entries);

/*
 * Finds a specific executable entry by exact entry path or matching base filename.
 * Returns 1 if found and fills out_entry_path, 0 otherwise.
 */
int zip_find_executable_entry(const char *zip_path, const char *target_exe, char *out_entry_path, size_t max_len);

/*
 * Finds the most suitable executable (.exe) inside a ZIP archive.
 * Scores candidates based on preferred_app (stripping platform suffixes like -win-x64).
 * Returns 1 if found and fills out_entry_path, 0 otherwise.
 */
int zip_find_best_executable(const char *zip_path, const char *preferred_app, char *out_entry_path, size_t max_len);

/*
 * Extracts a specific entry from a ZIP archive directly to dest_path.
 * Supports stored (0) and deflated (8) entries using pure C.
 * Returns 0 on success, non-zero on failure.
 */
int zip_extract_entry(const char *zip_path, const char *entry_name, const char *dest_path);

/*
 * Extracts all files in zip_path to dest_dir.
 * Returns 0 on success, non-zero on failure.
 */
int zip_extract_all(const char *zip_path, const char *dest_dir);

#ifdef __cplusplus
}
#endif

#endif /* ZIP_READER_H */
