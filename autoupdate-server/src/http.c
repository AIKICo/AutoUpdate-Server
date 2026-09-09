#include "http.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif

int http_parse_request(const char *raw_req, size_t raw_len, http_request_t *req) {
    memset(req, 0, sizeof(*req));

    /* Find end of request line */
    const char *line_end = strstr(raw_req, "\r\n");
    if (!line_end) return -1;

    char req_line[2048];
    size_t line_len = line_end - raw_req;
    if (line_len >= sizeof(req_line)) line_len = sizeof(req_line) - 1;
    memcpy(req_line, raw_req, line_len);
    req_line[line_len] = '\0';

    /* Parse method, uri, version */
    char uri[2048];
    char version[32];
    if (sscanf(req_line, "%15s %2047s %31s", req->method_str, uri, version) < 2) {
        return -1;
    }

    if (strcasecmp(req->method_str, "GET") == 0) req->method = HTTP_METHOD_GET;
    else if (strcasecmp(req->method_str, "HEAD") == 0) req->method = HTTP_METHOD_HEAD;
    else if (strcasecmp(req->method_str, "POST") == 0) req->method = HTTP_METHOD_POST;
    else if (strcasecmp(req->method_str, "OPTIONS") == 0) req->method = HTTP_METHOD_OPTIONS;
    else if (strcasecmp(req->method_str, "DELETE") == 0) req->method = HTTP_METHOD_DELETE;
    else req->method = HTTP_METHOD_UNKNOWN;

    /* Split uri into path and query */
    char *query_start = strchr(uri, '?');
    if (query_start) {
        *query_start = '\0';
        strncpy(req->query, query_start + 1, sizeof(req->query) - 1);
    }
    strncpy(req->path, uri, sizeof(req->path) - 1);

    /* Parse headers */
    const char *p = line_end + 2;
    const char *headers_end = strstr(raw_req, "\r\n\r\n");
    if (!headers_end) {
        headers_end = strstr(raw_req, "\n\n");
        if (!headers_end) return -1;
    }

    while (p < headers_end) {
        const char *next_line = strstr(p, "\r\n");
        if (!next_line || next_line == p) break;

        size_t hlen = next_line - p;
        char hbuf[1024];
        if (hlen >= sizeof(hbuf)) hlen = sizeof(hbuf) - 1;
        memcpy(hbuf, p, hlen);
        hbuf[hlen] = '\0';

        char *colon = strchr(hbuf, ':');
        if (colon) {
            *colon = '\0';
            char *val = colon + 1;
            while (*val == ' ' || *val == '\t') val++;

            if (strcasecmp(hbuf, "Range") == 0) {
                strncpy(req->range_header, val, sizeof(req->range_header) - 1);
            } else if (strcasecmp(hbuf, "Authorization") == 0) {
                strncpy(req->auth_header, val, sizeof(req->auth_header) - 1);
            } else if (strcasecmp(hbuf, "Content-Type") == 0) {
                strncpy(req->content_type, val, sizeof(req->content_type) - 1);
            } else if (strcasecmp(hbuf, "Content-Length") == 0) {
                req->content_length = (size_t)strtoull(val, NULL, 10);
            } else if (strcasecmp(hbuf, "Host") == 0) {
                strncpy(req->host_header, val, sizeof(req->host_header) - 1);
            } else if (strcasecmp(hbuf, "Cookie") == 0) {
                strncpy(req->cookie_header, val, sizeof(req->cookie_header) - 1);
            }
        }
        p = next_line + 2;
    }

    /* Locate body */
    if (headers_end) {
        if (strncmp(headers_end, "\r\n\r\n", 4) == 0) {
            req->body = headers_end + 4;
            req->body_len = raw_len - (req->body - raw_req);
        } else {
            req->body = headers_end + 2;
            req->body_len = raw_len - (req->body - raw_req);
        }
    }

    return 0;
}

int http_send_response(socket_t sock, int code, const char *status_text, const char *content_type, const char *extra_headers, const void *body, size_t body_len) {
    char header_buf[2048];
    int hlen = snprintf(header_buf, sizeof(header_buf),
        "HTTP/1.1 %d %s\r\n"
        "Server: AutoUpdate-Server/2.0\r\n"
        "Accept-Ranges: bytes\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, HEAD, OPTIONS, DELETE\r\n"
        "Access-Control-Allow-Headers: Range, Content-Type, Authorization\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        code, status_text ? status_text : "OK",
        content_type ? content_type : "text/plain",
        body_len,
        extra_headers ? extra_headers : ""
    );

    if (SOCK_WRITE(sock, header_buf, hlen) < 0) return -1;
    if (body && body_len > 0) {
        if (SOCK_WRITE(sock, body, body_len) < 0) return -1;
    }
    return 0;
}

int http_send_json(socket_t sock, int code, const char *json_body) {
    return http_send_response(sock, code, "OK", "application/json; charset=utf-8", NULL, json_body, strlen(json_body));
}

int http_send_error(socket_t sock, int code, const char *message) {
    char json_err[512];
    snprintf(json_err, sizeof(json_err), "{\"error\": %d, \"message\": \"%s\"}\n", code, message);
    return http_send_response(sock, code, message, "application/json", NULL, json_err, strlen(json_err));
}

int http_send_file(socket_t sock, const char *filepath, const char *range_header, int is_head, uint64_t *out_bytes_sent) {
    if (out_bytes_sent) *out_bytes_sent = 0;

    struct stat st;
    if (stat(filepath, &st) != 0 || (st.st_mode & S_IFDIR)) {
        return http_send_error(sock, 404, "File Not Found");
    }

#ifdef _WIN32
    int fd = open(filepath, O_RDONLY | O_BINARY);
#else
    int fd = open(filepath, O_RDONLY);
#endif
    if (fd < 0) {
        return http_send_error(sock, 403, "Access Forbidden");
    }

    uint64_t file_size = (uint64_t)st.st_size;
    const char *mime = get_mime_type(filepath);

    uint64_t start = 0;
    uint64_t end = file_size > 0 ? (file_size - 1) : 0;
    int is_range = 0;

    /* Parse Range Header if present (e.g. bytes=100-200 or bytes=100-) */
    if (range_header && strlen(range_header) > 0 && file_size > 0) {
        const char *prefix = "bytes=";
        const char *r = strstr(range_header, prefix);
        if (r) {
            r += strlen(prefix);
            char *dash = strchr(r, '-');
            if (dash) {
                if (dash == r) {
                    uint64_t suffix = strtoull(dash + 1, NULL, 10);
                    if (suffix < file_size) {
                        start = file_size - suffix;
                        end = file_size - 1;
                        is_range = 1;
                    }
                } else {
                    start = strtoull(r, NULL, 10);
                    if (*(dash + 1) != '\0' && *(dash + 1) != ',') {
                        end = strtoull(dash + 1, NULL, 10);
                    } else {
                        end = file_size - 1;
                    }
                    if (start <= end && start < file_size) {
                        if (end >= file_size) end = file_size - 1;
                        is_range = 1;
                    }
                }
            }
        }
    }

    if (range_header && strlen(range_header) > 0 && !is_range) {
        close(fd);
        char extra[128];
        snprintf(extra, sizeof(extra), "Content-Range: bytes */%llu\r\n", (unsigned long long)file_size);
        return http_send_response(sock, 416, "Range Not Satisfiable", "text/plain", extra, "Range Not Satisfiable\n", 22);
    }

    uint64_t content_len = (file_size == 0) ? 0 : (end - start + 1);

    char header_buf[2048];
    int hlen;
    if (is_range) {
        hlen = snprintf(header_buf, sizeof(header_buf),
            "HTTP/1.1 206 Partial Content\r\n"
            "Server: AutoUpdate-Server/2.0\r\n"
            "Accept-Ranges: bytes\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Range: bytes %llu-%llu/%llu\r\n"
            "Content-Length: %llu\r\n"
            "Content-Type: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            (unsigned long long)start,
            (unsigned long long)end,
            (unsigned long long)file_size,
            (unsigned long long)content_len,
            mime
        );
    } else {
        hlen = snprintf(header_buf, sizeof(header_buf),
            "HTTP/1.1 200 OK\r\n"
            "Server: AutoUpdate-Server/2.0\r\n"
            "Accept-Ranges: bytes\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %llu\r\n"
            "Content-Type: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            (unsigned long long)content_len,
            mime
        );
    }

    if (SOCK_WRITE(sock, header_buf, hlen) < 0) {
        close(fd);
        return -1;
    }

    if (is_head || content_len == 0) {
        close(fd);
        return 0;
    }

    /* Zero-copy transmission using sendfile on Linux */
#ifdef __linux__
    off_t offset = (off_t)start;
    size_t remaining = (size_t)content_len;
    while (remaining > 0) {
        size_t chunk = remaining > (1024 * 1024 * 4) ? (1024 * 1024 * 4) : remaining;
        ssize_t sent = sendfile(sock, fd, &offset, chunk);
        if (sent <= 0) {
            if (sent < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            break;
        }
        remaining -= sent;
        if (out_bytes_sent) *out_bytes_sent += sent;
    }
#else
    /* Portable buffer fallback */
    lseek(fd, (off_t)start, SEEK_SET);
    char buf[65536];
    uint64_t remaining = content_len;
    while (remaining > 0) {
        size_t to_read = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        ssize_t r = read(fd, buf, (unsigned int)to_read);
        if (r <= 0) break;
        ssize_t w = SOCK_WRITE(sock, buf, r);
        if (w <= 0) break;
        remaining -= w;
        if (out_bytes_sent) *out_bytes_sent += w;
    }
#endif

    close(fd);
    return 0;
}

int http_get_cookie(const http_request_t *req, const char *cookie_name, char *out_val, size_t out_len) {
    if (!req || !cookie_name || !out_val || out_len == 0) return -1;
    out_val[0] = '\0';
    if (req->cookie_header[0] == '\0') return -1;

    size_t name_len = strlen(cookie_name);
    const char *p = req->cookie_header;

    while (*p) {
        while (*p == ' ' || *p == ';') p++;
        if (!*p) break;

        if (strncmp(p, cookie_name, name_len) == 0 && p[name_len] == '=') {
            const char *val_start = p + name_len + 1;
            const char *val_end = val_start;
            while (*val_end && *val_end != ';') val_end++;

            size_t vlen = (size_t)(val_end - val_start);
            if (vlen >= out_len) vlen = out_len - 1;
            memcpy(out_val, val_start, vlen);
            out_val[vlen] = '\0';
            return 0;
        }

        while (*p && *p != ';') p++;
    }

    return -1;
}
