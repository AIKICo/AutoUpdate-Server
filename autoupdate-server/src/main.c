#include "server.h"
#include "utils.h"
#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
    #include <process.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

#define DEFAULT_PORT 8080
#define PID_FILE "autoupdate.pid"
#define LOG_FILE "autoupdate.log"

static void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_msg("INFO", "Received shutdown signal (%d), stopping server...", sig);
        server_stop();
        unlink(PID_FILE);
    }
}

static void print_usage(const char *prog) {
    printf("==================================================================\n");
    printf("  AutoUpdate-Server v2.0 - Standalone C WebServer                 \n");
    printf("  Specially Designed for AutoUpdater.NET with Range/Resume Support\n");
    printf("==================================================================\n\n");
    printf("کاربرد (Usage):\n");
    printf("  %s [options]\n", prog);
    printf("  %s stop      توقف سرور فعال در پس‌زمینه (Stop running daemon)\n", prog);
    printf("  %s status    بررسی وضعیت سرور (Check server status)\n\n", prog);
    printf("سوئیچ‌ها (Options):\n");
    printf("  -p <port>       تعیین پورت شنود (Listen port, پیش‌فرض: 8080)\n");
    printf("  -w <path>       مسیر پوشه فایل‌های به‌روزرسانی (Updates directory, پیش‌فرض: ./updates)\n");
    printf("  -r <path>       مسیر فایل‌های وب مدیریتی (Webroot directory, پیش‌فرض: ./webroot)\n");
    printf("  -u <username>   نام کاربری پنل مدیریت (Admin username, پیش‌فرض: admin)\n");
    printf("  -a <password>   کلمه عبور پنل مدیریت (Admin password, پیش‌فرض: admin123)\n");
    printf("  -d              اجرا به صورت سرویس در پس‌زمینه (Run as background daemon)\n");
    printf("  -l <logfile>    تعیین مسیر فایل لاگ (Log file path, پیش‌فرض: autoupdate.log)\n");
    printf("  -h, --help      نمایش این راهنما\n\n");
    printf("مثال‌ها (Examples):\n");
    printf("  %s -p 8080 -d                  اجرا در پس‌زمینه روی پورت 8080\n", prog);
    printf("  %s -p 9000 -w /var/updates -d  اجرا در پس‌زمینه با مسیر سفارشی\n", prog);
    printf("  %s stop                        توقف سرور در حال اجرا\n", prog);
    printf("  %s status                      بررسی وضعیت اجرا\n\n", prog);
}

static int do_daemonize(const char *pid_file, const char *log_file) {
#ifdef _WIN32
    /* On Windows, hide console window to run in background */
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
    FILE *fp = fopen(pid_file, "w");
    if (fp) {
        fprintf(fp, "%lu\n", GetCurrentProcessId());
        fclose(fp);
    }
    return 0;
#else
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) {
        printf("AutoUpdate-Server در پس‌زمینه با شناسه فرآیند (PID) %d راه‌اندازی شد.\n", pid);
        exit(0);
    }

    if (setsid() < 0) return -1;

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) exit(0);

    umask(0);

    FILE *fp = fopen(pid_file, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }

    int logfd = open(log_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd >= 0) {
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        close(logfd);
    }
    int nullfd = open("/dev/null", O_RDONLY);
    if (nullfd >= 0) {
        dup2(nullfd, STDIN_FILENO);
        close(nullfd);
    }

    return 0;
#endif
}

static int check_status(const char *pid_file) {
    FILE *fp = fopen(pid_file, "r");
    if (!fp) {
        printf("سرور فعال نیست (فایل PID یافت نشد).\n");
        return 1;
    }
    int pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) {
        fclose(fp);
        printf("خطا در خواندن فایل PID.\n");
        return 1;
    }
    fclose(fp);

#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (h) {
        CloseHandle(h);
        printf("سرور هم‌اکنون با شناسه (PID) %d در پس‌زمینه در حال اجرا است.\n", pid);
        return 0;
    }
#else
    if (kill(pid, 0) == 0) {
        printf("سرور هم‌اکنون با شناسه (PID) %d در پس‌زمینه در حال اجرا است.\n", pid);
        return 0;
    }
#endif

    printf("فرآیند مربوط به PID %d فعال نیست. فایل PID پاک شد.\n", pid);
    unlink(pid_file);
    return 1;
}

static int stop_daemon(const char *pid_file) {
    FILE *fp = fopen(pid_file, "r");
    if (!fp) {
        printf("سرور فعال نیست یا قبلاً متوقف شده است.\n");
        return 1;
    }
    int pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) {
        fclose(fp);
        unlink(pid_file);
        return 1;
    }
    fclose(fp);

    printf("در حال ارسال سیگنال توقف به سرور (PID %d)...\n", pid);
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (h) {
        TerminateProcess(h, 0);
        CloseHandle(h);
        unlink(pid_file);
        printf("سرور با موفقیت متوقف شد.\n");
        return 0;
    }
#else
    if (kill(pid, SIGTERM) == 0) {
        unlink(pid_file);
        printf("سرور با موفقیت متوقف شد.\n");
        return 0;
    }
#endif

    printf("خطا در توقف سرور.\n");
    unlink(pid_file);
    return 1;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    int is_daemon = 0;
    char updates_dir[1024] = "./updates";
    char webroot_dir[1024] = "./webroot";
    char log_file[1024] = LOG_FILE;
    char admin_user[64] = "admin";
    char admin_pass[64] = "admin123";

    if (argc >= 2) {
        if (strcmp(argv[1], "stop") == 0) {
            return stop_daemon(PID_FILE);
        } else if (strcmp(argv[1], "status") == 0) {
            return check_status(PID_FILE);
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            strncpy(updates_dir, argv[++i], sizeof(updates_dir) - 1);
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            strncpy(webroot_dir, argv[++i], sizeof(webroot_dir) - 1);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            strncpy(admin_user, argv[++i], sizeof(admin_user) - 1);
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            strncpy(admin_pass, argv[++i], sizeof(admin_pass) - 1);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            strncpy(log_file, argv[++i], sizeof(log_file) - 1);
        } else if (strcmp(argv[i], "-d") == 0) {
            is_daemon = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    MKDIR(updates_dir);
    MKDIR(webroot_dir);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    if (is_daemon) {
        if (do_daemonize(PID_FILE, log_file) < 0) {
            fprintf(stderr, "خطا در اجرای پس‌زمینه: %s\n", strerror(errno));
            return 1;
        }
    } else {
        FILE *fp = fopen(PID_FILE, "w");
        if (fp) {
#ifdef _WIN32
            fprintf(fp, "%lu\n", GetCurrentProcessId());
#else
            fprintf(fp, "%d\n", getpid());
#endif
            fclose(fp);
        }
    }

    log_init(log_file);

    server_ctx_t ctx;
    server_init(&ctx, port, updates_dir, webroot_dir, admin_user, admin_pass);

    int res = server_start(&ctx);

    unlink(PID_FILE);
    log_close();
    return res;
}
