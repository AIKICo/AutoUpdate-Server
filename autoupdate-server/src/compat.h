#ifndef COMPAT_H
#define COMPAT_H

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
    #include <direct.h>
    #include <io.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <winver.h>

    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "user32.lib")
    #pragma comment(lib, "version.lib")

    static inline int run_hidden_command(const char *cmdline) {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        memset(&pi, 0, sizeof(pi));

        char cmd_buf[4096];
        strncpy(cmd_buf, cmdline, sizeof(cmd_buf) - 1);
        cmd_buf[sizeof(cmd_buf) - 1] = '\0';
        if (CreateProcessA(NULL, cmd_buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            DWORD wait_res = WaitForSingleObject(pi.hProcess, 15000); /* 15s max timeout */
            if (wait_res == WAIT_TIMEOUT) {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return -1;
            }
            DWORD code = 1;
            GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return (int)code;
        }
        return -1;
    }

    typedef SOCKET socket_t;
    #define CLOSE_SOCK(s) closesocket(s)
    #define SOCK_READ(s, buf, len) recv((s), (buf), (int)(len), 0)
    #define SOCK_WRITE(s, buf, len) send((s), (buf), (int)(len), 0)
    #define MKDIR(path) _mkdir(path)
    #define SLEEP_SEC(s) Sleep((s) * 1000)
    #define IS_VALID_SOCK(s) ((s) != INVALID_SOCKET)

    #ifndef strncasecmp
    #define strncasecmp _strnicmp
    #endif
    #ifndef strcasecmp
    #define strcasecmp _stricmp
    #endif
    #ifndef unlink
    #define unlink _unlink
    #endif
    #ifndef access
    #define access _access
    #endif
    #ifndef read
    #define read _read
    #endif
    #ifndef write
    #define write _write
    #endif
    #ifndef close
    #define close _close
    #endif
    #ifndef lseek
    #define lseek _lseeki64
    #endif
    #ifndef open
    #define open _open
    #endif
    #ifndef O_BINARY
    #define O_BINARY _O_BINARY
    #endif

    #ifndef S_ISDIR
    #define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
    #endif
    #ifndef S_ISREG
    #define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
    #endif

    #if defined(_MSC_VER)
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
    #endif

    /* Windows threading & mutex compatibility with POSIX pthread */
    typedef SRWLOCK pthread_mutex_t;
    #define PTHREAD_MUTEX_INITIALIZER SRWLOCK_INIT
    #define pthread_mutex_init(m, a) InitializeSRWLock(m)
    #define pthread_mutex_lock(m) AcquireSRWLockExclusive(m)
    #define pthread_mutex_unlock(m) ReleaseSRWLockExclusive(m)
    #define pthread_mutex_destroy(m) ((void)0)

    typedef uintptr_t pthread_t;
    typedef int pthread_attr_t;
    #define PTHREAD_CREATE_DETACHED 1
    #define pthread_attr_init(a) (*(a) = 0)
    #define pthread_attr_setdetachstate(a, v) (*(a) = (v))
    #define pthread_attr_destroy(a) ((void)0)

    typedef void *(*pthread_start_routine_t)(void *);
    typedef struct {
        pthread_start_routine_t func;
        void *arg;
    } thread_trampoline_arg_t;

    static inline unsigned __stdcall _win32_thread_trampoline(void *p) {
        thread_trampoline_arg_t *targ = (thread_trampoline_arg_t *)p;
        pthread_start_routine_t func = targ->func;
        void *arg = targ->arg;
        free(targ);
        func(arg);
        return 0;
    }

    static inline int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                     void *(*start_routine)(void *), void *arg) {
        (void)attr;
        thread_trampoline_arg_t *targ = (thread_trampoline_arg_t *)malloc(sizeof(*targ));
        if (!targ) return -1;
        targ->func = start_routine;
        targ->arg = arg;
        uintptr_t handle = _beginthreadex(NULL, 0, _win32_thread_trampoline, targ, 0, NULL);
        if (!handle) {
            free(targ);
            return -1;
        }
        CloseHandle((HANDLE)handle);
        if (thread) *thread = handle;
        return 0;
    }

    /* Windows directory reading compatibility (dirent) */
    struct dirent {
        char d_name[MAX_PATH];
    };

    typedef struct DIR {
        HANDLE hFind;
        WIN32_FIND_DATAA fd;
        struct dirent ent;
        int first;
    } DIR;

    static inline DIR *opendir(const char *name) {
        if (!name) return NULL;
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s/*", name);
        DIR *dir = (DIR *)malloc(sizeof(DIR));
        if (!dir) return NULL;
        dir->hFind = FindFirstFileA(pattern, &dir->fd);
        if (dir->hFind == INVALID_HANDLE_VALUE) {
            free(dir);
            return NULL;
        }
        dir->first = 1;
        return dir;
    }

    static inline struct dirent *readdir(DIR *dir) {
        if (!dir || dir->hFind == INVALID_HANDLE_VALUE) return NULL;
        if (dir->first) {
            dir->first = 0;
        } else {
            if (!FindNextFileA(dir->hFind, &dir->fd)) {
                return NULL;
            }
        }
        strncpy(dir->ent.d_name, dir->fd.cFileName, sizeof(dir->ent.d_name) - 1);
        dir->ent.d_name[sizeof(dir->ent.d_name) - 1] = '\0';
        return &dir->ent;
    }

    static inline int closedir(DIR *dir) {
        if (!dir) return -1;
        if (dir->hFind != INVALID_HANDLE_VALUE) {
            FindClose(dir->hFind);
        }
        free(dir);
        return 0;
    }

    static inline void platform_init_network(void) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    static inline void platform_cleanup_network(void) {
        WSACleanup();
    }
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <pthread.h>

    typedef int socket_t;
    #define CLOSE_SOCK(s) close(s)
    #define SOCK_READ(s, buf, len) read((s), (buf), (len))
    #define SOCK_WRITE(s, buf, len) write((s), (buf), (len))
    #define MKDIR(path) mkdir((path), 0755)
    #define SLEEP_SEC(s) sleep(s)
    #define IS_VALID_SOCK(s) ((s) >= 0)

    static inline void platform_init_network(void) {}
    static inline void platform_cleanup_network(void) {}
#endif

#endif /* COMPAT_H */
