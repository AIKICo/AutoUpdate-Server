#ifndef COMPAT_H
#define COMPAT_H

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <direct.h>
    #include <io.h>

    typedef SOCKET socket_t;
    #define CLOSE_SOCK(s) closesocket(s)
    #define SOCK_READ(s, buf, len) recv((s), (buf), (int)(len), 0)
    #define SOCK_WRITE(s, buf, len) send((s), (buf), (int)(len), 0)
    #define MKDIR(path) _mkdir(path)
    #define SLEEP_SEC(s) Sleep((s) * 1000)
    #define IS_VALID_SOCK(s) ((s) != INVALID_SOCKET)

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
