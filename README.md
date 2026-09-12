# AutoUpdate-Server
### High-Performance, Zero-Dependency Offline Web Server for AutoUpdater.NET

[![GitHub Organization](https://img.shields.io/badge/Organization-AIKICo-blue)](https://github.com/AIKICo)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64%20%7C%20Windows%20x64-orange)](https://github.com/AIKICo/AutoUpdate-Server)
[![Build](https://img.shields.io/badge/Build-100%25%20Static%20Musl%20C-brightgreen)](https://github.com/AIKICo/AutoUpdate-Server)

A dedicated, standalone HTTP web server written in pure C for air-gapped / offline Linux servers and local testing environments. Specifically designed to serve software updates to [.NET applications using AutoUpdater.NET](https://github.com/ravibpatel/AutoUpdater.NET).

---

## Key Features

- **100% Standalone & Statically Linked:** Pure C implementation compiled with `musl libc`. Zero runtime dependencies on `glibc`, system packages, or internet connectivity (`apt-get`/`yum` not required).
- **Multi-Application Subfolder Support:** Dedicated directory for each software (e.g. `/Accounting/`, `/Warehouse/`, `/CRM/`, or `/Root/`).
- **Modern English Web Management Dashboard (`/admin/`):**
  - Intuitive GUI to create and manage application folders.
  - Auto-generation of `AutoUpdater.xml` and `AutoUpdater.json` catalog files.
  - Direct file upload for update packages (`.zip`, `.exe`, `.msi`).
  - Automatic on-the-fly checksum computation (**SHA-256** and **MD5**).
  - Built-in C# code snippet generator for client-side copy & paste.
  - Real-time server statistics (uptime, request count, bandwidth).
- **HTTP Resume & Partial Content:** Full HTTP `Range: bytes=start-end` support returning `206 Partial Content` and `Accept-Ranges: bytes` for seamless, resumable downloads.
- **Ultra-Fast Zero-Copy Transfer:** Uses the Linux kernel `sendfile(2)` system call for high-throughput, low-CPU file delivery.
- **Daemon & Background Ready:** Included `start.sh`, `stop.sh`, `status.sh`, and `autoupdater.service` for systemd integration.
- **Cross-Platform:** Includes both Linux static x86_64 binary and Windows native `.exe` for quick local testing.

---

## Quick Start on Linux (Offline Server)

### 1. Extract Archive
Transfer `autoupdate-server-linux-x64.tar.gz` to your offline Linux server via USB / SCP, then extract:
```bash
tar -xzf autoupdate-server-linux-x64.tar.gz
cd autoupdate-server
```

### 2. Make Executables Runnable
```bash
chmod +x ./bin/autoupdate-server start.sh stop.sh status.sh
```

### 3. Start Server in Background
```bash
./start.sh
```
*To customize port or password:*
```bash
./start.sh -p 9000 -u admin -P myStrongPassword
```

### 4. Open Web Admin Dashboard
Navigate to:
```
http://<YOUR-SERVER-IP>:8080/admin/
Default Username: admin
Default Password: admin123
```

---

## Quick Start on Windows (Testing)
Run `run_windows.bat` or execute directly:
```cmd
cd autoupdate-server
bin\autoupdate-server.exe -p 8080 -d ./updates -w ./webroot
```
Open `http://localhost:8080/admin/` in your browser.

---

## AutoUpdater.NET Client Integration (C#)

In your WPF, WinForms, or Console application:

```csharp
using AutoUpdaterDotNET;

public void CheckForUpdates()
{
    // Point directly to your server's application catalog:
    AutoUpdater.Start("http://your-server:8080/Accounting/AutoUpdater.xml");

    // Or if you prefer JSON catalog:
    // AutoUpdater.Start("http://your-server:8080/Accounting/AutoUpdater.json");
}
```

---

## Repository Contents

```
├── autoupdate-server/
│   ├── src/                    # Pure C cross-platform source code
│   │   ├── main.c              # Entry point & CLI argument parser
│   │   ├── server.c            # Multithreaded socket listener
│   │   ├── http.c              # HTTP parser & Range/206 engine
│   │   ├── admin.c             # Admin dashboard & REST APIs
│   │   ├── sha256.c & md5.c    # Cryptographic hash routines
│   │   └── utils.c & compat.h  # OS abstraction (Linux/Windows)
│   ├── bin/
│   │   ├── autoupdate-server   # 100% Static Linux x86_64 ELF binary
│   │   └── autoupdate-server.exe # Native Windows x64 test executable
│   ├── webroot/admin/          # Modern English admin dashboard (HTML5/CSS3)
│   ├── updates/                # Multi-app repository (Accounting, CRM, etc.)
│   ├── start.sh / stop.sh      # Background management scripts
│   └── autoupdater.service     # Linux systemd service template
├── nginx-portable/             # Alternative: Static pre-compiled Nginx 1.26.2
├── autoupdate-server-linux-x64.tar.gz # Ready-to-deploy archive (420 KB)
└── autoupdate-server-linux-x64.zip    # Ready-to-deploy zip archive
```

---

## راهنمای فارسی (Persian Summary)

این پکیج به صورت اختصاصی برای سرورهای ایزوله لینوکسی که دسترسی به اینترنت ندارند و امکان نصب بسته با apt یا yum وجود ندارد طراحی شده است. 
- نیازی به هیچ‌گونه نصب یا پکیج ندارد (کاملاً پرتابل و استاتیک).
- از قابلیت ادامه دانلود (Resume / 206 Partial Content) به طور کامل پشتیبانی می‌کند.
- دارای پنل وب انگلیسی مدیریت و آپلود فایل، ایجاد خودکار AutoUpdater.xml و محاسبه هش SHA256 است.
- به ازای هر نرم‌افزار یک پوشه مجزا فراهم می‌کند (مانند `/Accounting/AutoUpdater.xml`).
