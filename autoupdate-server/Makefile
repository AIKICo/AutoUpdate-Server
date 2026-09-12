CC ?= gcc
CFLAGS ?= -O3 -Wall -pthread -D_GNU_SOURCE -Isrc -DSQLITE_THREADSAFE=1
TARGET = bin/autoupdate-server

ifeq ($(wildcard src/sqlite3.c),)
    SRCS = src/main.c src/server.c src/http.c src/admin.c src/utils.c src/sha256.c src/md5.c src/db.c src/puff.c src/zip_reader.c
    LDFLAGS ?= -lsqlite3 -lpthread -ldl -lm
else
    SRCS = src/main.c src/server.c src/http.c src/admin.c src/utils.c src/sha256.c src/md5.c src/db.c src/sqlite3.c src/puff.c src/zip_reader.c
    LDFLAGS ?= -lpthread -ldl -lm
endif

PUBLISH_DIR = publish/linux-x64
PUBLISH_ARCHIVE = publish/autoupdate-server-linux-x64.tar.gz

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

publish-linux-x64: $(TARGET)
	@echo "==> Packaging AutoUpdate-Server for Linux x64..."
	@rm -rf $(PUBLISH_DIR) $(PUBLISH_ARCHIVE)
	@mkdir -p $(PUBLISH_DIR)
	@mkdir -p $(PUBLISH_DIR)/updates
	@cp $(TARGET) $(PUBLISH_DIR)/
	@cp -r webroot $(PUBLISH_DIR)/
	@cp run_linux.sh $(PUBLISH_DIR)/ 2>/dev/null || true
	@cp install_service.sh $(PUBLISH_DIR)/ 2>/dev/null || true
	@cp autoupdater.service $(PUBLISH_DIR)/ 2>/dev/null || true
	@cp build_linux.sh $(PUBLISH_DIR)/ 2>/dev/null || true
	@echo "[server]" > $(PUBLISH_DIR)/config.ini
	@echo "port = 8000" >> $(PUBLISH_DIR)/config.ini
	@echo "updates_dir = ./updates" >> $(PUBLISH_DIR)/config.ini
	@echo "webroot_dir = ./webroot" >> $(PUBLISH_DIR)/config.ini
	@chmod +x $(PUBLISH_DIR)/autoupdate-server
	@chmod +x $(PUBLISH_DIR)/*.sh 2>/dev/null || true
	@mkdir -p publish
	@tar -czf $(PUBLISH_ARCHIVE) -C publish linux-x64
	@echo "==> Linux x64 Release Packaged Successfully:"
	@echo "    Folder:  $(PUBLISH_DIR)/"
	@echo "    Archive: $(PUBLISH_ARCHIVE)"

clean:
	rm -rf $(TARGET) bin obj publish autoupdate.pid autoupdate.log autoupdate.db

.PHONY: all publish-linux-x64 clean

