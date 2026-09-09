CC ?= gcc
CFLAGS ?= -O3 -Wall -pthread
TARGET = bin/autoupdate-server
SRCS = src/main.c src/server.c src/http.c src/admin.c src/utils.c src/sha256.c src/md5.c

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET) autoupdate.pid autoupdate.log

.PHONY: all clean
