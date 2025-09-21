CC = zig cc
LDFLAGS = -lcurl
TARGET = cloudflare-ddns.out
SRC = cloudflare-ddns.c
HEADERS = config.h

.PHONY: build clean

build: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(CC) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)