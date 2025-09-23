CC = zig cc
LDFLAGS = -lcurl
TARGET = cloudflare-ddns.out
SRC = cloudflare-ddns.c 

.PHONY: build clean

build: $(TARGET)

$(TARGET): $(SRC) 
	$(CC) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)