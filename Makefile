CC = gcc
CFLAGS = -Wall -Wextra -O3
LDFLAGS = -lssl -lcrypto -lpthread -lyaml
SOURCES = server.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = server

.PHONY: all clean run keygen
all: $(TARGET)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
clean:
	rm -f $(OBJECTS) $(TARGET)
clean-all: clean
	rm -f cert.pem key.pem
$(OBJECTS): $(SOURCES)
	$(CC) $(CFLAGS) -c $< -o $@
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)	
run: $(TARGET)
	./$(TARGET)
keygen: cert.pem key.pem
	openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
