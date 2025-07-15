CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -Wno-deprecated-declarations
LDFLAGS = -lcrypto

# OpenSSL paths for macOS Homebrew
OPENSSL_PREFIX = $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(OPENSSL_PREFIX),)
    CFLAGS += -I$(OPENSSL_PREFIX)/include
    LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

TARGET = picocert_tests
SOURCES = picocert_tests.c
HEADERS = picocert.h

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

example: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

help:
	@echo "Available targets:"
	@echo "  all     - Build the test executable"
	@echo "  test    - Build and run the tests"
	@echo "  clean   - Remove built files"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - OpenSSL development libraries"
	@echo "  - On macOS: brew install openssl@3"
	@echo "  - On Ubuntu/Debian: sudo apt-get install libssl-dev"
	@echo "  - GCC compiler with C99 support"