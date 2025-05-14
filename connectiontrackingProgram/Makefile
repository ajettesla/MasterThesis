# Makefile for conntrack_logger

# Installation prefix (default: /usr/local)
PREFIX    ?= /usr/local

# Compiler and flags
CC        := gcc
CFLAGS    := -Wall -Wextra -O2 -g -I$(PREFIX)/include
LDFLAGS   := -L$(PREFIX)/lib -lnetfilter_conntrack -lblake3 -lpthread

# Targets and sources
SRC       := conntrack_logger.c
OBJ       := $(SRC:.c=.o)
TARGET    := conntrack_logger

# Phony targets
.PHONY: all clean install uninstall

# Default build target
all: $(TARGET)

# Link object files into the final executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile C source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install binary into $(PREFIX)/bin
install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/

# Remove installed binary
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

# Clean build artifacts
clean:
	rm -f $(OBJ) $(TARGET)
