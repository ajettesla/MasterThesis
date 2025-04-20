CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = conntrackAnalysis
SRC = conntrackAnalysis.c
DEPS = uthash.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(DEPS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

