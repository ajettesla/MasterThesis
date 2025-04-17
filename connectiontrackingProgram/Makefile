CC = gcc
CFLAGS = -Wall -O2 -pthread -D_GNU_SOURCE
LDLIBS = -lnetfilter_conntrack -lcrypto

TARGET = conntrack_logger
SRCS = conntrack_logger.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) *.o

