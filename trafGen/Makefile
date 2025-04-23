CC      = gcc
CFLAGS  = -Wall -pthread

all: tcp_server tcp_client udp_client udp_server

tcp_server: tcp_server.c
	$(CC) $(CFLAGS) -o $@ tcp_server.c

udp_server: udp_server.c
	$(CC) $(CFLAGS) -o $@ udp_server.c

udp_client: udp_client.c
	$(CC) $(CFLAGS) -o $@ udp_client.c

tcp_client: tcp_client.c
	$(CC) $(CFLAGS) -o $@ tcp_client.c

clean:
	rm -f tcp_server tcp_client udp_server udp_client 
