CC      = gcc
CFLAGS  = -Wall -pthread

all: tcp_server tcp_client udp_client udp_server tcp_client_sub udp_client_sub tcp_server_adp tcp_server_er tcp_client_er

tcp_server: tcp_server.c
	$(CC) $(CFLAGS) -o $@ tcp_server.c

tcp_server_adp: tcp_server_adp.c
	$(CC) $(CFLAGS) -o $@ tcp_server_adp.c

udp_server: udp_server.c
	$(CC) $(CFLAGS) -o $@ udp_server.c

udp_client: udp_client.c
	$(CC) $(CFLAGS) -o $@ udp_client.c

udp_client_sub: udp_client_sub.c
	$(CC) $(CFLAGS) -o $@ udp_client_sub.c

tcp_client: tcp_client.c
	$(CC) $(CFLAGS) -o $@ tcp_client.c

tcp_client_sub: tcp_client_sub.c
	$(CC) $(CFLAGS) -o $@ tcp_client_sub.c

tcp_client_er: tcp_client_er.c
	$(CC) $(CFLAGS) -o $@ tcp_client_er.c

tcp_server_er: tcp_server_er.c
	$(CC) $(CFLAGS) -o $@ tcp_server_er.c

clean:
	rm -f tcp_server tcp_client udp_server udp_client tcp_server_er tcp_client_er
