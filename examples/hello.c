#import <strings.h>
#import <sys/types.h>
#import <sys/socket.h>
#import <netdb.h>
#import <stdio.h>
#import <stdlib.h>

#import "shoes.h"

int main() {
	struct addrinfo hints;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	struct addrinfo *res;
	//"173.255.236.218"
	int rc = getaddrinfo("localhost", "9050", &hints, &res);
	if( rc != 0 ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		exit(EXIT_FAILURE);
	}

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if( sock == -1 ) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	
	if( connect(sock, res->ai_addr, res->ai_addrlen) != 0 ) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	struct shoes_conn_t *conn = shoes_alloc();
	shoes_set_version(conn, SOCKS_VERSION_5);
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	shoes_set_methods(conn, methods, sizeof(methods));
	shoes_set_command(conn, SOCKS_CMD_CONNECT);
	shoes_set_hostname(conn, "localhost", 1337);
	shoes_handshake(conn, sock);
	shoes_free(conn);

	FILE *s = fdopen(sock, "a+");
	fprintf(s, "Hello World!\n");
	fclose(s);
}
