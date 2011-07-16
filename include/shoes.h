#ifndef SHOES_H
#define SHOES_H

#import <stdbool.h>

typedef enum {
	SOCKS_CMD_CONNECT = 0x01,
	SOCKS_CMD_BIND = 0x02,
	SOCKS_CMD_UDP_ASSOCIATE = 0x03
} socks_cmd_e;

typedef enum {
	SOCKS_METHOD_NONE = 0x00,
	SOCKS_METHOD_GSSAPI = 0x01,
	SOCKS_METHOD_USERPASS = 0x02
} socks_method_e;

typedef enum {
	SOCKS_VERSION_5 = 0x05
} socks_version_e;

struct shoes_conn_t;

struct shoes_conn_t *shoes_alloc();
bool shoes_free( struct shoes_conn_t *conn );
bool shoes_set_version( struct shoes_conn_t *conn, socks_version_e version );
bool shoes_set_methods( struct shoes_conn_t *conn, const socks_method_e *methods, uint8_t nmethods );
bool shoes_set_command( struct shoes_conn_t *conn, socks_cmd_e cmd );
bool shoes_set_hostname( struct shoes_conn_t *conn, const char *hostname, in_port_t port );
bool shoes_set_sockaddr( struct shoes_conn_t *conn, const struct sockaddr *address );
bool shoes_handshake_f( struct shoes_conn_t *conn, FILE *sock );
bool shoes_handshake( struct shoes_conn_t *conn, int socket );

//int shoes_connect( const struct shoes_conn_t *conn, int socket, const struct sockaddr *proxyaddr, socklen_t proxyaddr_len );

#endif
