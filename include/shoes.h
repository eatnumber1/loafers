#ifndef __SHOES_H__
#define __SHOES_H__

typedef enum {
	SOCKS_CMD_UNINIT = 0x00,
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
	SOCKS_VERSION_UNINIT = 0x00,
	SOCKS_VERSION_5 = 0x05
} socks_version_e;

typedef enum {
	SHOES_ERR_NOERR = 0x00,
	SHOES_ERR_GENFAIL = 0x01,
	SHOES_ERR_NOTALLOWED = 0x02,
	SHOES_ERR_NETUNREACH = 0x03,
	SHOES_ERR_HOSTUNREACH = 0x04,
	SHOES_ERR_CONNREFUSED = 0x05,
	SHOES_ERR_TTLEXPIRED = 0x06,
	SHOES_ERR_CMDNOTSUP = 0x07,
	SHOES_ERR_AFNOTSUP = 0x08,
	SHOES_ERR_BADPACKET,
	SHOES_ERR_EOF,
	SHOES_ERR_NEED_READ,
	SHOES_ERR_NEED_WRITE,
	// Must be last for shoes_strerror
	SHOES_ERR_ERRNO = 0xFF
} shoes_rc_e;

struct shoes_conn_t;
struct shoes_conn_t;

const char *shoes_strerror( shoes_rc_e err );
shoes_rc_e shoes_conn_alloc( struct shoes_conn_t **conn );
shoes_rc_e shoes_conn_free( struct shoes_conn_t *conn );
shoes_rc_e shoes_set_version( struct shoes_conn_t *conn, socks_version_e version );
shoes_rc_e shoes_set_methods( struct shoes_conn_t *conn, const socks_method_e *methods, uint8_t nmethods );
shoes_rc_e shoes_set_command( struct shoes_conn_t *conn, socks_cmd_e cmd );
shoes_rc_e shoes_set_hostname( struct shoes_conn_t *conn, const char hostname[static], in_port_t port );
shoes_rc_e shoes_set_sockaddr( struct shoes_conn_t *conn, const struct sockaddr *address );

bool shoes_is_connected( struct shoes_conn_t *conn );

shoes_rc_e shoes_handshake( struct shoes_conn_t *conn, int sockfd );

#endif
