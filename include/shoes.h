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
	SHOES_ERR_NOERR,
	SHOES_ERR_BADPACKET,
	SHOES_ERR_EOF,
	SHOES_ERR_NEED_READ,
	SHOES_ERR_NEED_WRITE,
	SHOES_ERR_ERRNO,
	SHOES_ERR_SOCKS,
	SHOES_ERR_BADSTATE
} shoes_err_e;

typedef enum {
	SOCKS_ERR_NOERR = 0x00,
	SOCKS_ERR_GENFAIL = 0x01,
	SOCKS_ERR_NOTALLOWED = 0x02,
	SOCKS_ERR_NETUNREACH = 0x03,
	SOCKS_ERR_HOSTUNREACH = 0x04,
	SOCKS_ERR_CONNREFUSED = 0x05,
	SOCKS_ERR_TTLEXPIRED = 0x06,
	SOCKS_ERR_CMDNOTSUP = 0x07,
	SOCKS_ERR_AFNOTSUP = 0x08
} shoes_err_socks_e;

// This must be deep-copiable with simple assignment (no pointers!)
typedef struct {
	shoes_err_e code;
	union {
		int sys_errno;
		shoes_err_socks_e socks_errno;
	};
} shoes_rc_t;

struct _shoes_conn_t;
typedef struct _shoes_conn_t shoes_conn_t;

shoes_err_e shoes_errno( shoes_rc_t err );
shoes_err_socks_e shoes_socks_errno( shoes_rc_t err );
int shoes_sys_errno( shoes_rc_t err );

const char *shoes_strerror( shoes_rc_t err );
shoes_rc_t shoes_conn_alloc( shoes_conn_t **conn );
shoes_rc_t shoes_conn_free( shoes_conn_t *conn );
shoes_rc_t shoes_set_version( shoes_conn_t *conn, socks_version_e version );
shoes_rc_t shoes_set_methods( shoes_conn_t *conn, uint8_t nmethods, const socks_method_e methods[static nmethods] );
shoes_rc_t shoes_set_command( shoes_conn_t *conn, socks_cmd_e cmd );
shoes_rc_t shoes_set_hostname( shoes_conn_t *conn, const char hostname[static], in_port_t port );
shoes_rc_t shoes_set_sockaddr( shoes_conn_t *conn, const struct sockaddr *address );

bool shoes_is_connected( shoes_conn_t *conn );

shoes_rc_t shoes_handshake( shoes_conn_t *conn, int sockfd );

#endif
