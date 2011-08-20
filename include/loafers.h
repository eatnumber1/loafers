#ifndef __LOAFERS_H__
#define __LOAFERS_H__

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
	LOAFERS_ERR_NOERR,
	LOAFERS_ERR_NOERR_BINDWAIT,
	LOAFERS_ERR_BADPACKET,
	LOAFERS_ERR_EOF,
	LOAFERS_ERR_NEED_READ,
	LOAFERS_ERR_NEED_WRITE,
	LOAFERS_ERR_ERRNO,
	LOAFERS_ERR_SOCKS,
	LOAFERS_ERR_BADSTATE,
	LOAFERS_ERR_NOTAVAIL,
	LOAFERS_ERR_STREAM,
	LOAFERS_ERR_TALLOC
} loafers_err_e;

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
} loafers_err_socks_e;

// This must be deep-copiable with simple assignment (no pointers!)
typedef struct {
	loafers_err_e code;
	union {
		int sys_errno;
		loafers_err_socks_e socks_errno;
	};
} loafers_rc_t;

typedef loafers_rc_t (*loafers_stream_writer_f)( void *, const void *, size_t, ssize_t *, void * );
typedef loafers_rc_t (*loafers_stream_reader_f)( void *, void *, size_t, ssize_t *, void * );

struct _loafers_stream_t;
typedef struct _loafers_stream_t loafers_stream_t;

struct _loafers_conn_t;
typedef struct _loafers_conn_t loafers_conn_t;

__attribute__((visibility("default"))) loafers_err_e loafers_errno( loafers_rc_t err );
__attribute__((visibility("default"))) loafers_err_socks_e loafers_socks_errno( loafers_rc_t err );
__attribute__((visibility("default"))) int loafers_sys_errno( loafers_rc_t err );
__attribute__((visibility("default"))) loafers_rc_t
	loafers_rc( loafers_err_e err ),
	loafers_rc_sys();

__attribute__((visibility("default"))) const char *loafers_strerror( loafers_rc_t err );
__attribute__((visibility("default"))) loafers_rc_t
	loafers_conn_alloc( loafers_conn_t **conn ),
	loafers_conn_free( loafers_conn_t **conn ),
	loafers_set_version( loafers_conn_t *conn, socks_version_e version ),
	loafers_set_methods( loafers_conn_t *conn, uint8_t nmethods, const socks_method_e methods[static nmethods] ),
	loafers_set_command( loafers_conn_t *conn, socks_cmd_e cmd ),
	loafers_set_hostname( loafers_conn_t *conn, const char *hostname, in_port_t port ),
	loafers_set_sockaddr( loafers_conn_t *conn, const struct sockaddr *address ),
	loafers_get_external_addr( loafers_conn_t *conn, char **addr ),
	loafers_get_external_port( loafers_conn_t *conn, in_port_t *port ),
	loafers_get_remote_addr( loafers_conn_t *conn, char **addr ),
	loafers_get_remote_port( loafers_conn_t *conn, in_port_t *port ),
	loafers_get_listen_addr( loafers_conn_t *conn, char **addr ),
	loafers_get_listen_port( loafers_conn_t *conn, in_port_t *port );

__attribute__((visibility("default"))) loafers_rc_t
	loafers_stream_socket_alloc( loafers_stream_t **stream, int sockfd ),
	loafers_stream_custom_alloc( loafers_stream_t **stream, void *data, loafers_stream_writer_f writer, loafers_stream_reader_f reader, void *error ),
	loafers_stream_free( loafers_stream_t **stream );

__attribute__((visibility("default"))) void *loafers_get_stream_error( const loafers_stream_t *stream );

__attribute__((visibility("default"))) loafers_rc_t loafers_handshake( loafers_conn_t *conn, loafers_stream_t *stream );

#endif
