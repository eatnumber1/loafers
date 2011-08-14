#ifndef ___COMMON_H__
#define ___COMMON_H__

typedef struct {
	socks_version_e ver;
	uint8_t nmethods;
	socks_method_e *methods;
} socks_version_t;

typedef struct {
	socks_version_e ver;
	socks_method_e method;
} socks_methodsel_t;

typedef struct {
	socks_version_e ver;
	socks_cmd_e cmd;
	socks_atyp_e atyp;
	in_port_t dst_port;
	socks_addr_u dst_addr;
	size_t addrsiz;
} socks_request_t;

typedef struct {
	socks_version_e ver;
	loafers_err_socks_e rep;
	socks_atyp_e atyp;
	in_port_t bnd_port;
	socks_addr_u bnd_addr;
} socks_reply_t;

typedef enum {
	LOAFERS_CONN_UNPREPARED,
	LOAFERS_CONN_INVALID,

	LOAFERS_CONN_VERSION_PREPARE,
	LOAFERS_CONN_VERSION_SENDING,
	LOAFERS_CONN_METHODSEL_PREPARE,
	LOAFERS_CONN_METHODSEL_READING,
	LOAFERS_CONN_REQUEST_PREPARE,
	LOAFERS_CONN_REQUEST_SENDING,
	LOAFERS_CONN_REPLY_HEADER_PREPARE,
	LOAFERS_CONN_REPLY_HEADER_READING,
	LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE,
	LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING,
	LOAFERS_CONN_REPLY_PREPARE,
	LOAFERS_CONN_REPLY_READING,

	LOAFERS_CONN_CONNECTED
} loafers_conn_e;

struct _loafers_conn_t {
	socks_version_t ver;
	socks_request_t req;
	socks_reply_t reply;
	size_t addrsiz;
	// Connection state information
	loafers_conn_e state;
	uint8_t *buf, *bufptr;
	size_t bufremain;
	// For passing information between states.
	void *data;
	bool reply_avail, bindwait;
};

loafers_rc_t loafers_rc( loafers_err_e err );
loafers_rc_t loafers_rc_sys();
loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err );

loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count );

#endif
