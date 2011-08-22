#ifndef ___COMMON_H__
#define ___COMMON_H__

typedef enum {
	SOCKS_ATYP_UNINIT = 0x00,
	SOCKS_ATYP_IPV4 = 0x01,
	SOCKS_ATYP_HOSTNAME = 0x03,
	SOCKS_ATYP_IPV6 = 0x04
} socks_atyp_e;

typedef struct {
	struct in_addr *ip4;
	struct in6_addr *ip6;
	char *hostname;
} socks_addr_u;

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
	LOAFERS_CONN_BIND_REPLY_HEADER_PREPARE,
	LOAFERS_CONN_BIND_REPLY_HEADER_READING,
	LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_PREPARE,
	LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_READING,
	LOAFERS_CONN_BIND_REPLY_PREPARE,
	LOAFERS_CONN_BIND_REPLY_READING,
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
	socks_reply_t *reply;
	socks_reply_t *bnd_reply;
	size_t addrsiz;
	// Connection state information
	loafers_conn_e state;
	// TODO: Get rid of bufptr and bufremain
	uint8_t *buf, *bufptr;
	size_t bufremain;
	bool reply_avail, bnd_reply_avail;
	bool bindwait;
	// For passing information between states.
	void *data;
};

struct _loafers_stream_t {
	void *data;
	loafers_stream_writer_f write;
	loafers_stream_reader_f read;
	loafers_stream_closer_f close;
};

loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err );

loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count );

loafers_rc_t loafers_raw_read( loafers_stream_t *stream, void *buf, size_t buflen, ssize_t *remain );
loafers_rc_t loafers_raw_write( loafers_stream_t *stream, const void *buf, size_t buflen, ssize_t *remain );

#endif
