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

typedef struct {
	socks_atyp_e atyp;
	socks_addr_u dst_addr;
	in_port_t dst_port;
	size_t addrsiz;
} socks_udp_request_t;

typedef enum {
	LOAFERS_CONN_UNPREPARED,
	LOAFERS_CONN_INVALID,

	LOAFERS_CONN_VERSION_PREPARE,
	LOAFERS_CONN_VERSION_SENDING,
	LOAFERS_CONN_VERSION_FLUSHING,
	LOAFERS_CONN_METHODSEL_PREPARE,
	LOAFERS_CONN_METHODSEL_READING,
	LOAFERS_CONN_REQUEST_PREPARE,
	LOAFERS_CONN_REQUEST_SENDING,
	LOAFERS_CONN_REQUEST_FLUSHING,
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

// OPTIMIZE: Leverage talloc_pools
struct _loafers_conn_t {
	socks_version_t ver;
	socks_request_t req;
	socks_reply_t *reply;
	socks_reply_t *bnd_reply;
	size_t addrsiz;
	// Connection state information
	loafers_conn_e state;
	uint8_t *buf, *bufptr;
	size_t bufremain;
	bool reply_avail, bnd_reply_avail;
	bool bindwait, flushing;
	// For passing information between states.
	void *data;
};

struct _loafers_stream_t {
	void *data, *wpacket, *wpacketptr;
	size_t wpacketlen;
	bool udp;
	socks_udp_request_t udp_req;
	loafers_stream_writer_f write;
	loafers_stream_reader_f read;
	loafers_stream_closer_f close;
};

loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err );

loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count );

loafers_rc_t loafers_stream_read( loafers_stream_t *stream, void *buf, size_t buflen, size_t *count );
loafers_rc_t loafers_stream_write( loafers_stream_t *stream, const void *buf, size_t buflen );
loafers_rc_t loafers_stream_flush( loafers_stream_t *stream );
loafers_rc_t loafers_stream_purge( loafers_stream_t *stream );

void loafers_talloc_name( void *ctx, const char *str );
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define loafers_talloc_name(ctx) loafers_talloc_name(ctx, __FILE__ ":" TOSTRING(__LINE__))

#endif
