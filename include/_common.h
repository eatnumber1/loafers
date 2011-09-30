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
	socks_method_e *methods;
	uint8_t nmethods;
} socks_version_t;

typedef struct {
	socks_version_e ver;
	socks_method_e method;
} socks_methodsel_t;

typedef struct {
	socks_version_e ver;
	socks_cmd_e cmd;
	socks_atyp_e atyp;
	socks_addr_u dst_addr;
	in_port_t dst_port;
	size_t addrsiz;
} socks_request_t;

typedef struct {
	socks_version_e ver;
	loafers_err_socks_e rep;
	socks_atyp_e atyp;
	socks_addr_u bnd_addr;
	in_port_t bnd_port;
} socks_reply_t;

typedef struct {
	socks_atyp_e atyp;
	socks_addr_u dst_addr;
	in_port_t dst_port;
	size_t addrsiz;
} socks_udp_request_t;

// TODO: Reduce the number of states if possible.
typedef enum {
	LOAFERS_CONN_UNPREPARED = 0,
	LOAFERS_CONN_INVALID,

	LOAFERS_CONN_GENERATE_STREAM,
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
	LOAFERS_CONN_UDP_ADDRESS,
	LOAFERS_CONN_UDP_RESOLVE,
	LOAFERS_CONN_UDP_CONNECT,

	LOAFERS_CONN_CONNECTED
} loafers_conn_e;

typedef struct {
	struct addrinfo *hints;
	char *hostname, *servname;
	loafers_stream_t *stream;
} loafers_server_info_t;

typedef struct {
	void *data;
	loafers_stream_generator_f create;
	loafers_stream_destroyer_f destroy;
} loafers_stream_generator_t;

// OPTIMIZE: Leverage talloc_pools
struct _loafers_conn_t {
	loafers_stream_generator_t *generator;
	socks_version_t ver;
	socks_request_t req;
	socks_reply_t *reply;
	socks_reply_t *bnd_reply;
	// Connection state information
	loafers_conn_e state;
	loafers_server_info_t udprelay, proxy;
	// For passing information between states.
	void *data;
	uint8_t *buf, *bufptr;
	size_t bufremain;
	size_t addrsiz;
	bool reply_avail, bnd_reply_avail;
	bool bindwait, flushing;
	ucontext_t uctx;
};

struct _loafers_stream_t {
	void *data, *wpacket, *wpacketptr;
	loafers_stream_writer_f write;
	loafers_stream_reader_f read;
	loafers_stream_closer_f close;
	struct {
		socks_udp_request_t req;
		struct _loafers_stream_t *stream;
		bool enabled;
	} udp;
	struct {
		enum {
			LOAFERS_WRITE_INACTIVE = 0,
			LOAFERS_WRITE_PURGING,
			LOAFERS_WRITE_WRITING,
			LOAFERS_WRITE_FLUSHING
		} write;
		enum {
			LOAFERS_FLUSH_INACTIVE = 0,
			LOAFERS_FLUSH_WRITING,
			LOAFERS_FLUSH_PURGING
		} flush;
	} state;
	size_t wpacketlen;
};
typedef struct _loafers_connected_state_t loafers_connected_state_t;

loafers_rc_t loafers_rc_talloc();
loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err );

loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count );

loafers_rc_t loafers_stream_read( loafers_stream_t *stream, void *buf, size_t buflen, size_t *count );
loafers_rc_t loafers_stream_write( loafers_stream_t *stream, const void *buf, size_t buflen );
loafers_rc_t loafers_stream_flush( loafers_stream_t *stream );
loafers_rc_t loafers_stream_purge( loafers_stream_t *stream );

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define loafers_talloc_name(ctx) talloc_set_name_const(ctx, __FILE__ ":" TOSTRING(__LINE__))

loafers_rc_t *loafers_get_global_rc_ptr();
#define loafers_global_rc (*loafers_get_global_rc_ptr())

#endif
