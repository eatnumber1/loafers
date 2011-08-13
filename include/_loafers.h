#ifndef ___LOAFERS_H__
#define ___LOAFERS_H__

typedef enum {
	SOCKS_ATYP_UNINIT = 0x00,
	SOCKS_ATYP_IPV4 = 0x01,
	SOCKS_ATYP_HOSTNAME = 0x03,
	SOCKS_ATYP_IPV6 = 0x04
} socks_atyp_e;

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
	struct in_addr *ip4;
	struct in6_addr *ip6;
	char *hostname;
} socks_addr_u;

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

	LOAFERS_CONN_UNPREPARED,
	LOAFERS_CONN_CONNECTED,
	LOAFERS_CONN_INVALID
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
};

static loafers_rc_t loafers_rc( loafers_err_e err );
static loafers_rc_t loafers_rc_sys();
static loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err );

static const char *socks_strerror( loafers_err_socks_e err );

static loafers_rc_t loafers_free_addr_u( socks_atyp_e atyp, socks_addr_u addr );

static void loafers_set_prepared( loafers_conn_t *conn );
static loafers_rc_t loafers_set_atyp( loafers_conn_t *conn, socks_atyp_e atyp );

static loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count );

static loafers_rc_t loafers_write( int fd, loafers_conn_t *conn );
static loafers_rc_t loafers_read( int fd, loafers_conn_t *conn );

static loafers_rc_t loafers_conn_version_prepare( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_version_sending( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_methodsel_prepare( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_methodsel_reading( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_request_prepare( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_request_sending( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_reply_header_prepare( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_reply_header_reading( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_reply_header_hostlen_prepare( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_reply_header_hostlen_reading( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_reply_prepare( loafers_conn_t *conn, int sockfd );
static loafers_rc_t loafers_conn_reply_reading( loafers_conn_t *conn, int sockfd );

typedef loafers_rc_t (*loafers_state_handler)( loafers_conn_t *, int );
static const loafers_state_handler loafers_state_handlers[] = {
	[LOAFERS_CONN_VERSION_PREPARE] = loafers_conn_version_prepare,
	[LOAFERS_CONN_VERSION_SENDING] = loafers_conn_version_sending,
	[LOAFERS_CONN_METHODSEL_PREPARE] = loafers_conn_methodsel_prepare,
	[LOAFERS_CONN_METHODSEL_READING] = loafers_conn_methodsel_reading,
	[LOAFERS_CONN_REQUEST_PREPARE] = loafers_conn_request_prepare,
	[LOAFERS_CONN_REQUEST_SENDING] = loafers_conn_request_sending,
	[LOAFERS_CONN_REPLY_HEADER_PREPARE] = loafers_conn_reply_header_prepare,
	[LOAFERS_CONN_REPLY_HEADER_READING] = loafers_conn_reply_header_reading,
	[LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE] = loafers_conn_reply_header_hostlen_prepare,
	[LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING] = loafers_conn_reply_header_hostlen_reading,
	[LOAFERS_CONN_REPLY_PREPARE] = loafers_conn_reply_prepare,
	[LOAFERS_CONN_REPLY_READING] = loafers_conn_reply_reading
};
static const size_t loafers_nostates = sizeof(loafers_state_handlers) / sizeof(loafers_state_handler);

#endif
