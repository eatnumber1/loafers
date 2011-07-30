#ifndef ___SHOES_H__
#define ___SHOES_H__

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
	shoes_err_socks_e rep;
	socks_atyp_e atyp;
	in_port_t bnd_port;
	socks_addr_u bnd_addr;
} socks_reply_t;

typedef enum {
	SHOES_CONN_VERSION_PREPARE,
	SHOES_CONN_VERSION_SENDING,
	SHOES_CONN_METHODSEL_PREPARE,
	SHOES_CONN_METHODSEL_READING,
	SHOES_CONN_REQUEST_PREPARE,
	SHOES_CONN_REQUEST_SENDING,
	SHOES_CONN_REPLY_HEADER_PREPARE,
	SHOES_CONN_REPLY_HEADER_READING,
	SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE,
	SHOES_CONN_REPLY_HEADER_HOSTLEN_READING,
	SHOES_CONN_REPLY_PREPARE,
	SHOES_CONN_REPLY_READING,

	SHOES_CONN_UNPREPARED,
	SHOES_CONN_CONNECTED,
	SHOES_CONN_INVALID
} shoes_conn_e;

struct _shoes_conn_t {
	socks_version_t ver;
	socks_request_t req;
	socks_reply_t reply;
	size_t addrsiz;
	// Connection state information
	shoes_conn_e state;
	uint8_t *buf, *bufptr;
	size_t bufremain;
	// For passing information between states.
	void *data;
};

static shoes_rc_t shoes_rc( shoes_err_e err );
static shoes_rc_t shoes_rc_sys();
static shoes_rc_t shoes_rc_socks( shoes_err_e err, shoes_err_socks_e socks_err );

static const char *socks_strerror( shoes_err_socks_e err );

static shoes_rc_t shoes_free_addr_u( socks_atyp_e atyp, socks_addr_u addr );

static void shoes_set_prepared( shoes_conn_t *conn );
static shoes_rc_t shoes_set_atyp( shoes_conn_t *conn, socks_atyp_e atyp );

static shoes_rc_t shoes_connbuf_alloc( shoes_conn_t *conn, size_t count );

static shoes_rc_t shoes_write( int fd, shoes_conn_t *conn );
static shoes_rc_t shoes_read( int fd, shoes_conn_t *conn );

static shoes_rc_t shoes_conn_version_prepare( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_version_sending( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_methodsel_prepare( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_methodsel_reading( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_request_prepare( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_request_sending( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_reply_header_prepare( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_reply_header_reading( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_reply_header_hostlen_prepare( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_reply_header_hostlen_reading( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_reply_prepare( shoes_conn_t *conn, int sockfd );
static shoes_rc_t shoes_conn_reply_reading( shoes_conn_t *conn, int sockfd );

typedef shoes_rc_t (*shoes_state_handler)( shoes_conn_t *, int );
static const shoes_state_handler shoes_state_handlers[] = {
	[SHOES_CONN_VERSION_PREPARE] = shoes_conn_version_prepare,
	[SHOES_CONN_VERSION_SENDING] = shoes_conn_version_sending,
	[SHOES_CONN_METHODSEL_PREPARE] = shoes_conn_methodsel_prepare,
	[SHOES_CONN_METHODSEL_READING] = shoes_conn_methodsel_reading,
	[SHOES_CONN_REQUEST_PREPARE] = shoes_conn_request_prepare,
	[SHOES_CONN_REQUEST_SENDING] = shoes_conn_request_sending,
	[SHOES_CONN_REPLY_HEADER_PREPARE] = shoes_conn_reply_header_prepare,
	[SHOES_CONN_REPLY_HEADER_READING] = shoes_conn_reply_header_reading,
	[SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE] = shoes_conn_reply_header_hostlen_prepare,
	[SHOES_CONN_REPLY_HEADER_HOSTLEN_READING] = shoes_conn_reply_header_hostlen_reading,
	[SHOES_CONN_REPLY_PREPARE] = shoes_conn_reply_prepare,
	[SHOES_CONN_REPLY_READING] = shoes_conn_reply_reading
};
static const size_t shoes_nostates = sizeof(shoes_state_handlers) / sizeof(shoes_state_handler);

#endif
