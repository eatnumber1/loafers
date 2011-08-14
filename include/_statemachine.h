#ifndef ___STATEMACHINE_H__
#define ___STATEMACHINE_H__

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

#endif
