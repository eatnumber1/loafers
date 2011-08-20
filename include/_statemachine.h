#ifndef ___STATEMACHINE_H__
#define ___STATEMACHINE_H__

static loafers_rc_t loafers_conn_write( loafers_stream_t *stream, loafers_conn_t *conn );
static loafers_rc_t loafers_conn_read( loafers_stream_t *stream, loafers_conn_t *conn );

static loafers_rc_t loafers_conn_version_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_version_sending( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_methodsel_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_methodsel_reading( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_request_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_request_sending( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_bind_reply_header_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_bind_reply_header_reading( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_bind_reply_header_hostlen_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_bind_reply_header_hostlen_reading( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_bind_reply_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_bind_reply_reading( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_reply_header_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_reply_header_reading( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_reply_header_hostlen_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_reply_header_hostlen_reading( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_reply_prepare( loafers_conn_t *conn, loafers_stream_t *stream );
static loafers_rc_t loafers_conn_reply_reading( loafers_conn_t *conn, loafers_stream_t *stream );

static loafers_rc_t loafers_conn_generic_reply_header_prepare( loafers_conn_t *conn, loafers_stream_t *stream, bool *avail_flag, socks_reply_t **reply, loafers_conn_e next_state );
static loafers_rc_t loafers_conn_generic_reply_header_reading( loafers_conn_t *conn, loafers_stream_t *stream, socks_reply_t *reply, const loafers_conn_e next_states[const static 2] );
static loafers_rc_t loafers_conn_generic_reply_header_hostlen_prepare( loafers_conn_t *conn, loafers_stream_t *stream, loafers_conn_e next_state );
static loafers_rc_t loafers_conn_generic_reply_header_hostlen_reading( loafers_conn_t *conn, loafers_stream_t *stream, loafers_conn_e next_state );
static loafers_rc_t loafers_conn_generic_reply_prepare( loafers_conn_t *conn, loafers_stream_t *stream, socks_reply_t *reply, loafers_conn_e next_state );
static loafers_rc_t loafers_conn_generic_reply_reading( loafers_conn_t *conn, loafers_stream_t *stream, bool *avail_flag, socks_reply_t *reply, loafers_conn_e next_state );

typedef loafers_rc_t (*loafers_state_handler)( loafers_conn_t *, loafers_stream_t * );

#endif
