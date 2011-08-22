#ifndef ___STREAM_H__
#define ___STREAM_H__

static loafers_rc_t loafers_stream_write_socket( void *data, const void *buf, size_t buflen, ssize_t *remain );
static loafers_rc_t loafers_stream_read_socket( void *data, void *buf, size_t buflen, ssize_t *remain );
static loafers_rc_t loafers_stream_close_socket( void *data );

static loafers_rc_t loafers_stream_write_FILE( void *data, const void *buf, size_t buflen, ssize_t *remain );
static loafers_rc_t loafers_stream_read_FILE( void *data, void *buf, size_t buflen, ssize_t *remain );
static loafers_rc_t loafers_stream_close_FILE( void *data );

#endif
