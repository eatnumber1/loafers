#ifndef ___STREAM_H__
#define ___STREAM_H__

static loafers_rc_t loafers_stream_write_socket( void *d, const void *buf, size_t buflen, ssize_t *remain );
static loafers_rc_t loafers_stream_read_socket( void *d, void *buf, size_t buflen, ssize_t *remain );
static loafers_rc_t loafers_stream_close_socket( void *data );

#endif
