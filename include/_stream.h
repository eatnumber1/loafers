#ifndef ___STREAM_H__
#define ___STREAM_H__

static loafers_rc_t loafers_stream_write_socket( void *d, const void *buf, size_t buflen, ssize_t *remain, void *error );
static loafers_rc_t loafers_stream_read_socket( void *d, void *buf, size_t buflen, ssize_t *remain, void *error );

typedef struct {
	int sock;
	void *bufptr;
	size_t bufremain;
} loafers_stream_socket_data_t;

#endif
