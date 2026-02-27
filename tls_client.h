#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H
#include <stdint.h>
#include <stddef.h>

extern int tls_verbose;

uint8_t *do_https_get(const char *host, int port, const char *path, size_t *out_len);

#endif
