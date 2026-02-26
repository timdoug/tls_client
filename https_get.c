/* https_get.c — CLI wrapper for tls_client library */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_client.h"

static void __attribute__((noreturn)) die(const char *msg) { fprintf(stderr, "FATAL: %s\n", msg); exit(1); }

int main(int argc, char **argv) {
    int arg = 1;
    if(arg < argc && strcmp(argv[arg], "-v") == 0) { tls_verbose = 1; arg++; }
    if(arg != argc - 1) { fprintf(stderr, "Usage: %s [-v] https://host[:port]/path\n", argv[0]); return 1; }
    const char *url = argv[arg];
    if(strncmp(url, "https://", 8) != 0) die("URL must start with https://");
    const char *hoststart = url + 8;
    const char *slash = strchr(hoststart, '/');
    const char *path = slash ? slash : "/";
    char host[256];
    int port = 443;
    size_t hostlen = slash ? (size_t)(slash - hoststart) : strlen(hoststart);
    if(hostlen >= sizeof(host)) die("hostname too long");
    memcpy(host, hoststart, hostlen);
    host[hostlen] = '\0';
    /* check for :port */
    char *colon = strchr(host, ':');
    if(colon) { port = (int)strtol(colon + 1, NULL, 10); *colon = '\0'; }
    size_t len;
    uint8_t *body = do_https_get(host, port, path, &len);
    if(body) {
        fwrite(body, 1, len, stdout);
        free(body);
    }
    return 0;
}
