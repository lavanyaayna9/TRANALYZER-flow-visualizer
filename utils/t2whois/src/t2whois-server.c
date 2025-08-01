#include "t2whois-server.h"
#include "t2whois-utils.h"
#include "t2whois.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "t2log.h"
#include "t2utils.h"



static void *handle_client(void *arg) {
    const int tid = *(int*)arg;
    FILE *file = (FILE*)&tid;

    const size_t buflen = INET6_ADDRSTRLEN;
    char *buf = calloc(buflen+1, sizeof(char));
    if (UNLIKELY(!buf)) {
        T2_ERR("Failed to allocate memory for client buffer");
        close(tid);
        pthread_exit(NULL);
        return NULL;
    }

    if (oneline && print_header) {
        print_geoinfo_oneline_hdr(file);
    }

    while (read_line(tid, buf, buflen, true) > 0) {
        process_ip(file, buf);
    }

    free(buf);

    struct sockaddr_in client;
    socklen_t i = sizeof(client);
    if (getpeername(tid, (struct sockaddr*)&client, &i) == 0) {
        char cli_ip[INET6_ADDRSTRLEN];
        if (client.sin_family == AF_INET) {
            inet_ntop(AF_INET, &(client.sin_addr), cli_ip, INET_ADDRSTRLEN);
            T2_FINF(stdout, "Client left: %s:%u", cli_ip, ntohs(client.sin_port));
        } else if (client.sin_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6*) &client;
            inet_ntop(AF_INET6, &(addr->sin6_addr), cli_ip, INET6_ADDRSTRLEN);
            T2_FINF(stdout, "Client left: %s:%u", cli_ip, ntohs(client.sin_port));
        } else {
            T2_PERR(T2WHOIS, "Client connected with unknown address family %u left", client.sin_family);
        }
    }

    close(tid);
    pthread_exit(NULL);
}


void run_server(const char *addr, uint16_t port) {
    int sfd_s;
    if ((sfd_s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        T2_PERR(T2WHOIS, "%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    const struct hostent * const host = gethostbyname(addr);

    struct sockaddr_in server = {};
    server.sin_family = AF_INET;
    server.sin_addr = *(struct in_addr*)host->h_addr;
    server.sin_port = htons(port);

    if (bind(sfd_s, (struct sockaddr*)&server, sizeof(server)) < 0) {
        T2_PERR(T2WHOIS, "%s", strerror(errno));
        close(sfd_s);
        exit(EXIT_FAILURE);
    }

    listen(sfd_s, T2WHOIS_MAX_CLIENTS);
    T2_FINF(stdout, "Server listening on %s:%" PRIu16, addr, port);

    pthread_attr_t attr;
    pthread_attr_init(&attr);

    pthread_t threads;
    struct sockaddr_in client;
    socklen_t i = sizeof(client);
    char cli_ip[INET6_ADDRSTRLEN];

    int cl_s;
    while ((cl_s = accept(sfd_s, (struct sockaddr*)&client, &i))) {
        if (client.sin_family == AF_INET) {
            inet_ntop(AF_INET, &(client.sin_addr), cli_ip, INET_ADDRSTRLEN);
        } else if (client.sin_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6*) &client;
            inet_ntop(AF_INET6, &(addr->sin6_addr), cli_ip, INET6_ADDRSTRLEN);
        } else {
            T2_PERR(T2WHOIS, "Client attempted to connect with unknown address family %u", client.sin_family);
            continue;
        }
        T2_FINF(stdout, "New client: %s:%u %d", cli_ip, ntohs(client.sin_port), cl_s);
        pthread_create(&threads, &attr, handle_client, &cl_s);
    }

    close(sfd_s);
}
