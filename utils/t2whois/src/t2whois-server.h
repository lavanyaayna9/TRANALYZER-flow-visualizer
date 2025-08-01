#ifndef T2WHOIS_SERVER_H_INCLUDED
#define T2WHOIS_SERVER_H_INCLUDED

#include <stdint.h> // for uint16_t

#define T2WHOIS_SERVER_IP   "127.0.0.1"
#define T2WHOIS_SERVER_PORT 6666
#define T2WHOIS_MAX_CLIENTS 10 // Maximum number of clients allowed

void run_server(const char *addr, uint16_t port);

#endif // T2WHOIS_SERVER_H_INCLUDED
