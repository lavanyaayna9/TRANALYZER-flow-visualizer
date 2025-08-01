#ifndef T2WHOIS_PROMPT_H_INCLUDED
#define T2WHOIS_PROMPT_H_INCLUDED

#include <stdbool.h>    // for bool

#define PROMPT  ">>> "

#define PROMPT_CMD_ABOUT  "about"
#define PROMPT_CMD_IP     "ip"
#define PROMPT_CMD_FIELDS "fields"
#define PROMPT_CMD_HDR    "header"
#define PROMPT_CMD_HELP   "help"
#define PROMPT_CMD_QUIT   "quit"
#define PROMPT_CMD_RAND   "rand"
#define PROMPT_CMD_RAND4  "rand4"
#define PROMPT_CMD_RAND6  "rand6"

#define PROMPT_EXIT    -1 // Command exit encountered
#define PROMPT_SUCCESS  0 // Command successfully executed
#define PROMPT_ERROR    1 // Command invalid/unknown
#define PROMPT_UNDEF    2 // Command not executed (unknown)

void prompt_init();
void run_prompt(bool prompt);

#endif // T2WHOIS_PROMPT_H_INCLUDED
