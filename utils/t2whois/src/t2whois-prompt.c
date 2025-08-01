#include "t2whois-prompt.h"
#include "t2whois.h"

#include <ctype.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "t2log.h"
#include "t2utils.h"


#define T2WHOIS_STRCASECMP(str1, str2) \
    (strncasecmp((str1), (str2), sizeof((str2))-1) == 0)


// Static functions prototypes

static int_fast8_t exec_prompt_cmd(const char *cmd);
static char *prompt_generator(const char *text, int state);
static char **prompt_completion(const char *text, int start, int end);


void prompt_init() {
    rl_attempted_completion_function = prompt_completion;
}


static void prompt_help() {
    printf("The following commands are available:\n");
    printf("    " BOLD "%-6s" NOCOLOR "     get information about the IPv4/6 address 'ip'\n", PROMPT_CMD_IP);
#if T2WHOIS_RANDOM == 1
    printf("    " BOLD "%-6s" NOCOLOR "     get information about a random IPv4/6 address\n", PROMPT_CMD_RAND);
    printf("    " BOLD "%-6s" NOCOLOR "     get information about a random IPv4 address\n", PROMPT_CMD_RAND4);
    printf("    " BOLD "%-6s" NOCOLOR "     get information about a random IPv6 address\n", PROMPT_CMD_RAND6);
#endif
    printf("    " BOLD "%-6s" NOCOLOR "     display the columns header\n", PROMPT_CMD_HDR);
    printf("    " BOLD "%-6s" NOCOLOR "     list the available fields\n", PROMPT_CMD_FIELDS);
    printf("    " BOLD "%-6s" NOCOLOR "     show info about the database\n", PROMPT_CMD_ABOUT);
    printf("    " BOLD "%-6s" NOCOLOR "     show this help\n", PROMPT_CMD_HELP);
    printf("    " BOLD "%-6s" NOCOLOR "     exit the program\n", PROMPT_CMD_QUIT);
}


void run_prompt(bool prompt) {
    const char * const prefix = (prompt ? PROMPT : "");

    char *line;
    while ((line = readline(prefix))) {
        const size_t linelen = strlen(line) + 1;
        if (linelen > 1) {
            add_history(line);
            switch (exec_prompt_cmd(line)) {
                case PROMPT_EXIT:
                    free(line);
                    return;
                case PROMPT_SUCCESS:
                case PROMPT_ERROR:
                    break;
                default:
                    process_ip(stdout, line);
                    break;
            }
        }
        free(line);
    }
}


static int_fast8_t exec_prompt_cmd(const char *cmd) {
    int_fast8_t status = PROMPT_SUCCESS;

    if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_QUIT)) {
        status = PROMPT_EXIT;
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_IP)) {
        printf("Enter an IPv4 or IPv6 address as follows: 1.2.3.4, ff80::\n");
#if T2WHOIS_RANDOM == 1
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_RAND4)) {
        test_random_ipv4();
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_RAND6)) {
        test_random_ipv6();
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_RAND)) {
        test_random_ip();
#endif
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_HDR))  {
        print_geoinfo_oneline_hdr(stdout);
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_FIELDS)) {
        print_fields();
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_ABOUT)) {
        print_dbs_info();
    } else if (T2WHOIS_STRCASECMP(cmd, PROMPT_CMD_HELP) || *cmd == '?') {
        prompt_help();
    } else if (!isxdigit(*cmd) && *cmd != ':') {
        T2_ERR("Unrecognized command '%s'", cmd);
        status = PROMPT_ERROR;
    } else {
        status = PROMPT_UNDEF;
    }

    return status;
}


static char *prompt_generator(const char *text, int state) {

    static const char * const prompt_cmds[] = {
        PROMPT_CMD_ABOUT,
        PROMPT_CMD_FIELDS,
        PROMPT_CMD_HDR,
        PROMPT_CMD_HELP,
        PROMPT_CMD_QUIT,
#if T2WHOIS_RANDOM == 1
        PROMPT_CMD_RAND,
        PROMPT_CMD_RAND4,
        PROMPT_CMD_RAND6,
#endif
        NULL
    };

    static int list_index, len;
    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    const char *name;
    while ((name = prompt_cmds[list_index++])) {
        if (strncmp(name, text, len) == 0) {
            return strdup(name);
        }
    }

    return NULL;
}


static char **prompt_completion(const char *text, int start UNUSED, int end UNUSED) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, prompt_generator);
}
