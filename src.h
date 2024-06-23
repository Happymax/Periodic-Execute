//
// Project by Yunzhi Wang
//

#ifndef PERIODIC_EXECUTE_SRC_H
#define PERIODIC_EXECUTE_SRC_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <getopt.h>
#include <string.h>
#include <wordexp.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#define SHELL_FAIL 127
#define EXEC_FAIL 126
#define CMD_ARG_PARSE_FAIL (-128)
#define CHILD_TERM_SIG (-127)
// Global Variables
extern char** environ;
extern const char* PROGNAME;
extern bool SILENT, PERSEVERANT, SHELL;
extern volatile sig_atomic_t SIGNAL;

// Helper Functions
void signal_handler(int sig);
void signal_action_runner(volatile sig_atomic_t sig, struct timespec* remain);
int runner(const char* path, const char* ori_path, const char* cmd);
void arg_parser(int argc, char** argv, struct timespec* period, bool* wait, unsigned long long* count, char** path, char* ori_path, int* cmdc, char*** cmdv);
void logger(bool err, const char* str, ...);

// Print Messages
void print_help(void);
void print_usage(void);
void print_invalid(int option, const char* arg);

// Message Strings
static const char* USAGE_MSG =
        "Usage: %s [Options] <Argument> [Commands]\n\n"
        "Please Refer to the Program Manual:\n"
        "%s -h\n"
        "%s --help\n";

static const char* HELP_MSG =
        "Usage: %s [Options] <Argument> [Commands]\n"
        "--> Periodically execute the command(s), with adjustable time period.\n"
        "%s\n"
        "Timer Options:\n"
        "--> Default time period between executions is 1 minute if no timer options are provided.\n"
        "    Values provided by following timer options will add up.\n"
        "    If time period is set to 0 (minimum), the behaviour will depend on the OS scheduler.\n"
        "    Actual time period may be different due to the OS scheduler and sleep / hibernation events.\n"
        "%s%s%s\n"
        "Program Options:\n"
        "--> By default the command will be executed for the first time directly.\n"
        "\t-w, --wait\t\t\tExecute command for the first time after the first time period.\n"
        "\t-s, --shell\t\t\tUse shell command interpreter sh.\n"
        "%s%s"
        "\t    --no-exit\t\t\tIgnore failures when executing the command and keep trying next time.\n"
        "\t\t\t\t\tIf this is set, error messages will be treated as logs and print to stdout.\n"
        "\t    --no-log\t\t\tPrint no logs of this program.\n"
        "\t-h, --help\t\t\tPrint this manual.\n\n"
        "Examples:\n"
        "%s -s -c 3 \"echo 1 >> text.txt\" \"cat text.txt\"\n"
        "%s -H 2 -M 30 ./program\n"
        "%s --seconds 20 --wait \"sh ./script.sh\"\n";

static const char* EXEC_HELP_MSG =
        "\t[Commands]\t\t\tCommand(s) to execute.\n"
        "\t\t\t\t\tCommands will be executed in the sequence that they're passed over.\n"
        "\t\t\t\t\tCommands with arguments should be passed as one single argument.\n"
        "\t\t\t\t\tThis depends on the environment, usually by e.g. surrounding with \".\n"
        "\t\t\t\t\tDouble Quotation Mark needed in commands may be substituted with \\\".\n";

static const char* SEC_HELP_MSG =
        "\t-S, --seconds\t<Value>\t\tTime period in seconds.\n";

static const char* MIN_HELP_MSG =
        "\t-M, --minutes\t<Value>\t\tTime period in minutes.\n";

static const char* HUR_HELP_MSG =
        "\t-H, --hours\t<Value>\t\tTime period in hours.\n";

static const char* PATH_HELP_MSG =
        "\t-p, --path\t<Path>\t\tSet a different working directory from the current one.\n";

static const char* COUNT_HELP_MSG =
        "\t-c, --count\t<Value>\t\tMaximum number of runs. The default value is 0 (unlimited).\n";

static const char* INVALID_MSG =
        "%s: invalid argument for option '%s': %s\n";

static const char* NO_CMD_MSG =
        "%s: at least one command needs to be provided\n";

#endif //PERIODIC_EXECUTE_SRC_H
