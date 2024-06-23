#include "src.h"

const char* PROGNAME;
bool SILENT, PERSEVERANT, SHELL;
volatile sig_atomic_t SIGNAL;

int main(int argc, char** argv) {
    struct timespec period = {0,0}, remain = {0,0};
    char ori_path[PATH_MAX];
    bool wait;
    unsigned long long count;
    char* path;
    int cmdc;
    char** cmdv;
    arg_parser(argc, argv, &period, &wait, &count, &path, ori_path, &cmdc, &cmdv);
    struct sigaction sa = {signal_handler, 0, 0};
    SIGNAL = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGCONT, &sa, NULL);

    // Run
    int ret;
    unsigned long long ctr = 0;
    time_t next_time;
    struct tm next_tm = {0};
    if (wait) {
        // Calculate first scheduled time
        time(&next_time);
        next_time += period.tv_sec; // ignore nsec as only sec is used for period
        localtime_r(&next_time, &next_tm);
        logger(false, "First execution scheduled at: [%04d-%02d-%02d-%02d:%02d:%02d]",
               next_tm.tm_year + 1900, next_tm.tm_mon + 1, next_tm.tm_mday, next_tm.tm_hour, next_tm.tm_min, next_tm.tm_sec);
        nanosleep(&period, &remain);
    }
    do {
        while (SIGNAL) {
            signal_action_runner(SIGNAL, &remain);
        }
        ctr++;
        if (count) {
            logger(false, "Executing attempt (%d/%d) ...", ctr, count);
        } else {
            logger(false, "Executing attempt (%d) ...", ctr);
        }
        for (int i = 0; i < cmdc; i++) {
            ret = runner(path, ori_path, cmdv[i]);
            if (ret < 0 || ret == SHELL_FAIL || ret == EXEC_FAIL) {
                char* err_msg;
                switch (ret) {
                    case SHELL_FAIL:
                        err_msg = "Shell execution failed";
                        break;
                    case EXEC_FAIL:
                        err_msg = "Process could not start";
                        break;
                    case CMD_ARG_PARSE_FAIL:
                        err_msg = "Could not parse command arguments";
                        break;
                    case CHILD_TERM_SIG:
                        err_msg = "Process is terminated by a signal";
                        break;
                    default:
                        err_msg = strerror(errno);
                        break;
                }
                if (count) {
                    logger(true, "Execution attempt (%d/%d) failed: %s", ctr, count, err_msg);
                } else {
                    logger(true, "Execution attempt (%d) failed: %s", ctr, err_msg);
                }
                break;
            }
        }
        if (ret >= 0 && ret != EXEC_FAIL && ret != SHELL_FAIL) {
            if (count) {
                logger(false, "Execution attempt (%d/%d) completed", ctr, count);
            } else {
                logger(false, "Execution attempt (%d) completed", ctr);
            }
        } else if (!PERSEVERANT) {
            logger(false, "Exit due to failure");
            exit(EXIT_FAILURE);
        }
        if (count && ctr >= count) {
            logger(false, "Exit with all executions scheduled completed");
            return EXIT_SUCCESS;
        }
        // Calculate next scheduled time
        time(&next_time);
        next_time += period.tv_sec; // ignore nsec as only sec is used for period
        localtime_r(&next_time, &next_tm);
        logger(false, "Next execution scheduled at: [%04d-%02d-%02d-%02d:%02d:%02d]",
               next_tm.tm_year + 1900, next_tm.tm_mon + 1, next_tm.tm_mday, next_tm.tm_hour, next_tm.tm_min, next_tm.tm_sec);
        nanosleep(&period, &remain);
    } while (true);
}

/* -------------------------------------------------- */

void signal_handler(int sig) {
    // Needs to be async-signal-safe
    SIGNAL = sig;
}

void signal_action_runner(volatile sig_atomic_t sig, struct timespec* remain) {
    // Not called as signal handler, doesn't need to be async-signal-safe
    struct timespec rescheduled_time;
    struct tm rescheduled_tm = {0};
    switch (sig) {
        case SIGINT:
            logger(false, "Exit due to signal: %s", strsignal(sig));
            exit(EXIT_SUCCESS);
        case SIGQUIT:
            logger(true, "Exit due to signal: %s", strsignal(sig));
            exit(EXIT_FAILURE);
        case SIGCONT:
            // Calculate rescheduled time
            SIGNAL = (sig == SIGCONT) ? 0 : SIGNAL; // restore signal to 0, but make sure not to disturb other incoming signals
            clock_gettime(CLOCK_REALTIME, &rescheduled_time);
            rescheduled_time.tv_sec += remain->tv_sec;
            rescheduled_time.tv_nsec += remain->tv_nsec;
            if (rescheduled_time.tv_nsec >= 1000000000) {
                rescheduled_time.tv_sec += rescheduled_time.tv_nsec / 1000000000;
                rescheduled_time.tv_nsec %= 1000000000;
            }
            localtime_r(&(rescheduled_time.tv_sec), &rescheduled_tm);
            logger(false, "Next execution rescheduled due to signal at: [%04d-%02d-%02d-%02d:%02d:%02d]",
                   rescheduled_tm.tm_year + 1900, rescheduled_tm.tm_mon + 1, rescheduled_tm.tm_mday, rescheduled_tm.tm_hour, rescheduled_tm.tm_min, rescheduled_tm.tm_sec);
            nanosleep(remain, remain);
            return;
        default:
            break;
    }
}

int runner(const char* path, const char* ori_path, const char* cmd) {
    if (SHELL) {
        if (path) {
            if (chdir(path) < 0) {
                return -1;
            }
        }
        int ret = system(cmd);
        if (path) {
            chdir(ori_path);
        }
        return ret;
    } else {
        pid_t pid = fork();
        if (pid == -1) {
            return -1;
        } else if (pid == 0) {
            /* Child Process */
            if (path) {
                if (chdir(path) < 0) {
                    exit(EXIT_FAILURE);
                }
            }
            // Parse args
            char **cmd_argv;
            wordexp_t cmd_arg;
            int ret;
            if ((ret = wordexp(cmd, &cmd_arg, 0)) != 0) {
                //fprintf(stderr, "TEST: Parse arg error: %d\n", ret);
                exit(ret);
            }
            cmd_argv = calloc(cmd_arg.we_wordc + 1, sizeof(char*)); // argv needs to have null-termination
            memcpy(cmd_argv, cmd_arg.we_wordv, sizeof(char*) * cmd_arg.we_wordc);
            ret = execvp(cmd_argv[0], cmd_argv);
            free(cmd_argv);
            wordfree(&cmd_arg);
            logger(false, "Process cannot start: %s", strerror(errno));
            exit(ret);
        } else {
            /* Parent Process */
            int child_state = 0;
            do {
                waitpid(pid, &child_state, WUNTRACED | WCONTINUED);
                if (WIFSTOPPED(child_state)) {
                    logger(false, "Process is paused");
                } else if (WIFCONTINUED(child_state)) {
                    logger(false, "Process continues ...");
                } else if (WIFEXITED(child_state)) {
                    int8_t ret = WEXITSTATUS(child_state); // WEXITSTATUS() captures lower 8 byte
                    //fprintf(stderr, "TEST: parent caught child exit: %d\n", ret);
                    switch (ret) {
                        case WRDE_BADCHAR:
                            logger(false, "Command arguments contain one of the following unquoted characters: "
                                          "⟨newline⟩, ‘|’, ‘&’, ‘;’, ‘<’, ‘>’, ‘(’, ‘)’, ‘{’, ‘}’");
                            return CMD_ARG_PARSE_FAIL;
                        case WRDE_NOSPACE:
                            logger(false, "Not enough memory to parse command arguments");
                            return CMD_ARG_PARSE_FAIL;
                        case WRDE_SYNTAX:
                            logger(false, "Command arguments contain syntax error");
                            return CMD_ARG_PARSE_FAIL;
                        case -1:
                            return EXEC_FAIL;
                        default:
                            return ret;
                    }
                } else if (WIFSIGNALED(child_state)) {
                    int8_t sig = WTERMSIG(child_state);
                    logger(false, "Execution is terminated by signal: %s", strsignal(sig));
                    return CHILD_TERM_SIG;
                } else {
                    //fprintf(stderr, "TEST: parent caught child: %d\n", child_state);
                    break;
                }
            } while (true);
        }
    }
    return 0;
}

void logger(bool err, const char* str, ...) {
    if ((!err || PERSEVERANT) && SILENT) {
        return;
    }
    FILE* output = (err && !PERSEVERANT) ? stderr : stdout;
    time_t cur_time;
    time(&cur_time);
    struct tm cur_tm = {0};
    localtime_r(&cur_time, &cur_tm);
    va_list given_args;
    va_start(given_args, str);
    fprintf(output, "<<[%04d-%02d-%02d-%02d:%02d:%02d]%s: ", cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, cur_tm.tm_mday,
            cur_tm.tm_hour, cur_tm.tm_min, cur_tm.tm_sec, PROGNAME);
    vfprintf(output, str, given_args);
    fprintf(output, ">>\n");
    va_end(given_args);
}

void arg_parser(int argc, char** argv, struct timespec* period, bool* wait, unsigned long long* count, char** path, char* ori_path, int* cmdc, char*** cmdv) {
    const char* filename = strrchr(argv[0], '/');
    PROGNAME = filename ? filename + 1 : argv[0];
    getcwd(ori_path, PATH_MAX);
    *wait = false;
    SILENT = false;
    PERSEVERANT = false;
    SHELL = false;
    *count = 0;
    *path = NULL;
    long sec = 0, min = 0, hur = 0, time_sec = 0;
    bool timer_set = false;
    struct option opts[] = {
            {"seconds", required_argument, 0, 'S'},
            {"minutes", required_argument, 0, 'M'},
            {"hours", required_argument, 0, 'H'},
            {"shell", no_argument, 0, 's'},
            {"wait", no_argument, 0, 'w'},
            {"count", required_argument, 0, 'c'},
            {"path", required_argument, 0, 'p'},
            {"no-exit", no_argument, 0, 768},
            {"no-log", no_argument, 0, 1024},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
    };
    int index;
    char* end_ptr;
    int opt;
    while((opt = getopt_long(argc, argv, "S:M:H:swc:p:h", opts, &index)) != -1) {
        switch (opt) {
            case 'h': // --help
                print_help();
                exit(EXIT_SUCCESS);
            case 'S': // --seconds
                timer_set = true;
                sec = strtol(optarg, &end_ptr, 10);
                if (*end_ptr != '\0') {
                    print_invalid(opt, optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'M': // --minutes
                timer_set = true;
                min = strtol(optarg, &end_ptr, 10);
                if (*end_ptr != '\0') {
                    print_invalid(opt, optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'H': // -- hours
                timer_set = true;
                hur = strtol(optarg, &end_ptr, 10);
                if (*end_ptr != '\0') {
                    print_invalid(opt, optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                SHELL = true;
                break;
            case 'w': // --wait
                *wait = true;
                break;
            case 'c': // --count
                *count = strtoull(optarg, &end_ptr, 10);
                if (*end_ptr != '\0') {
                    print_invalid(opt, optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                *path = optarg;
                break;
            case 768: // --no-exit
                PERSEVERANT = true;
                break;
            case 1024: // --no-log
                SILENT = true;
                break;
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }
    time_sec += sec + min * 60 + hur * 3600;
    period->tv_sec = timer_set ? (time_sec <= 0 ? 0 : time_sec) : 60;
    if ((*cmdc = argc - optind) < 1) {
        print_invalid(0, NULL);
        exit(EXIT_FAILURE);
    }
    *cmdv = argv + optind;
}

/* -------------------------------------------------- */

void print_help(void) {
    fprintf(stdout, HELP_MSG, PROGNAME, EXEC_HELP_MSG, SEC_HELP_MSG, MIN_HELP_MSG, HUR_HELP_MSG, COUNT_HELP_MSG, PATH_HELP_MSG, PROGNAME, PROGNAME, PROGNAME);
}

void print_usage(void) {
    fprintf(stderr, USAGE_MSG, PROGNAME, PROGNAME, PROGNAME);
}

void print_invalid(int option, const char* arg) {
    switch (option) {
        case 0: // no commands provided
            fprintf(stderr, NO_CMD_MSG, PROGNAME);
            fprintf(stderr, "%s", EXEC_HELP_MSG);
            break;
        case 'S': // --seconds
            fprintf(stderr, INVALID_MSG, PROGNAME, "-S/--seconds", arg);
            fprintf(stderr, "%s", SEC_HELP_MSG);
            break;
        case 'M': // --minutes
            fprintf(stderr, INVALID_MSG, PROGNAME, "-M/--minutes", arg);
            fprintf(stderr, "%s", MIN_HELP_MSG);
            break;
        case 'H': // --hours
            fprintf(stderr, INVALID_MSG, PROGNAME, "-H/--hours", arg);
            fprintf(stderr, "%s", HUR_HELP_MSG);
            break;
        case 'c': // --count
            fprintf(stderr, INVALID_MSG, PROGNAME, "-c/--count", arg);
            fprintf(stderr, "%s", COUNT_HELP_MSG);
            break;
        case 'p': // --path
            fprintf(stderr, INVALID_MSG, PROGNAME, "-p/--path", arg);
            fprintf(stderr, "%s", PATH_HELP_MSG);
        default:
            print_usage();
            break;
    }
}
