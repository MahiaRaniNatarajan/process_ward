#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
/*
 * cli.c
 * -----
 * Kernel-level, no-frontend interface for Process Ward.
 *
 * Talks directly to /proc (the kernel's process interface) through
 * proc_reader.c, runs the same rule_engine / treatment / analysis
 * logic, and prints everything to the terminal. No HTTP server, no
 * browser, no HTML/JS/CSS.
 *
 * Usage:
 *   process_ward                          interactive REPL (default)
 *   process_ward scan                     one-shot ward scan + report
 *   process_ward watch [--interval N]     auto-refreshing scan (default 5s)
 *   process_ward show PID                 full diagnosis for one PID
 *   process_ward report                   system health/capability/pattern report only
 *   process_ward treat PID SIGNAL [--yes] apply a treatment
 *   process_ward treat-all-safe           SIGCONT every stopped process
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "proc_reader.h"
#include "rule_engine.h"
#include "treatment.h"
#include "analysis.h"

/* ---- ANSI colors -------------------------------------------------- */
#define RESET "\033[0m"
#define BOLD  "\033[1m"
#define DIM   "\033[2m"

static const char *color_for(const char *sev) {
    if (strcmp(sev, "HEALTHY") == 0) return "\033[32m";
    if (strcmp(sev, "OBSERVATION") == 0) return "\033[36m";
    if (strcmp(sev, "WARNING") == 0) return "\033[33m";
    if (strcmp(sev, "CRITICAL") == 0) return "\033[31m";
    return "";
}

static const char *chip_for(const char *sev) {
    if (strcmp(sev, "HEALTHY") == 0) return "*";
    if (strcmp(sev, "OBSERVATION") == 0) return "o";
    if (strcmp(sev, "WARNING") == 0) return "!";
    if (strcmp(sev, "CRITICAL") == 0) return "X";
    return "?";
}

/* Prints text colored by severity, then resets. Returns nothing;
 * writes directly to stdout (mirrors Python's `c(sev, text)` helper,
 * which returned a string - here we just print it inline). */
static void cprint(const char *sev, const char *text) {
    printf("%s%s%s", color_for(sev), text, RESET);
}

static void clear_screen(void) {
    if (system("clear") != 0) {
        /* Not fatal - worst case the screen just doesn't clear. */
    }
}

/* ---- core scan ------------------------------------------------------ */

static Diagnosis *scan_and_diagnose(int *out_count) {
    int n;
    Process *procs = snapshot(&n);
    Diagnosis *diagnoses = malloc((size_t)(n > 0 ? n : 1) * sizeof(Diagnosis));
    diagnose_all(procs, n, diagnoses);
    free(procs);
    *out_count = n;
    return diagnoses;
}

/* ---- printing --------------------------------------------------------- */

static int cmp_diag_sev_desc(const void *a, const void *b) {
    const Diagnosis *da = (const Diagnosis *)a;
    const Diagnosis *db = (const Diagnosis *)b;
    return severity_rank(db->severity) - severity_rank(da->severity);
}

static void print_table(const Diagnosis *diagnoses, int count) {
    Diagnosis *rows = malloc((size_t)(count > 0 ? count : 1) * sizeof(Diagnosis));
    memcpy(rows, diagnoses, (size_t)count * sizeof(Diagnosis));
    qsort(rows, (size_t)count, sizeof(Diagnosis), cmp_diag_sev_desc);

    const char *header = "  " "    PID  NAME                STATE       "
                          "   CPU s   MEM MB  DIAGNOSIS";
    printf(BOLD "%s" RESET "\n", header);
    printf(DIM);
    for (size_t i = 0; i < strlen(header); i++) putchar('-');
    printf(RESET "\n");

    for (int i = 0; i < count; i++) {
        const Diagnosis *d = &rows[i];
        const Process *p = &d->process;
        const Finding *diag = &d->findings[d->primary_index];
        char name[20];
        snprintf(name, sizeof(name), "%s", p->name);

        printf("%2s %7d  %-20s%-12s%8.2f%9.2f  ",
               chip_for(d->severity), p->pid, name, p->state_name,
               p->cpu_seconds, p->mem_mb);
        cprint(d->severity, diag->condition);
        printf("\n");
    }
    free(rows);
}

static const char *score_sev(double score) {
    if (score >= 80) return "HEALTHY";
    if (score >= 55) return "WARNING";
    return "CRITICAL";
}

static void print_report(const FullReport *report) {
    const HealthReport *h = &report->health;

    printf(BOLD "\nSystem health" RESET "\n");
    char scorebuf[32];
    snprintf(scorebuf, sizeof(scorebuf), "%.1f", h->overall_health);
    printf("  Overall score: ");
    cprint(score_sev(h->overall_health), scorebuf);
    printf("\n");
    printf("  Healthy %d  Observation %d  Warning %d  Critical %d\n",
           h->healthy, h->observation, h->warning, h->critical);

    printf(BOLD "\nSub-scores" RESET "\n");
    printf("  %-22s%.1f\n", "process_stability", h->process_stability);
    printf("  %-22s%.1f\n", "process_management", h->process_management);
    printf("  %-22s%.1f\n", "reaping_health", h->reaping_health);

    printf(BOLD "\nCapabilities" RESET "\n");
    for (int i = 0; i < report->capability_count; i++) {
        const Capability *cap = &report->capabilities[i];
        printf("  %-22s%-12s%.1f\n", cap->name, cap->rating, cap->score);
    }

    if (report->pattern_count > 0) {
        printf(BOLD "\nSystem findings" RESET "\n");
        for (int i = 0; i < report->pattern_count; i++) {
            const Pattern *p = &report->patterns[i];
            printf("  [%s] %s - %s\n", p->classification, p->name, p->evidence);
        }
    }

    if (report->root_cause_count > 0) {
        printf(BOLD "\nRoot-cause candidates" RESET "\n");
        for (int i = 0; i < report->root_cause_count; i++) {
            const RootCause *rc = &report->root_causes[i];
            printf("  PID %d (%s): %s\n", rc->pid, rc->name, rc->reason);
        }
    }
}

static void print_detail(const Diagnosis *d) {
    const Finding *diag = &d->findings[d->primary_index];
    const Process *p = &d->process;

    printf(BOLD "\n%s %s" RESET "\n", diag->icon, diag->condition);
    printf("PID %d - %s - severity: ", p->pid, p->name);
    cprint(d->severity, d->severity);
    printf("\n");

    printf(BOLD "\nEvidence" RESET "\n");
    for (int i = 0; i < diag->evidence_count; i++) {
        printf("  - %s\n", diag->evidence[i]);
    }

    printf(BOLD "\nOS concept" RESET "\n");
    printf("  %s\n", diag->os_concept);

    if (diag->has_likely_cause) {
        printf(BOLD "\nLikely cause" RESET "\n");
        printf("  %s\n", diag->likely_cause);
    }

    const Treatment *t = &diag->treatment;
    printf(BOLD "\nTreatment plan (%s-tier)" RESET "\n", t->safety);
    printf("  %s\n", t->label);
    printf(DIM "  %s" RESET "\n", t->note);
    if (t->cmd[0] != '\0') {
        printf("\n  Run:\n");
        printf("    " BOLD "%s" RESET "\n", t->cmd);
    }
}

/* ---- treatment -------------------------------------------------------- */

static void do_treat(int pid, const char *sig_in, int assume_yes) {
    char sig[16];
    size_t i = 0;
    for (; sig_in[i] && i < sizeof(sig) - 1; i++) sig[i] = (char)toupper((unsigned char)sig_in[i]);
    sig[i] = '\0';

    const char *tier = safety_tier_for(sig);
    if (tier && strcmp(tier, "red") == 0 && !assume_yes) {
        printf("%s is a red-tier dangerous treatment. Send it to PID %d? [y/N] ", sig, pid);
        fflush(stdout);
        char answer[16] = {0};
        if (!fgets(answer, sizeof(answer), stdin)) answer[0] = '\0';
        for (char *p = answer; *p; p++) *p = (char)tolower((unsigned char)*p);
        /* trim newline/whitespace */
        char *nl = strchr(answer, '\n');
        if (nl) *nl = '\0';
        if (strcmp(answer, "y") != 0) {
            printf("Cancelled.\n");
            return;
        }
    }

    Process before_proc;
    int have_before = (read_process(pid, &before_proc) == 0);
    Diagnosis before_diag;
    int have_before_diag = 0;
    if (have_before) {
        int n;
        Process *all = snapshot(&n);
        diagnose_process(&before_proc, all, n, &before_diag);
        free(all);
        have_before_diag = 1;
    }

    TreatmentResult result;
    char err[256];
    int confirmed = (tier && strcmp(tier, "red") == 0);
    if (send_signal(pid, sig, confirmed, &result, err, sizeof(err)) != 0) {
        cprint("CRITICAL", "Error: ");
        cprint("CRITICAL", err);
        printf("\n");
        return;
    }

    usleep(300 * 1000); /* 0.3s, matches Python's time.sleep(0.3) */

    Process after_proc;
    const char *outcome;
    if (read_process(pid, &after_proc) != 0) {
        outcome = "process_exited";
    } else {
        int n;
        Process *all = snapshot(&n);
        Diagnosis after_diag;
        diagnose_process(&after_proc, all, n, &after_diag);
        free(all);

        if (!have_before_diag) {
            outcome = "unknown";
        } else if (strcmp(after_diag.severity, "HEALTHY") == 0 &&
                   strcmp(before_diag.severity, "HEALTHY") != 0) {
            outcome = "improved";
        } else if (strcmp(after_diag.severity, before_diag.severity) == 0) {
            outcome = "unchanged";
        } else {
            outcome = "changed";
        }
    }

    const char *msg;
    if (strcmp(outcome, "improved") == 0) msg = "condition improved on re-scan.";
    else if (strcmp(outcome, "unchanged") == 0) msg = "condition unchanged, may need a different treatment.";
    else if (strcmp(outcome, "changed") == 0) msg = "condition changed.";
    else if (strcmp(outcome, "process_exited") == 0) msg = "process no longer exists after treatment (exited).";
    else msg = "treatment sent; verification inconclusive.";

    printf("Sent %s to PID %d (%s-tier): %s\n", result.signal_name, pid, result.safety_tier, msg);
}

static void treat_all_safe(void) {
    int count;
    Diagnosis *diagnoses = scan_and_diagnose(&count);

    int cand_count = 0;
    int *cand_pids = malloc((size_t)(count > 0 ? count : 1) * sizeof(int));
    for (int i = 0; i < count; i++) {
        const Diagnosis *d = &diagnoses[i];
        const Finding *primary = &d->findings[d->primary_index];
        if (strcmp(d->severity, "HEALTHY") != 0 &&
            strcmp(primary->treatment.action, "SIGCONT") == 0) {
            cand_pids[cand_count++] = d->pid;
        }
    }
    free(diagnoses);

    if (cand_count == 0) {
        printf("No processes currently have a safe automatic treatment available.\n");
        free(cand_pids);
        return;
    }
    printf("Sending SIGCONT to %d stopped process(es)...\n", cand_count);
    for (int i = 0; i < cand_count; i++) {
        do_treat(cand_pids[i], "SIGCONT", 1);
    }
    free(cand_pids);
}

/* ---- interactive REPL --------------------------------------------------- */

static const char *HELP =
    "\nCommands:\n"
    "  scan                 rescan and print the ward table + report\n"
    "  show PID              full diagnosis for one PID\n"
    "  treat PID SIGNAL       apply a treatment (SIGTERM/SIGKILL/SIGSTOP/SIGCONT)\n"
    "  treat-all-safe         SIGCONT every stopped process\n"
    "  watch [interval]       auto-refresh scan (Ctrl+C to stop)\n"
    "  help                    show this help\n"
    "  quit / exit             leave\n";

static void do_scan_and_report(void) {
    int count;
    Diagnosis *diagnoses = scan_and_diagnose(&count);
    print_table(diagnoses, count);
    FullReport report;
    full_report(diagnoses, count, &report);
    print_report(&report);
    free(diagnoses);
}

static void watch_mode(double interval);

static void repl(void) {
    printf(BOLD "Process Ward - kernel-level CLI (no frontend)" RESET "\n");
    printf(DIM "Reads /proc directly. Type 'help' for commands." RESET "\n");
    do_scan_and_report();

    char line[256];
    while (1) {
        printf("\n> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) {
            printf("\n");
            break;
        }
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* trim leading whitespace */
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        if (*start == '\0') continue;

        char parts[8][64];
        int nparts = 0;
        char *tok = strtok(start, " \t");
        while (tok && nparts < 8) {
            snprintf(parts[nparts], sizeof(parts[nparts]), "%s", tok);
            nparts++;
            tok = strtok(NULL, " \t");
        }
        if (nparts == 0) continue;

        char cmd[64];
        snprintf(cmd, sizeof(cmd), "%s", parts[0]);
        for (char *p = cmd; *p; p++) *p = (char)tolower((unsigned char)*p);

        if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "help") == 0) {
            printf("%s", HELP);
        } else if (strcmp(cmd, "scan") == 0) {
            do_scan_and_report();
        } else if (strcmp(cmd, "report") == 0) {
            int count;
            Diagnosis *diagnoses = scan_and_diagnose(&count);
            FullReport report;
            full_report(diagnoses, count, &report);
            print_report(&report);
            free(diagnoses);
        } else if (strcmp(cmd, "show") == 0 && nparts == 2) {
            int pid = atoi(parts[1]);
            Process proc;
            if (read_process(pid, &proc) != 0) {
                printf("PID %s not found.\n", parts[1]);
                continue;
            }
            int n;
            Process *all = snapshot(&n);
            Diagnosis d;
            diagnose_process(&proc, all, n, &d);
            free(all);
            print_detail(&d);
        } else if (strcmp(cmd, "treat") == 0 && nparts == 3) {
            do_treat(atoi(parts[1]), parts[2], 0);
        } else if (strcmp(cmd, "treat-all-safe") == 0) {
            treat_all_safe();
        } else if (strcmp(cmd, "watch") == 0) {
            double interval = (nparts == 2) ? atof(parts[1]) : 5.0;
            watch_mode(interval);
        } else {
            printf("Unrecognized command. Type 'help' for a list.\n");
        }
    }
}

static void watch_mode(double interval) {
    while (1) {
        clear_screen();
        int count;
        Diagnosis *diagnoses = scan_and_diagnose(&count);
        time_t now = time(NULL);
        struct tm *tmv = localtime(&now);
        char timebuf[16];
        strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tmv);
        printf(DIM "Process Ward - auto-refresh every %gs (Ctrl+C to stop) - %s" RESET "\n",
               interval, timebuf);
        print_table(diagnoses, count);
        FullReport report;
        full_report(diagnoses, count, &report);
        print_report(&report);
        free(diagnoses);
        fflush(stdout);

        struct timespec ts;
        ts.tv_sec = (time_t)interval;
        ts.tv_nsec = (long)((interval - (double)ts.tv_sec) * 1e9);
        nanosleep(&ts, NULL);
    }
    /* Ctrl+C (SIGINT) terminates the process by default, matching the
     * Python version's behavior after printing "Stopped watching." there
     * isn't a clean way to intercept that in a minimal CLI without extra
     * signal handling, so watch runs until interrupted at the OS level. */
}

/* ---- argument parsing / entrypoint --------------------------------------- */

static void usage(void) {
    fprintf(stderr,
        "Process Ward - kernel-level CLI\n\n"
        "Usage:\n"
        "  process_ward                          interactive REPL (default)\n"
        "  process_ward scan                     one-shot ward scan + report\n"
        "  process_ward watch [--interval N]     auto-refreshing scan (default 5s)\n"
        "  process_ward show PID                 full diagnosis for one PID\n"
        "  process_ward report                   system health/capability/pattern report only\n"
        "  process_ward treat PID SIGNAL [--yes] apply a treatment\n"
        "  process_ward treat-all-safe           SIGCONT every stopped process\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        repl();
        return 0;
    }

    const char *command = argv[1];

    if (strcmp(command, "scan") == 0) {
        do_scan_and_report();
    } else if (strcmp(command, "report") == 0) {
        int count;
        Diagnosis *diagnoses = scan_and_diagnose(&count);
        FullReport report;
        full_report(diagnoses, count, &report);
        print_report(&report);
        free(diagnoses);
    } else if (strcmp(command, "watch") == 0) {
        double interval = 5.0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
                interval = atof(argv[++i]);
            }
        }
        watch_mode(interval);
    } else if (strcmp(command, "show") == 0) {
        if (argc < 3) { usage(); return 2; }
        int pid = atoi(argv[2]);
        Process proc;
        if (read_process(pid, &proc) != 0) {
            printf("PID %d not found.\n", pid);
            return 1;
        }
        int n;
        Process *all = snapshot(&n);
        Diagnosis d;
        diagnose_process(&proc, all, n, &d);
        free(all);
        print_detail(&d);
    } else if (strcmp(command, "treat") == 0) {
        if (argc < 4) { usage(); return 2; }
        int assume_yes = 0;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--yes") == 0) assume_yes = 1;
        }
        do_treat(atoi(argv[2]), argv[3], assume_yes);
    } else if (strcmp(command, "treat-all-safe") == 0) {
        treat_all_safe();
    } else if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        usage();
    } else {
        fprintf(stderr, "Unrecognized command: %s\n\n", command);
        usage();
        return 2;
    }

    return 0;
}
