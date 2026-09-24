#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
/*
 * incident.c
 * ----------
 * See incident.h for the module's purpose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "incident.h"
#include "history.h"

static void timestamp_str(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *tmv = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tmv);
}

void format_incident_report(const Diagnosis *d, int treated,
                             const TreatmentResult *tr, const char *outcome,
                             char *out, size_t out_len) {
    const Finding *primary = &d->findings[d->primary_index];
    const Process *p = &d->process;
    char ts[32];
    timestamp_str(ts, sizeof(ts));

    char evidence_block[MAX_EVIDENCE * (EVIDENCE_LEN + 4) + 1];
    evidence_block[0] = '\0';
    for (int i = 0; i < primary->evidence_count; i++) {
        strncat(evidence_block, "  - ", sizeof(evidence_block) - strlen(evidence_block) - 1);
        strncat(evidence_block, primary->evidence[i], sizeof(evidence_block) - strlen(evidence_block) - 1);
        strncat(evidence_block, "\n", sizeof(evidence_block) - strlen(evidence_block) - 1);
    }
    if (primary->evidence_count == 0) {
        snprintf(evidence_block, sizeof(evidence_block), "  (none recorded)\n");
    }

    char treated_block[300];
    if (treated && tr) {
        snprintf(treated_block, sizeof(treated_block),
                 "Treatment performed : %s (%s-tier)\n"
                 "Treatment result    : %s\n",
                 tr->signal_name, tr->safety_tier, outcome ? outcome : "unknown");
    } else {
        snprintf(treated_block, sizeof(treated_block),
                 "Treatment performed : (not yet treated)\n"
                 "Treatment result    : n/a\n");
    }

    snprintf(out, out_len,
        "PROCESS INCIDENT REPORT\n"
        "========================\n"
        "Generated            : %s\n"
        "Process ID           : %d\n"
        "Process name          : %s\n"
        "Parent process (PPID) : %d\n"
        "Detected condition    : %s\n"
        "Severity              : %s\n"
        "Evidence:\n"
        "%s"
        "Suspected cause        : %s\n"
        "Recommended treatment  : %s (%s-tier)\n"
        "  %s\n"
        "%s",
        ts, p->pid, p->name, p->ppid,
        primary->condition, d->severity,
        evidence_block,
        primary->has_likely_cause ? primary->likely_cause : "(none identified)",
        primary->treatment.label, primary->treatment.safety, primary->treatment.note,
        treated_block);
}

int incident_save(const Diagnosis *d, int treated, const TreatmentResult *tr,
                   const char *outcome, char *path_out, size_t path_out_len) {
    char report[4096];
    format_incident_report(d, treated, tr, outcome, report, sizeof(report));

    time_t now = time(NULL);
    snprintf(path_out, path_out_len, "%s/incident_%d_%ld.txt",
             incidents_dir(), d->pid, (long)now);

    FILE *f = fopen(path_out, "w");
    if (!f) return -1;
    fputs(report, f);
    fclose(f);

    /* also append a one-line index entry for quick scanning */
    char idx[600];
    snprintf(idx, sizeof(idx), "%s/index.log", incidents_dir());
    FILE *fi = fopen(idx, "a");
    if (fi) {
        char ts[32];
        timestamp_str(ts, sizeof(ts));
        fprintf(fi, "%s  PID %-7d %-20s %-10s %s\n",
                ts, d->pid, d->process.name, d->severity,
                d->findings[d->primary_index].condition);
        fclose(fi);
    }
    return 0;
}

void recovery_log_append(const char *fmt, ...) {
    FILE *f = fopen(recovery_log_path(), "a");
    if (!f) return;
    char ts[32];
    timestamp_str(ts, sizeof(ts));
    fprintf(f, "%s  ", ts);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fprintf(f, "\n");
    fclose(f);
}

void recovery_log_print(void) {
    FILE *f = fopen(recovery_log_path(), "r");
    if (!f) {
        printf("No recovery actions recorded yet.\n");
        return;
    }
    char line[512];
    int any = 0;
    while (fgets(line, sizeof(line), f)) {
        fputs(line, stdout);
        any = 1;
    }
    fclose(f);
    if (!any) printf("No recovery actions recorded yet.\n");
}
