#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
/*
 * history.c
 * ---------
 * See history.h for the module's purpose.
 *
 * Storage format is a deliberately dumb one-line-per-sample text file,
 * one file per PID, under ~/.process_ward/history/. No dependencies
 * beyond libc; a text format keeps it inspectable with `cat`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "history.h"

/* ---- ~/.process_ward/history/ ------------------------------------ */

static const char *state_home(void) {
    static char buf[512];
    static int done = 0;
    if (done) return buf;
    done = 1;
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/tmp";
    snprintf(buf, sizeof(buf), "%s/.process_ward", home);
    return buf;
}

/* Idempotent mkdir - ignores EEXIST, mirrors `mkdir -p` for our two
 * fixed levels (base dir + history/incidents subdirs). */
static void ensure_dir(const char *path) {
    mkdir(path, 0700); /* ignore errors; a failed mkdir surfaces later as a failed fopen */
}

const char *history_dir(void) {
    static char buf[560];
    static int done = 0;
    if (done) return buf;
    done = 1;
    ensure_dir(state_home());
    snprintf(buf, sizeof(buf), "%s/history", state_home());
    ensure_dir(buf);
    return buf;
}

const char *incidents_dir(void) {
    static char buf[560];
    static int done = 0;
    if (done) return buf;
    done = 1;
    ensure_dir(state_home());
    snprintf(buf, sizeof(buf), "%s/incidents", state_home());
    ensure_dir(buf);
    return buf;
}

const char *recovery_log_path(void) {
    static char buf[560];
    static int done = 0;
    if (done) return buf;
    done = 1;
    ensure_dir(state_home());
    snprintf(buf, sizeof(buf), "%s/recovery.log", state_home());
    return buf;
}

static void hist_path_for(int pid, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%s/%d.hist", history_dir(), pid);
}

/* ---- recording ----------------------------------------------------- */

void history_record(const Process *procs, const char severities[][SEV_LEN], int count) {
    time_t now = time(NULL);
    for (int i = 0; i < count; i++) {
        const Process *p = &procs[i];
        char path[600];
        hist_path_for(p->pid, path, sizeof(path));
        FILE *f = fopen(path, "a");
        if (!f) continue;
        const char *sev = severities ? severities[i] : "";
        fprintf(f, "%ld %.2f %.2f %d %d %ld %c %s\n",
                (long)now, p->cpu_seconds, p->mem_mb, p->num_threads,
                p->fd_count, p->fd_soft_limit, p->state_code ? p->state_code : '?',
                (sev && sev[0]) ? sev : "UNKNOWN");
        fclose(f);
    }

    /* Prune occasionally (cheap check: only when the file has clearly
     * grown past the cap) so a long-running `watch` doesn't grow
     * history files without bound. */
    for (int i = 0; i < count; i++) {
        char path[600];
        hist_path_for(procs[i].pid, path, sizeof(path));
        FILE *f = fopen(path, "r");
        if (!f) continue;
        int lines = 0;
        char linebuf[256];
        while (fgets(linebuf, sizeof(linebuf), f)) lines++;
        fclose(f);
        if (lines > HISTORY_MAX_SAMPLES + 40) {
            /* rewrite keeping only the most recent HISTORY_MAX_SAMPLES */
            HistorySample tmp[HISTORY_MAX_SAMPLES];
            int n = history_load(procs[i].pid, tmp, HISTORY_MAX_SAMPLES);
            FILE *out = fopen(path, "w");
            if (out) {
                for (int j = 0; j < n; j++) {
                    fprintf(out, "%ld %.2f %.2f %d %d %ld %c %s\n",
                            (long)tmp[j].ts, tmp[j].cpu_seconds, tmp[j].mem_mb,
                            tmp[j].num_threads, tmp[j].fd_count, tmp[j].fd_soft_limit,
                            tmp[j].state_code ? tmp[j].state_code : '?', tmp[j].severity);
                }
                fclose(out);
            }
        }
    }
}

int history_load(int pid, HistorySample *out, int max_samples) {
    char path[600];
    hist_path_for(pid, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    /* Read every line into a growable buffer, then keep the tail -
     * simplest correct way to get "most recent N" without seeking
     * tricks on a small text file. */
    size_t cap = 64, n = 0;
    HistorySample *all = malloc(cap * sizeof(HistorySample));
    char linebuf[256];
    while (fgets(linebuf, sizeof(linebuf), f)) {
        long ts; double cpu, mem; int threads, fd; long fdlim; char state; char sev[SEV_LEN];
        sev[0] = '\0';
        int got = sscanf(linebuf, "%ld %lf %lf %d %d %ld %c %15s",
                          &ts, &cpu, &mem, &threads, &fd, &fdlim, &state, sev);
        if (got < 7) continue;
        if (n == cap) {
            cap *= 2;
            HistorySample *nb = realloc(all, cap * sizeof(HistorySample));
            if (!nb) break;
            all = nb;
        }
        all[n].ts = (time_t)ts;
        all[n].cpu_seconds = cpu;
        all[n].mem_mb = mem;
        all[n].num_threads = threads;
        all[n].fd_count = fd;
        all[n].fd_soft_limit = fdlim;
        all[n].state_code = state;
        snprintf(all[n].severity, SEV_LEN, "%s", got >= 8 ? sev : "UNKNOWN");
        n++;
    }
    fclose(f);

    int want = (int)n < max_samples ? (int)n : max_samples;
    size_t start = n - (size_t)want;
    for (int i = 0; i < want; i++) out[i] = all[start + (size_t)i];
    free(all);
    return want;
}

void history_clear(int pid) {
    char path[600];
    hist_path_for(pid, path, sizeof(path));
    remove(path);
}

/* ---- trend analysis -------------------------------------------------- */

Trend trend_of(const double *values, int n) {
    Trend t;
    memset(&t, 0, sizeof(t));
    if (n < 2) return t;

    t.have_trend = 1;
    t.samples_used = n;
    t.first_value = values[0];
    t.last_value = values[n - 1];

    /* Average step-to-step delta, and whether the series is
     * (non-strictly) increasing across essentially every step - a
     * simple, explainable trend test rather than a full regression. */
    double sum_delta = 0.0;
    int up_steps = 0, down_steps = 0;
    for (int i = 1; i < n; i++) {
        double d = values[i] - values[i - 1];
        sum_delta += d;
        if (d > 0.0001) up_steps++;
        else if (d < -0.0001) down_steps++;
    }
    t.rate_per_sample = sum_delta / (double)(n - 1);
    /* "increasing" = most steps moved up and almost none moved down */
    t.increasing = (up_steps >= (n - 1) * 2 / 3) && (down_steps == 0) && (t.last_value > t.first_value);
    return t;
}
