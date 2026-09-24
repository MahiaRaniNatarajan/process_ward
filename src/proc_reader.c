#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
/*
 * proc_reader.c
 * -------------
 * See proc_reader.h for the module's purpose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "proc_reader.h"

static long CLOCK_TICKS = 100;
static long PAGE_SIZE = 4096;
static long BOOT_TIME = 0;

/* ---- one-time init of the "constants" the Python module computed at
 * import time (sysconf values + boot time from /proc/stat) ---- */
static void init_constants(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    long ticks = sysconf(_SC_CLK_TCK);
    if (ticks > 0) CLOCK_TICKS = ticks;

    long page = sysconf(_SC_PAGESIZE);
    if (page > 0) PAGE_SIZE = page;

    FILE *f = fopen("/proc/stat", "r");
    BOOT_TIME = (long)time(NULL); /* fallback */
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "btime", 5) == 0) {
                long bt;
                if (sscanf(line, "btime %ld", &bt) == 1) {
                    BOOT_TIME = bt;
                }
                break;
            }
        }
        fclose(f);
    }
}

/* Read an entire small file into a malloc'd, NUL-terminated buffer.
 * Returns NULL if the file can't be read (already gone, no permission,
 * etc.) - mirrors proc_reader.py's `_read_file`. Caller must free(). */
static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return NULL; }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); fclose(f); return NULL; }
            buf = nb;
        }
    }
    fclose(f);
    buf[len] = '\0';
    return buf;
}

/* Like read_file, but also reports the exact byte count read (needed for
 * /proc/<pid>/cmdline, whose argv entries are NUL-separated - a plain
 * NUL-terminated C string would silently truncate at the first arg). */
static char *read_file_n(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "r");
    if (!f) { *out_len = 0; return NULL; }

    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); *out_len = 0; return NULL; }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); fclose(f); *out_len = 0; return NULL; }
            buf = nb;
        }
    }
    fclose(f);
    *out_len = len;
    return buf;
}

static int cmp_int(const void *a, const void *b) {
    int ia = *(const int *)a, ib = *(const int *)b;
    return ia - ib;
}

int *list_pids(int *out_count) {
    init_constants();

    DIR *d = opendir("/proc");
    if (!d) {
        *out_count = 0;
        return NULL;
    }

    size_t cap = 256, n = 0;
    int *pids = malloc(cap * sizeof(int));

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        int is_digit_str = (*name != '\0');
        for (const char *p = name; *p; p++) {
            if (!isdigit((unsigned char)*p)) { is_digit_str = 0; break; }
        }
        if (!is_digit_str) continue;

        if (n == cap) {
            cap *= 2;
            pids = realloc(pids, cap * sizeof(int));
        }
        pids[n++] = atoi(name);
    }
    closedir(d);

    qsort(pids, n, sizeof(int), cmp_int);
    *out_count = (int)n;
    return pids;
}

static const char *state_name_for(char code) {
    switch (code) {
        case 'R': return "Running";
        case 'S': return "Sleeping";
        case 'D': return "Uninterruptible Sleep";
        case 'Z': return "Zombie";
        case 'T': return "Stopped";
        case 't': return "Tracing Stop";
        case 'X': return "Dead";
        case 'I': return "Idle";
        default:  return "Unknown";
    }
}

int read_process(int pid, Process *out) {
    init_constants();
    memset(out, 0, sizeof(*out));

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    char *stat_raw = read_file(path);
    if (!stat_raw) return -1;

    /* comm (2nd field) is wrapped in parens and may itself contain
     * spaces/parens, so find it via the first '(' and the LAST ')'. */
    char *open_paren = strchr(stat_raw, '(');
    char *close_paren = strrchr(stat_raw, ')');
    if (!open_paren || !close_paren || close_paren < open_paren) {
        free(stat_raw);
        return -1;
    }

    size_t comm_len = (size_t)(close_paren - open_paren - 1);
    if (comm_len >= NAME_LEN) comm_len = NAME_LEN - 1;
    memcpy(out->name, open_paren + 1, comm_len);
    out->name[comm_len] = '\0';

    /* Fields after "comm) ", 0-indexed from "state" as in proc_reader.py */
    char *rest = close_paren + 2; /* skip ") " */
    char state = 0;
    int ppid = 0, pgrp = 0, session = 0, num_threads = 0;
    long long utime = 0, stime = 0, starttime_ticks = 0;
    long vsize = 0, rss_pages = 0;

    /* Tokenize the remaining whitespace-separated fields, matching the
     * Python code's rest[0..21] indices exactly. */
    char *fields[40];
    int nf = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(rest, " \t\n", &saveptr);
    while (tok && nf < 40) {
        fields[nf++] = tok;
        tok = strtok_r(NULL, " \t\n", &saveptr);
    }

    if (nf < 22) { free(stat_raw); return -1; }

    state = fields[0][0];
    ppid = atoi(fields[1]);
    pgrp = atoi(fields[2]);
    session = atoi(fields[3]);
    utime = atoll(fields[11]);
    stime = atoll(fields[12]);
    num_threads = atoi(fields[17]);
    starttime_ticks = atoll(fields[19]);
    vsize = atol(fields[20]);
    rss_pages = atol(fields[21]);

    free(stat_raw);

    double start_time_unix = (double)BOOT_TIME + ((double)starttime_ticks / (double)CLOCK_TICKS);
    double age_seconds = (double)time(NULL) - start_time_unix;
    if (age_seconds < 0.0) age_seconds = 0.0;

    double cpu_seconds = (double)(utime + stime) / (double)CLOCK_TICKS;
    long mem_bytes = rss_pages * PAGE_SIZE;

    out->pid = pid;
    out->ppid = ppid;
    out->pgrp = pgrp;
    out->session = session;
    out->state_code = state;
    snprintf(out->state_name, STATE_NAME_LEN, "%s", state_name_for(state));
    out->num_threads = num_threads;
    out->cpu_seconds = ((double)((long)(cpu_seconds * 100 + 0.5))) / 100.0; /* round to 2dp */
    out->mem_bytes = mem_bytes;
    out->mem_mb = ((double)((long)(mem_bytes / (1024.0 * 1024.0) * 100 + 0.5))) / 100.0;
    out->age_seconds = ((double)((long)(age_seconds * 10 + 0.5))) / 10.0; /* round to 1dp */
    out->vsize = vsize;

    /* /proc/<pid>/status - Uid line */
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    char *status_raw = read_file(path);
    out->has_uid = 0;
    if (status_raw) {
        char *line = status_raw;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            size_t linelen = nl ? (size_t)(nl - line) : strlen(line);
            if (linelen >= 4 && strncmp(line, "Uid:", 4) == 0) {
                char tmp[128];
                size_t cl = linelen < sizeof(tmp) - 1 ? linelen : sizeof(tmp) - 1;
                memcpy(tmp, line, cl);
                tmp[cl] = '\0';
                char uidbuf[UID_LEN] = {0};
                if (sscanf(tmp, "Uid: %15s", uidbuf) == 1) {
                    snprintf(out->uid, UID_LEN, "%s", uidbuf);
                    out->has_uid = 1;
                }
                break;
            }
            line = nl ? nl + 1 : NULL;
        }
        free(status_raw);
    }

    /* /proc/<pid>/cmdline - NUL-separated argv, joined with spaces */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    size_t cmdline_len = 0;
    char *cmdline_raw = read_file_n(path, &cmdline_len);
    out->cmdline[0] = '\0';
    if (cmdline_raw) {
        size_t len = cmdline_len;
        size_t j = 0;
        for (size_t i = 0; i < len && j < CMDLINE_LEN - 1; i++) {
            char ch = cmdline_raw[i];
            out->cmdline[j++] = (ch == '\0') ? ' ' : ch;
        }
        out->cmdline[j] = '\0';
        /* trim trailing/leading spaces */
        while (j > 0 && out->cmdline[j - 1] == ' ') out->cmdline[--j] = '\0';
        size_t start = 0;
        while (out->cmdline[start] == ' ') start++;
        if (start > 0) memmove(out->cmdline, out->cmdline + start, strlen(out->cmdline + start) + 1);
        free(cmdline_raw);
    }
    if (out->cmdline[0] == '\0') {
        snprintf(out->cmdline, CMDLINE_LEN, "%s", out->name);
    }

    /* /proc/<pid>/fd - count open file descriptors (needs same
     * privileges as reading the process at all; -1 if we can't see it,
     * which is normal for processes owned by other users). */
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    DIR *fdd = opendir(path);
    if (fdd) {
        int n_fd = 0;
        struct dirent *fe;
        while ((fe = readdir(fdd)) != NULL) {
            if (fe->d_name[0] == '.') continue;
            n_fd++;
        }
        closedir(fdd);
        out->fd_count = n_fd;
    } else {
        out->fd_count = -1;
    }

    /* /proc/<pid>/limits - "Max open files" soft limit, used for
     * predictive file-descriptor-exhaustion warnings. */
    out->fd_soft_limit = 0;
    snprintf(path, sizeof(path), "/proc/%d/limits", pid);
    char *limits_raw = read_file(path);
    if (limits_raw) {
        char *line = strstr(limits_raw, "Max open files");
        if (line) {
            long soft = 0;
            if (sscanf(line, "Max open files %ld", &soft) == 1) {
                out->fd_soft_limit = soft;
            }
        }
        free(limits_raw);
    }

    return 0;
}

Process *snapshot(int *out_count) {
    int npids;
    int *pids = list_pids(&npids);

    Process *procs = malloc((size_t)(npids > 0 ? npids : 1) * sizeof(Process));
    int n = 0;
    for (int i = 0; i < npids; i++) {
        Process p;
        if (read_process(pids[i], &p) == 0) {
            procs[n++] = p;
        }
    }
    free(pids);
    *out_count = n;
    return procs;
}
