/*
 * history.h
 * ---------
 * The "patient chart" - a small time-based history of process health,
 * persisted to disk (~/.process_ward/history/<pid>.hist) so that it
 * survives across separate `process_ward` invocations, not just within
 * one `watch` session.
 *
 * Every `scan` / `watch` tick appends one sample per currently-visible
 * process. Older samples are pruned so files stay bounded.
 *
 * This is the foundation for:
 *   - Process Health Timeline (raw samples)
 *   - Predictive Resource Risk Detection (trend projection)
 *   - Resource-Leak Detection (monotonic growth over time)
 */
#ifndef HISTORY_H
#define HISTORY_H

#include <time.h>
#include "common.h"

#define HISTORY_MAX_SAMPLES 200   /* samples kept on disk per PID */

/* ---- shared on-disk state location (~/.process_ward/...) --------- */
const char *history_dir(void);      /* .../history   - per-PID sample files */
const char *incidents_dir(void);    /* .../incidents - saved incident reports */
const char *recovery_log_path(void);/* .../recovery.log - append-only action log */

typedef struct {
    time_t ts;
    double cpu_seconds;
    double mem_mb;
    int num_threads;
    int fd_count;
    long fd_soft_limit;
    char state_code;
    char severity[SEV_LEN];   /* primary diagnosis severity at sample time */
} HistorySample;

/* Appends one sample per process in `procs`/`count` to that process's
 * on-disk history file, then prunes to HISTORY_MAX_SAMPLES. `severity`
 * (parallel array, may be NULL) records the diagnosis severity at
 * sample time, used by the timeline/explainable-diagnosis views. */
void history_record(const Process *procs, const char severities[][SEV_LEN], int count);

/* Loads up to `max_samples` most recent samples for `pid`, oldest
 * first. Returns the number of samples actually loaded (0 if no
 * history file exists yet). */
int history_load(int pid, HistorySample *out, int max_samples);

/* Deletes all recorded history for one process (used when a PID is
 * confirmed gone / reused, so old data doesn't pollute the trend). */
void history_clear(int pid);

/* ---- Trend analysis --------------------------------------------- */

typedef struct {
    int have_trend;          /* enough samples to say anything */
    int increasing;          /* values are (non-strictly) increasing over the window */
    double rate_per_sample;  /* average change per sample */
    double first_value;
    double last_value;
    int samples_used;
} Trend;

/* Fits a simple trend to the last `n` values (chronological order). */
Trend trend_of(const double *values, int n);

#endif /* HISTORY_H */
