/*
 * proc_reader.h
 * -------------
 * The "Patient Scanner" + "Process Monitor" layer.
 *
 * Reads real Linux process data from /proc and turns it into plain
 * Process structs of *facts* (PID, PPID, state, cpu, memory, etc).
 * This module does NOT diagnose anything - it only observes.
 */
#ifndef PROC_READER_H
#define PROC_READER_H

#include "common.h"

/* Returns list of every currently visible PID, sorted ascending.
 * *out_count receives the number of pids. Caller must free() the array. */
int *list_pids(int *out_count);

/* Fill `out` with facts for a single pid, from /proc/<pid>/stat,
 * /proc/<pid>/status and /proc/<pid>/cmdline.
 * Returns 0 on success, -1 if the process has already disappeared
 * (processes are ephemeral - this is expected and safe). */
int read_process(int pid, Process *out);

/* A full scan of every process currently on the system.
 * Returns a malloc'd array of Process (dead processes silently skipped);
 * *out_count receives its length. Caller must free() the array. */
Process *snapshot(int *out_count);

#endif /* PROC_READER_H */
