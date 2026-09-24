/*
 * rule_engine.h
 * -------------
 * The "Doctor" of the hospital metaphor.
 *
 * Takes process facts (from proc_reader) and produces diagnoses.
 * Every diagnosis is derived from an explicit, readable rule - never
 * a guess, never a black box.
 */
#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "common.h"

/* ---- Tunable thresholds (the "clinical guidelines") ---- */
#define HIGH_CPU_SECONDS          30.0
#define HIGH_MEM_MB              500.0
#define LONG_LIVED_ZOMBIE_SECONDS 60.0
#define ORPHAN_PPID                 1

/* Diagnose a single process. `all` / `all_count` is the full snapshot,
 * used to look up this process's children (for the child-reaping rule). */
void diagnose_process(const Process *proc, const Process *all, int all_count,
                       Diagnosis *out);

/* Diagnose every process in a snapshot. `out` must have room for
 * `count` Diagnosis entries. */
void diagnose_all(const Process *processes, int count, Diagnosis *out);

#endif /* RULE_ENGINE_H */
